/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "plgd_dps_apis_internal.h"
#include "plgd_dps_cloud_internal.h"
#include "plgd_dps_context_internal.h"
#include "plgd_dps_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_provision_internal.h"

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/oc_helpers_internal.h"
#include "oc_api.h"
#include "oc_cloud.h"
#include "oc_rep.h" // oc_rep_get_by_type_and_key
#include "oc_uuid.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

bool
dps_cloud_is_started(size_t device)
{
  const oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(device);
  if (cloud_ctx == NULL) {
    return false;
  }
  return oc_cloud_manager_is_started(cloud_ctx);
}

static bool
cloud_check_status(size_t device, uint8_t status)
{
  const oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(device);
  if (cloud_ctx == NULL) {
    return false;
  }
  return (oc_cloud_get_status(cloud_ctx) & status) == status;
}

bool
dps_cloud_is_registered(size_t device)
{
  return cloud_check_status(device, OC_CLOUD_REGISTERED);
}

bool
dps_cloud_is_logged_in(size_t device)
{
  return cloud_check_status(device, OC_CLOUD_LOGGED_IN);
}

void
dps_cloud_observer_init(plgd_cloud_status_observer_t *obs)
{
  assert(obs != NULL);
  memset(obs, 0, sizeof(plgd_cloud_status_observer_t));
  obs->cfg.max_count = 30; // NOLINT
  obs->cfg.interval_s = 1;
}

static void
dps_cloud_observer_on_cloud_server_change(void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
  // invoke the original callback
  if (ctx->cloud_observer.original_on_selected_change.cb != NULL) {
    ctx->cloud_observer.original_on_selected_change.cb(
      ctx->cloud_observer.original_on_selected_change.cb_data);
  }

  dps_cloud_observer_on_server_change(ctx);
}

void
dps_cloud_observer_deinit(plgd_dps_context_t *ctx)
{
  oc_remove_delayed_callback(ctx, dps_cloud_observe_status_async);
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx != NULL) {
    oc_endpoint_addresses_on_selected_change_t on_selected_change =
      oc_endpoint_addresses_get_on_selected_change(
        &cloud_ctx->store.ci_servers);
    if (on_selected_change.cb == &dps_cloud_observer_on_cloud_server_change) {
      oc_endpoint_addresses_set_on_selected_change(
        &cloud_ctx->store.ci_servers,
        ctx->cloud_observer.original_on_selected_change.cb,
        ctx->cloud_observer.original_on_selected_change.cb_data);
      ctx->cloud_observer.original_on_selected_change.cb = NULL;
      ctx->cloud_observer.original_on_selected_change.cb_data = NULL;
    }
  }
  ctx->cloud_observer.last_status = 0;
  ctx->cloud_observer.retry_count = 0;
  oc_free_string(&ctx->cloud_observer.initial_endpoint_uri);
  memset(&ctx->cloud_observer.last_endpoint_uuid, 0, sizeof(oc_uuid_t));
  ctx->cloud_observer.remaining_endpoint_changes = 0;
}

bool
dps_cloud_observer_copy_endpoint_uuid(plgd_cloud_status_observer_t *obs,
                                      const oc_uuid_t *uuid)
{
  oc_uuid_t nil_uuid = { { 0 } };
  if (uuid == NULL) {
    uuid = &nil_uuid;
  }

  if (oc_uuid_is_equal(obs->last_endpoint_uuid, *uuid)) {
    return false;
  }
  memcpy(&obs->last_endpoint_uuid, uuid, sizeof(oc_uuid_t));
  return true;
}

static bool
dps_cloud_observer_server_retry_is_ongoing(
  const plgd_cloud_status_observer_t *obs)
{
  return oc_string(obs->initial_endpoint_uri) != NULL;
}

bool
dps_cloud_observer_load(plgd_cloud_status_observer_t *obs,
                        const oc_cloud_context_t *cloud_ctx)
{
  // get the selected cloud server
  const oc_endpoint_address_t *selected =
    oc_cloud_selected_server_address(cloud_ctx);
  if (selected == NULL) {
    DPS_ERR("No cloud server selected");
    return false;
  }
  oc_copy_string(&obs->initial_endpoint_uri, oc_endpoint_address_uri(selected));
  dps_cloud_observer_copy_endpoint_uuid(obs,
                                        oc_endpoint_address_uuid(selected));

  // endpoint retry count = number of cloud servers (except the currently
  // selected one)
  obs->remaining_endpoint_changes = dps_cloud_count_servers(cloud_ctx, true);
  DPS_DBG("Number of alternative cloud servers: %u",
          (unsigned)obs->remaining_endpoint_changes);
  obs->retry_count = 0;
  obs->last_status = 0;
  return true;
}

void
dps_cloud_observer_on_provisioning_started(plgd_dps_context_t *ctx,
                                           oc_cloud_context_t *cloud_ctx)
{
  if (dps_cloud_observer_server_retry_is_ongoing(&ctx->cloud_observer)) {
    DPS_INFO("Reinitializing cloud observer on cloud provisioning of server "
             "with different ID");
    dps_cloud_observe_status(ctx);
    return;
  }

  DPS_INFO("Initializing cloud observer on cloud provisioning start-up");
  if (!dps_cloud_observer_load(&ctx->cloud_observer, cloud_ctx)) {
    dps_manager_reprovision_and_restart(ctx);
    return;
  }

  // add on selection change callback, but store the original callback and data
  // to be able to invoke it and restore it
  oc_endpoint_addresses_on_selected_change_t cloud_on_selected_change =
    oc_endpoint_addresses_get_on_selected_change(&cloud_ctx->store.ci_servers);
  assert(cloud_on_selected_change.cb !=
         &dps_cloud_observer_on_cloud_server_change);
  if (cloud_on_selected_change.cb !=
      &dps_cloud_observer_on_cloud_server_change) {
    ctx->cloud_observer.original_on_selected_change = cloud_on_selected_change;
    oc_endpoint_addresses_set_on_selected_change(
      &cloud_ctx->store.ci_servers, dps_cloud_observer_on_cloud_server_change,
      ctx);
  }

  dps_cloud_observe_status(ctx);
}

oc_event_callback_retval_t
dps_cloud_observer_reprovision_server_uuid_change_async(void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx != NULL) {
    oc_cloud_manager_stop_v1(cloud_ctx, false);
  }
  // execute status callback right after this handler ends
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  // remove credentials and ACLs
  dps_set_ps_and_last_error(ctx, 0,
                            PLGD_DPS_GET_CREDENTIALS |
                              PLGD_DPS_HAS_CREDENTIALS | PLGD_DPS_GET_ACLS |
                              PLGD_DPS_HAS_ACLS | PLGD_DPS_CLOUD_STARTED,
                            ctx->last_error);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));

  // go to next step -> get credentials
  dps_provisioning_schedule_next_step(ctx);
  return OC_EVENT_DONE;
}

void
dps_cloud_observer_on_server_change(plgd_dps_context_t *ctx)
{
  if (ctx->cloud_observer.remaining_endpoint_changes == 0) {
    DPS_DBG("No cloud server left to try");
    return;
  }

  const oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx == NULL) {
    DPS_ERR("failed to obtain cloud context for device(%zu)", ctx->device);
    goto reprovision;
  }
  const oc_endpoint_address_t *selected =
    oc_cloud_selected_server_address(cloud_ctx);
  if (selected == NULL) {
    DPS_ERR("no cloud server selected");
    goto reprovision;
  }
  if (oc_string_is_equal(&ctx->cloud_observer.initial_endpoint_uri,
                         oc_endpoint_address_uri(selected))) {
    DPS_INFO("initial cloud server reached, forcing reprovisioning");
    ctx->cloud_observer.remaining_endpoint_changes = 0;
    goto reprovision;
  }

  --ctx->cloud_observer.remaining_endpoint_changes;
  ctx->cloud_observer.retry_count = 0;
  ctx->cloud_observer.last_status = 0;

  if (dps_cloud_observer_copy_endpoint_uuid(
        &ctx->cloud_observer, oc_endpoint_address_uuid(selected))) {
    DPS_INFO(
      "cloud server uuid has changed, reprovisioning credentials and ACLs");
    oc_remove_delayed_callback(ctx, dps_cloud_observe_status_async);
    // execute outside of the on change callback
    dps_reset_delayed_callback_ms(
      ctx, dps_cloud_observer_reprovision_server_uuid_change_async, 0);
    return;
  }

  dps_cloud_observe_status(ctx);
  return;

reprovision:
  oc_remove_delayed_callback(ctx, dps_cloud_observe_status_async);
  dps_reset_delayed_callback(ctx, dps_manager_reprovision_and_restart_async, 0);
}

bool
plgd_dps_set_cloud_observer_configuration(plgd_dps_context_t *ctx,
                                          uint8_t max_retry_count,
                                          uint8_t retry_interval_s)
{
  assert(ctx != NULL);
  if (retry_interval_s == 0) {
    DPS_ERR("configure cloud observer failed: invalid interval");
    return false;
  }
  ctx->cloud_observer.cfg.max_count = max_retry_count;
  ctx->cloud_observer.cfg.interval_s = retry_interval_s;
  DPS_DBG("cloud status observer cfg:");
  DPS_DBG("\tmax_count:%u", (unsigned)ctx->cloud_observer.cfg.max_count);
  DPS_DBG("\tinterval_s:%u", (unsigned)ctx->cloud_observer.cfg.interval_s);
  return true;
}

plgd_cloud_status_observer_configuration_t
plgd_dps_get_cloud_observer_configuration(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->cloud_observer.cfg;
}

void
dps_cloud_observe_status(plgd_dps_context_t *ctx)
{
  if (ctx->cloud_observer.cfg.max_count == 0) {
    DPS_DBG("cloud status observer disabled");
    dps_cloud_observer_deinit(ctx);
    return;
  }
  if (oc_has_delayed_callback(ctx, dps_cloud_observe_status_async, false)) {
    DPS_DBG("cloud status observer already scheduled or running");
    return;
  }
  DPS_DBG("cloud status observer scheduled to start in %u seconds",
          (unsigned)ctx->cloud_observer.cfg.interval_s);
  dps_reset_delayed_callback(ctx, dps_cloud_observe_status_async,
                             ctx->cloud_observer.cfg.interval_s);
}

static bool
dps_cloud_observer_update_status(plgd_cloud_status_observer_t *obs,
                                 oc_cloud_status_t add_status)
{
  if ((obs->last_status & add_status) == 0) {
    obs->last_status |= add_status;
    obs->retry_count = 0;
    return true;
  }
  return false;
}

oc_event_callback_retval_t
dps_cloud_observe_status_async(void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx == NULL) {
    DPS_ERR("Cannot obtain cloud context for device(%zu), force reprovisioning",
            ctx->device);
    goto provisioning_restart;
  }
  if (!oc_cloud_manager_is_started(cloud_ctx)) {
    DPS_ERR("Cloud manager has not been started, force reprovisioning");
    goto provisioning_restart;
  }

  if (ctx->cloud_observer.cfg.max_count == 0) {
    DPS_INFO("Cloud status observer disabled");
    return OC_EVENT_DONE;
  }

  if (oc_cloud_get_server_session_state(cloud_ctx) == OC_SESSION_DISCONNECTED) {
    DPS_DBG("Cloud disconnected");
    ctx->cloud_observer.last_status = 0;
    goto retry;
  }

  uint8_t cloud_status = oc_cloud_get_status(cloud_ctx);
  if ((cloud_status & OC_CLOUD_REGISTERED) != 0 &&
      dps_cloud_observer_update_status(&ctx->cloud_observer,
                                       OC_CLOUD_REGISTERED)) {
    DPS_DBG("Cloud registered");
  }
  if ((cloud_status & OC_CLOUD_LOGGED_IN) != 0 &&
      dps_cloud_observer_update_status(&ctx->cloud_observer,
                                       OC_CLOUD_LOGGED_IN)) {
    DPS_DBG("Cloud logged in");
  }
  if ((ctx->cloud_observer.last_status &
       (OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN)) ==
      (OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN)) {
    DPS_INFO("Cloud registered and logged in");
    dps_cloud_observer_deinit(ctx);
    return OC_EVENT_DONE;
  }

retry:
  DPS_DBG("Waiting for cloud (retry:%d)", (int)ctx->cloud_observer.retry_count);
  ++ctx->cloud_observer.retry_count;
  if (ctx->cloud_observer.retry_count >= ctx->cloud_observer.cfg.max_count) {
    DPS_DBG("Cloud observer reached max retry count");
    if (ctx->cloud_observer.remaining_endpoint_changes == 0) {
      DPS_DBG("No cloud server left to try, force reprovisioning");
      // rollback to the initial cloud server
      oc_endpoint_addresses_select_by_uri(
        &cloud_ctx->store.ci_servers,
        oc_string_view2(&ctx->cloud_observer.initial_endpoint_uri));
      goto provisioning_restart;
    }
    DPS_DBG("Switching to the next cloud server");
    if (!oc_endpoint_addresses_select_next(&cloud_ctx->store.ci_servers)) {
      DPS_DBG(
        "Failed to switch to the next cloud server, force reprovisioning");
      goto provisioning_restart;
    }
    oc_cloud_manager_restart(cloud_ctx);
    return OC_EVENT_DONE;
  }

  return OC_EVENT_CONTINUE;

provisioning_restart:
  dps_cloud_observer_deinit(ctx);
  dps_manager_reprovision_and_restart(ctx);
  return OC_EVENT_DONE;
}

typedef struct
{
  const oc_string_t *uri;
  oc_uuid_t uuid;
  bool found;
} dps_cloud_match_data_t;

static bool
dps_cloud_match(oc_endpoint_address_t *eaddr, void *data)
{
  dps_cloud_match_data_t *match = (dps_cloud_match_data_t *)data;
  const oc_string_t *ea_uri = oc_endpoint_address_uri(eaddr);
  assert(ea_uri != NULL);
  const oc_uuid_t *ea_uuid = oc_endpoint_address_uuid(eaddr);
  assert(ea_uuid != NULL);
  if (oc_string_is_equal(match->uri, ea_uri) &&
      oc_uuid_is_equal(match->uuid, *ea_uuid)) {
    match->found = true;
    return false; // stop iteration
  }
  return true; // continue iteration
}

static bool
dps_cloud_contains_server(const oc_cloud_context_t *cloud_ctx,
                          const oc_string_t *uri, oc_uuid_t uuid)
{
  dps_cloud_match_data_t match = {
    .uri = uri,
    .uuid = uuid,
    .found = false,
  };
  oc_cloud_iterate_server_addresses(cloud_ctx, dps_cloud_match, &match);
  return match.found;
}

void
dps_cloud_add_servers(oc_cloud_context_t *cloud_ctx, const oc_rep_t *servers)
{
  for (const oc_rep_t *server = servers; server != NULL;
       server = server->next) {
    const oc_rep_t *rep = oc_rep_get_by_type_and_key(
      server->value.object, OC_REP_STRING, DPS_CLOUD_ENDPOINT_URI,
      OC_CHAR_ARRAY_LEN(DPS_CLOUD_ENDPOINT_URI));
    if (rep == NULL) {
      DPS_ERR("cloud server uri missing");
      continue;
    }
    const oc_string_t *uri = &rep->value.string;

    rep = oc_rep_get_by_type_and_key(server->value.object, OC_REP_STRING,
                                     DPS_CLOUD_ENDPOINT_ID,
                                     OC_CHAR_ARRAY_LEN(DPS_CLOUD_ENDPOINT_ID));
    oc_string_view_t idv = { 0 };
    oc_uuid_t uuid = { 0 };
    if (rep != NULL) {
      idv = oc_string_view2(&rep->value.string);
      if (oc_str_to_uuid_v1(idv.data, idv.length, &uuid) < 0) {
        DPS_ERR("cloud server id(%s) invalid", idv.data);
        continue;
      }
    }

    oc_string_view_t uriv = oc_string_view2(uri);
    if (dps_cloud_contains_server(cloud_ctx, uri, uuid)) {
      DPS_DBG("cloud server address already added (uri:%s, id=%s)", uriv.data,
              idv.data != NULL ? idv.data : "NULL");
      continue;
    }
    if (oc_cloud_add_server_address(cloud_ctx, uriv.data, uriv.length, uuid) ==
        NULL) {
      DPS_ERR("failed to add cloud server address (uri:%s, id=%s)", uriv.data,
              idv.data != NULL ? idv.data : "NULL");
      continue;
    }
    DPS_DBG("cloud server address added (uri:%s, id=%s)", uriv.data,
            idv.data != NULL ? idv.data : "NULL");
  }
}

typedef struct
{
  const oc_endpoint_address_t *toIgnore;
  uint8_t count;
} dps_cloud_count_data_t;

static bool
dps_cloud_count_address(oc_endpoint_address_t *address, void *data)
{
  dps_cloud_count_data_t *ccd = (dps_cloud_count_data_t *)data;
  if (address != ccd->toIgnore) {
    ++ccd->count;
  }
  return true;
}

uint8_t
dps_cloud_count_servers(const oc_cloud_context_t *cloud_ctx,
                        bool ignoreSelected)
{
  dps_cloud_count_data_t ccd = {
    .toIgnore =
      ignoreSelected ? oc_cloud_selected_server_address(cloud_ctx) : NULL,
    .count = 0,
  };
  oc_cloud_iterate_server_addresses(cloud_ctx, dps_cloud_count_address, &ccd);
  return ccd.count;
}
