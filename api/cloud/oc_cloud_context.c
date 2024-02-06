/****************************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#include "oc_config.h"

#ifdef OC_CLOUD

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_deregister_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/cloud/oc_cloud_log_internal.h"
#include "api/cloud/oc_cloud_manager_internal.h"
#include "api/cloud/oc_cloud_rd_internal.h"
#include "api/cloud/oc_cloud_store_internal.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_session_events.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

#include <assert.h>

OC_LIST(g_cloud_context_list);
OC_MEMB(g_cloud_context_pool, oc_cloud_context_t, OC_MAX_NUM_DEVICES);

static bool
need_to_reinitialize_cloud_storage(const oc_cloud_context_t *ctx)
{
#ifdef OC_SECURITY
  const oc_sec_pstat_t *ps = oc_sec_get_pstat(ctx->device);
  if (ps->s == OC_DOS_RFOTM || ps->s == OC_DOS_RESET) {
    return true;
  }
#endif /* OC_SECURITY  */
  return cloud_is_deregistering(ctx);
}

static void
reinitialize_cloud_storage(oc_cloud_context_t *ctx)
{
  if (!need_to_reinitialize_cloud_storage(ctx)) {
    return;
  }
  OC_CLOUD_DBG("reinitializing cloud context in storage");
  oc_cloud_store_initialize(&ctx->store);
  if (oc_cloud_store_dump(&ctx->store) < 0) {
    OC_CLOUD_ERR("failed to dump cloud store");
  }
}

oc_cloud_context_t *
cloud_context_init(size_t device)
{
  oc_cloud_context_t *ctx =
    (oc_cloud_context_t *)oc_memb_alloc(&g_cloud_context_pool);
  if (ctx == NULL) {
    OC_CLOUD_ERR("insufficient memory to create cloud context");
    return NULL;
  }
  ctx->next = NULL;
  ctx->device = device;
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  ctx->cloud_ep = oc_new_endpoint();
  ctx->selected_identity_cred_id = -1;
  oc_cloud_store_load(&ctx->store);
  ctx->store.status &=
    ~(OC_CLOUD_LOGGED_IN | OC_CLOUD_TOKEN_EXPIRY | OC_CLOUD_REFRESHED_TOKEN |
      OC_CLOUD_LOGGED_OUT | OC_CLOUD_FAILURE | OC_CLOUD_DEREGISTERED);
  // In the case of a factory reset and SEGFAULT occurs, the cloud data may
  // remain on the device when the device is shut down during de-registration.
  reinitialize_cloud_storage(ctx);
  ctx->time_to_live = RD_PUBLISH_TTL_UNLIMITED;
  ctx->cloud_manager = false;
  ctx->keepalive.ping_timeout = 4;
  oc_list_add(g_cloud_context_list, ctx);

  return ctx;
}

void
cloud_context_deinit(oc_cloud_context_t *ctx)
{
  cloud_rd_deinit(ctx);
  // In the case of a factory reset, the cloud data may remain on the device
  // when the device is shut down during de-registration.
  reinitialize_cloud_storage(ctx);
  oc_cloud_store_deinitialize(&ctx->store);
  oc_cloud_close_endpoint(ctx->cloud_ep);
  oc_free_endpoint(ctx->cloud_ep);
  oc_list_remove(g_cloud_context_list, ctx);
  oc_memb_free(&g_cloud_context_pool, ctx);
}

oc_cloud_context_t *
oc_cloud_get_context(size_t device)
{
  oc_cloud_context_t *ctx = oc_list_head(g_cloud_context_list);
  while (ctx != NULL && ctx->device != device) {
    ctx = ctx->next;
  }
  return ctx;
}

size_t
oc_cloud_get_device(const oc_cloud_context_t *ctx)
{
  return ctx->device;
}

const char *
oc_cloud_get_apn(const oc_cloud_context_t *ctx)
{
  return oc_string(ctx->store.auth_provider);
}

const char *
oc_cloud_get_at(const oc_cloud_context_t *ctx)
{
  return oc_string(ctx->store.access_token);
}

const char *
oc_cloud_get_cis(const oc_cloud_context_t *ctx)
{
  return oc_string_view2(
           oc_cloud_endpoint_selected_address(&ctx->store.ci_servers))
    .data;
}

const oc_uuid_t *
oc_cloud_get_sid(const oc_cloud_context_t *ctx)
{
  if (ctx->store.ci_servers.selected == NULL) {
    return NULL;
  }
  return &ctx->store.ci_servers.selected->id;
}

const char *
oc_cloud_get_uid(const oc_cloud_context_t *ctx)
{
  return oc_string(ctx->store.uid);
}

void
cloud_context_iterate(cloud_context_iterator_cb_t cb, void *user_data)
{
  for (oc_cloud_context_t *ctx = oc_list_head(g_cloud_context_list);
       ctx != NULL; ctx = ctx->next) {
    cb(ctx, user_data);
  }
}

void
cloud_context_clear(oc_cloud_context_t *ctx)
{
  oc_cloud_context_clear(ctx, true);
}

void
oc_cloud_context_clear(oc_cloud_context_t *ctx, bool dump_async)
{
  assert(ctx != NULL);

  cloud_rd_reset_context(ctx);
  oc_cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  cloud_manager_stop(ctx);
  oc_cloud_deregister_stop(ctx);
  oc_cloud_store_initialize(&ctx->store);
  ctx->last_error = 0;
  ctx->store.cps = 0;
  ctx->selected_identity_cred_id = -1;
  ctx->keepalive.ping_timeout = 4;
  if (dump_async) {
    oc_cloud_store_dump_async(&ctx->store);
  } else {
    oc_cloud_store_dump(&ctx->store);
  }
}

size_t
cloud_context_size(void)
{
  return oc_list_length(g_cloud_context_list);
}

bool
cloud_context_has_access_token(const oc_cloud_context_t *ctx)
{
  return !oc_string_is_empty(&ctx->store.access_token);
}

bool
cloud_context_has_permanent_access_token(const oc_cloud_context_t *ctx)
{
  return cloud_context_has_access_token(ctx) && ctx->store.expires_in < 0;
}

void
cloud_context_clear_access_token(oc_cloud_context_t *ctx)
{
  oc_set_string(&ctx->store.access_token, NULL, 0);
  ctx->store.expires_in = 0;
}

bool
cloud_context_has_refresh_token(const oc_cloud_context_t *ctx)
{
  return !oc_string_is_empty(&ctx->store.refresh_token);
}

void
oc_cloud_set_identity_cert_chain(oc_cloud_context_t *ctx, int cred_id)
{
  ctx->selected_identity_cred_id = cred_id;
}

int
oc_cloud_get_identity_cert_chain(const oc_cloud_context_t *ctx)
{
  return ctx->selected_identity_cred_id;
}

void
oc_cloud_set_keepalive(
  oc_cloud_context_t *ctx,
  oc_cloud_on_keepalive_response_cb_t on_keepalive_response, void *user_data)
{
  ctx->keepalive.on_response = on_keepalive_response;
  ctx->keepalive.user_data = user_data;
}

void
oc_cloud_set_schedule_action(oc_cloud_context_t *ctx,
                             oc_cloud_schedule_action_cb_t on_schedule_action,
                             void *user_data)
{
  ctx->schedule_action.on_schedule_action = on_schedule_action;
  ctx->schedule_action.user_data = user_data;
}

oc_cloud_endpoint_t *
oc_cloud_add_server(oc_cloud_context_t *ctx, const char *uri, size_t uri_len,
                    oc_uuid_t sid)
{
  return oc_cloud_endpoint_add(&ctx->store.ci_servers,
                               oc_string_view(uri, uri_len), sid);
}

bool
oc_cloud_remove_server(oc_cloud_context_t *ctx, const oc_cloud_endpoint_t *ce)
{
  return oc_cloud_endpoint_remove(&ctx->store.ci_servers, ce);
}

void
oc_cloud_iterate_servers(const oc_cloud_context_t *ctx,
                         oc_cloud_endpoints_iterate_fn_t fn, void *data)
{
  oc_cloud_endpoints_iterate(&ctx->store.ci_servers, fn, data);
}

bool
oc_cloud_select_server(oc_cloud_context_t *ctx,
                       const oc_cloud_endpoint_t *server)
{
  if (!oc_list_has_item(ctx->store.ci_servers.endpoints, server)) {
    return false;
  }
  ctx->store.ci_servers.selected = server;
  return true;
}

#endif /* OC_CLOUD */
