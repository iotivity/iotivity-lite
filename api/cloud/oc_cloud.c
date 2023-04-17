/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_config.h"

#ifdef OC_CLOUD

#include "api/oc_server_api_internal.h"
#include "oc_api.h"
#include "oc_cloud_context_internal.h"
#include "oc_cloud_deregister_internal.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_manager_internal.h"
#include "oc_cloud_store_internal.h"
#include "oc_collection.h"
#include "oc_core_res.h"
#include "oc_network_monitor.h"
#include "port/oc_assert.h"

#ifdef OC_SECURITY
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

void
cloud_reset_delayed_callback(void *cb_data, oc_trigger_t callback,
                             uint16_t seconds)
{
  oc_remove_delayed_callback(cb_data, callback);
  oc_set_delayed_callback(cb_data, callback, seconds);
}

void
cloud_reset_delayed_callback_ms(void *cb_data, oc_trigger_t callback,
                                uint64_t milliseconds)
{
  oc_remove_delayed_callback(cb_data, callback);
  oc_set_delayed_callback_ms_v1(cb_data, callback, milliseconds);
}

bool
cloud_is_connection_error_code(oc_status_t code)
{
  return code == OC_STATUS_SERVICE_UNAVAILABLE ||
         code == OC_STATUS_GATEWAY_TIMEOUT || code == OC_CONNECTION_CLOSED ||
         code == OC_TRANSACTION_TIMEOUT;
}

bool
cloud_is_timeout_error_code(oc_status_t code)
{
  return code == OC_REQUEST_TIMEOUT;
}

void
cloud_manager_cb(oc_cloud_context_t *ctx)
{
  OC_DBG("cloud manager status changed %d", (int)ctx->store.status);
  cloud_rd_manager_status_changed(ctx);

  if (ctx->callback != NULL) {
    ctx->callback(ctx, ctx->store.status, ctx->user_data);
  }
}

static oc_event_callback_retval_t
start_manager(void *user_data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)user_data;
  oc_free_endpoint(ctx->cloud_ep);
  ctx->cloud_ep = oc_new_endpoint();
  cloud_manager_start(ctx);
  return OC_EVENT_DONE;
}

static void
cloud_manager_restart(oc_cloud_context_t *ctx)
{
  cloud_manager_stop(ctx);
  cloud_deregister_stop(ctx);
  oc_remove_delayed_callback(ctx, start_manager);
  oc_set_delayed_callback(ctx, start_manager, 0);
}

static oc_event_callback_retval_t
restart_manager(void *user_data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)user_data;
  cloud_manager_restart(ctx);
  return OC_EVENT_DONE;
}

void
cloud_close_endpoint(const oc_endpoint_t *cloud_ep)
{
  OC_DBG("cloud_close_endpoint");
#ifdef OC_SECURITY
  const oc_tls_peer_t *peer = oc_tls_get_peer(cloud_ep);
  if (peer != NULL) {
    OC_DBG("cloud_close_endpoint: oc_tls_close_connection");
    oc_tls_close_connection(cloud_ep);
  } else
#endif /* OC_SECURITY */
  {
#ifdef OC_TCP
    OC_DBG("cloud_close_endpoint: oc_connectivity_end_session");
    oc_connectivity_end_session(cloud_ep);
#endif /* OC_TCP */
  }
}

int
cloud_reset(size_t device, bool sync, uint16_t timeout)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(device);
  if (ctx == NULL) {
    return -1;
  }
  OC_DBG("[Cloud] cloud_reset");

#ifdef OC_SECURITY
  if (oc_tls_connected(ctx->cloud_ep) &&
      cloud_deregister_on_reset(ctx, sync, timeout)) {
    return 0;
  }
#else  /* !OC_SECURITY */
  (void)timeout;
  (void)sync;
#endif /* OC_SECURITY */

  cloud_context_clear(ctx);
  return 0;
}

void
cloud_set_cloudconf(oc_cloud_context_t *ctx, const cloud_conf_update_t *data)
{
  assert(ctx != NULL);
  assert(data != NULL);
  if (data->auth_provider && data->auth_provider_len) {
    oc_set_string(&ctx->store.auth_provider, data->auth_provider,
                  data->auth_provider_len);
  }
  if (data->access_token && data->access_token_len) {
    oc_set_string(&ctx->store.access_token, data->access_token,
                  data->access_token_len);
  }
  if (data->ci_server && data->ci_server_len) {
    oc_set_string(&ctx->store.ci_server, data->ci_server, data->ci_server_len);
  }
  if (data->sid && data->sid_len) {
    oc_set_string(&ctx->store.sid, data->sid, data->sid_len);
  }
}

int
oc_cloud_provision_conf_resource(oc_cloud_context_t *ctx, const char *server,
                                 const char *access_token,
                                 const char *server_id,
                                 const char *auth_provider)
{
  assert(ctx != NULL);
  if (!server || !access_token || !server_id) {
    return -1;
  }

  cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  cloud_store_initialize(&ctx->store);
  cloud_manager_stop(ctx);
  cloud_deregister_stop(ctx);

  cloud_conf_update_t data = {
    .access_token = access_token,
    .access_token_len = strlen(access_token),
    .ci_server = server,
    .ci_server_len = strlen(server),
    .sid = server_id,
    .sid_len = strlen(server_id),
    .auth_provider = auth_provider,
    .auth_provider_len = auth_provider != NULL ? strlen(auth_provider) : 0,
  };
  cloud_set_cloudconf(ctx, &data);
  cloud_rd_reset_context(ctx);

  ctx->store.status = OC_CLOUD_INITIALIZED;
  ctx->store.cps = OC_CPS_READYTOREGISTER;

  cloud_store_dump_async(&ctx->store);

  if (ctx->cloud_manager) {
    oc_cloud_manager_restart(ctx);
  }

  return 0;
}

void
cloud_update_by_resource(oc_cloud_context_t *ctx,
                         const cloud_conf_update_t *data)
{
  if (data->ci_server_len == 0) {
    OC_DBG("[Cloud] got forced deregister via provisioning of empty cis");
    if (cloud_reset(ctx->device, false, CLOUD_DEREGISTER_TIMEOUT) != 0) {
      OC_DBG("[Cloud] reset failed");
    }
    return;
  }

  // if deregistering or other cloud API was active then closing of the endpoint
  // triggers the handler with timeout error, which ensures that/ the operation
  // is interrupted
  cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  cloud_store_initialize(&ctx->store);
  cloud_manager_stop(ctx);
  cloud_deregister_stop(ctx);

  cloud_set_cloudconf(ctx, data);
  cloud_rd_reset_context(ctx);

  ctx->store.status = OC_CLOUD_INITIALIZED;
  ctx->store.cps = OC_CPS_READYTOREGISTER;
  if (ctx->cloud_manager) {
    oc_cloud_manager_restart(ctx);
    return;
  }

  if (oc_cloud_manager_start(ctx, ctx->callback, ctx->user_data) != 0) {
    OC_ERR("cannot start cloud manager");
  }
}

#ifdef OC_SESSION_EVENTS
static void
cloud_ep_session_event_handler(const oc_endpoint_t *endpoint,
                               oc_session_state_t state, void *user_data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)user_data;
  if (oc_endpoint_compare(endpoint, ctx->cloud_ep) != 0) {
    OC_DBG("session handler skipped: endpoint does not match");
    return;
  }
  OC_DBG("[CM] cloud_ep_session_event_handler ep_state: %d (current: %d)",
         (int)state, (int)ctx->cloud_ep_state);
  bool state_changed = ctx->cloud_ep_state != state;
  if (!state_changed) {
    return;
  }

  ctx->cloud_ep_state = state;
  if (ctx->cloud_ep_state == OC_SESSION_DISCONNECTED && ctx->cloud_manager &&
      (ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    cloud_manager_restart(ctx);
  }
}
#endif /* OC_SESSION_EVENTS */

static void
cloud_interface_up_event_handler(oc_cloud_context_t *ctx, void *user_data)
{
  (void)user_data;
  if (ctx->store.status == OC_CLOUD_INITIALIZED) {
    cloud_manager_restart(ctx);
  }
}

static void
cloud_interface_event_handler(oc_interface_event_t event)
{
  if (event == NETWORK_INTERFACE_UP) {
    cloud_context_iterate(cloud_interface_up_event_handler, NULL);
  }
}

void
cloud_set_last_error(oc_cloud_context_t *ctx, oc_cloud_error_t error)
{
  if (error != ctx->last_error) {
    ctx->last_error = error;
    oc_notify_observers(ctx->cloud_conf);
  }
}

void
cloud_set_cps(oc_cloud_context_t *ctx, oc_cps_t cps)
{
  if (cps != ctx->store.cps) {
    ctx->store.cps = cps;
    oc_notify_observers(ctx->cloud_conf);
  }
}

void
cloud_set_cps_and_last_error(oc_cloud_context_t *ctx, oc_cps_t cps,
                             oc_cloud_error_t error)
{
  if ((error != ctx->last_error) || (cps != ctx->store.cps)) {
    ctx->store.cps = cps;
    ctx->last_error = error;
    oc_notify_observers(ctx->cloud_conf);
  }
}

bool
cloud_is_deregistering(const oc_cloud_context_t *ctx)
{
  return ctx->store.cps == OC_CPS_DEREGISTERING;
}

void
oc_cloud_manager_restart(oc_cloud_context_t *ctx)
{
  OC_DBG("[CM] oc_cloud_manager_restart");
#ifdef OC_SESSION_EVENTS
  if (ctx->cloud_ep_state == OC_SESSION_CONNECTED) {
    bool is_tcp = (ctx->cloud_ep->flags & TCP) != 0;
    cloud_close_endpoint(ctx->cloud_ep);
    if (is_tcp) {
      return;
    }
  }
#endif /* OC_SESSION_EVENTS */
  oc_remove_delayed_callback(ctx, restart_manager);
  oc_set_delayed_callback(ctx, restart_manager, 0);
}

int
oc_cloud_manager_start(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL) {
    return -1;
  }

  ctx->callback = cb;
  ctx->user_data = data;

  cloud_manager_start(ctx);
  ctx->cloud_manager = true;
#ifdef OC_SESSION_EVENTS
  oc_remove_session_event_callback_v1(cloud_ep_session_event_handler, ctx,
                                      false);
  oc_remove_network_interface_event_callback(cloud_interface_event_handler);
  oc_add_session_event_callback_v1(cloud_ep_session_event_handler, ctx);
  oc_add_network_interface_event_callback(cloud_interface_event_handler);
#endif /* OC_SESSION_EVENTS */

  return 0;
}

int
oc_cloud_manager_stop(oc_cloud_context_t *ctx)
{
  if (!ctx) {
    return -1;
  }
#ifdef OC_SESSION_EVENTS
  oc_remove_session_event_callback_v1(cloud_ep_session_event_handler, ctx,
                                      false);
  if (cloud_context_size() == 0) {
    oc_remove_network_interface_event_callback(cloud_interface_event_handler);
  }
#endif /* OC_SESSION_EVENTS */
  oc_remove_delayed_callback(ctx, restart_manager);
  oc_remove_delayed_callback(ctx, start_manager);
  cloud_rd_reset_context(ctx);
  cloud_manager_stop(ctx);
  cloud_store_initialize(&ctx->store);
  cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  ctx->cloud_manager = false;
  return 0;
}

int
oc_cloud_init(void)
{
  oc_set_on_delayed_delete_resource_cb(oc_cloud_delete_resource);
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    if (cloud_context_init(device) == NULL) {
      return -1;
    }
    oc_cloud_add_resource(oc_core_get_resource_by_index(OCF_P, 0));
    oc_cloud_add_resource(oc_core_get_resource_by_index(OCF_D, device));
  }
  return 0;
}

void
oc_cloud_shutdown(void)
{
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    oc_cloud_context_t *ctx = oc_cloud_get_context(device);
    if (ctx == NULL) {
      OC_ERR("invalid cloud context for device=%zu", device);
      continue;
    }
    cloud_manager_stop(ctx);
#ifdef OC_SESSION_EVENTS
    oc_remove_session_event_callback_v1(cloud_ep_session_event_handler, ctx,
                                        false);
#endif /* OC_SESSION_EVENTS */
    cloud_context_deinit(ctx);
    OC_DBG("cloud_shutdown for %d", (int)device);
  }
}
#endif /* OC_CLOUD */
