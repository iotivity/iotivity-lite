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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_deregister_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/cloud/oc_cloud_log_internal.h"
#include "api/cloud/oc_cloud_manager_internal.h"
#include "api/cloud/oc_cloud_rd_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/cloud/oc_cloud_store_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_ri_server_internal.h"
#include "api/oc_server_api_internal.h"
#include "oc_api.h"
#include "oc_collection.h"
#include "oc_core_res.h"
#include "oc_network_monitor.h"
#include "port/oc_assert.h"
#include "util/oc_mmem_internal.h"
#include "util/oc_secure_string_internal.h"

#ifdef OC_SECURITY
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

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
  OC_CLOUD_DBG("cloud manager status changed %d", (int)ctx->store.status);
  cloud_rd_manager_status_changed(ctx);

  if (ctx->on_status_change.cb != NULL) {
    ctx->on_status_change.cb(ctx, ctx->store.status,
                             ctx->on_status_change.user_data);
  }
}

static oc_event_callback_retval_t
start_manager(void *user_data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)user_data;
  oc_free_endpoint(ctx->cloud_ep);
  ctx->cloud_ep = oc_new_endpoint();
  ctx->store.status &= ~OC_CLOUD_LOGGED_IN;
  cloud_manager_start(ctx);
  cloud_manager_cb(ctx);
  return OC_EVENT_DONE;
}

static void
cloud_manager_restart(oc_cloud_context_t *ctx)
{
  if (!ctx->cloud_manager) {
    OC_CLOUD_ERR("cloud manager is not running");
    return;
  }
  cloud_manager_stop(ctx);
  oc_cloud_deregister_stop(ctx);
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

bool
oc_cloud_set_endpoint(oc_cloud_context_t *ctx)
{
  assert(ctx->cloud_ep != NULL);
  if (!oc_endpoint_is_empty(ctx->cloud_ep)) {
    return true;
  }

  bool success = false;
  const oc_string_t *ep_addr =
    oc_cloud_endpoint_selected_address(&ctx->store.ci_servers);
  if (oc_string_to_endpoint(ep_addr, ctx->cloud_ep, NULL) == 0) {
    // set device id to cloud endpoint for multiple servers
    ctx->cloud_ep->device = ctx->device;
    success = true;
  }
#ifdef OC_DNS_CACHE
  oc_dns_clear_cache();
#endif /* OC_DNS_CACHE */

  return success;
}

void
oc_cloud_close_endpoint(const oc_endpoint_t *ep)
{
  OC_CLOUD_DBG("oc_cloud_close_endpoint");
#ifdef OC_SECURITY
  const oc_tls_peer_t *peer = oc_tls_get_peer(ep);
  if (peer != NULL) {
    OC_CLOUD_DBG("oc_cloud_close_endpoint: oc_tls_close_connection");
    oc_tls_close_connection(ep);
  } else
#endif /* OC_SECURITY */
  {
#ifdef OC_TCP
    OC_CLOUD_DBG("oc_cloud_close_endpoint: oc_connectivity_end_session");
    oc_connectivity_end_session(ep);
#endif /* OC_TCP */
  }
}

int
cloud_reset(size_t device, bool force, bool sync, uint16_t timeout)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(device);
  if (ctx == NULL) {
    return -1;
  }
  OC_CLOUD_DBG("cloud_reset");

#ifdef OC_SECURITY
  if (!force && oc_tls_connected(ctx->cloud_ep) &&
      oc_cloud_deregister_on_reset(ctx, sync, timeout)) {
    return 0;
  }
#else  /* !OC_SECURITY */
  (void)timeout;
  (void)sync;
  (void)force;
#endif /* OC_SECURITY */

  cloud_context_clear(ctx);
  return 0;
}

void
cloud_set_cloudconf(oc_cloud_context_t *ctx, const oc_cloud_conf_update_t *data)
{
  assert(ctx != NULL);
  assert(data != NULL);
  if (!oc_string_is_null_or_empty(data->access_token)) {
    oc_copy_string(&ctx->store.access_token, data->access_token);
  }
  if (!oc_string_is_null_or_empty(data->auth_provider)) {
    oc_copy_string(&ctx->store.auth_provider, data->auth_provider);
  }
  if (!oc_string_is_null_or_empty(data->ci_server)) {
    // cannot oc_cloud_endpoints_reinit, because the deinit might deallocate
    // oc_string_t values and relocate memory, thus invalidating the
    // oc_string_view
    oc_cloud_endpoints_deinit(&ctx->store.ci_servers);
    // oc_cloud_endpoints_init only allocates, so the oc_string_view_t is valid
    oc_string_view_t cis = oc_string_view2(data->ci_server);
    if (!oc_cloud_endpoints_init(
          &ctx->store.ci_servers, ctx->store.ci_servers.on_selected_change,
          ctx->store.ci_servers.on_selected_change_data, cis, data->sid)) {
      OC_WRN("Failed to reinitialize cloud server endpoints");
    }
  }
}

static oc_string_t
cloud_cstring_to_temp_oc_string(const char *str, size_t len)
{
  return OC_MMEM((void *)str, len + 1, NULL); // +1 for null terminator
}

int
oc_cloud_provision_conf_resource(oc_cloud_context_t *ctx, const char *server,
                                 const char *access_token,
                                 const char *server_id,
                                 const char *auth_provider)
{
  assert(ctx != NULL);
  if (server == NULL || access_token == NULL || server_id == NULL) {
    return -1;
  }
  size_t server_len = oc_strnlen(server, OC_MAX_STRING_LENGTH);
  if (server_len >= OC_MAX_STRING_LENGTH) {
    return -1;
  }
  size_t access_token_len = oc_strnlen(access_token, OC_MAX_STRING_LENGTH);
  if (access_token_len >= OC_MAX_STRING_LENGTH) {
    return -1;
  }
  size_t server_id_len = oc_strnlen(server_id, OC_UUID_LEN);
  oc_uuid_t sid = OCF_COAPCLOUDCONF_DEFAULT_SID;
  if (server_id_len > 0 &&
      oc_str_to_uuid_v1(server_id, server_id_len, &sid) != OC_UUID_ID_SIZE) {
    OC_ERR("invalid sid(%s)", server_id);
    return -1;
  }
  size_t auth_provider_len = oc_strnlen_s(auth_provider, OC_MAX_STRING_LENGTH);
  if (auth_provider_len >= OC_MAX_STRING_LENGTH) {
    return -1;
  }

  oc_cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  oc_cloud_store_reinitialize(&ctx->store);
  cloud_manager_stop(ctx);
  oc_cloud_deregister_stop(ctx);

  const oc_string_t at =
    cloud_cstring_to_temp_oc_string(access_token, access_token_len);
  const oc_string_t s = cloud_cstring_to_temp_oc_string(server, server_len);
  oc_cloud_conf_update_t data = {
    .access_token = &at,
    .ci_server = &s,
    .sid = sid,
  };

  const oc_string_t ap =
    cloud_cstring_to_temp_oc_string(auth_provider, auth_provider_len);
  if (auth_provider != NULL) {
    data.auth_provider = &ap;
  }

  cloud_set_cloudconf(ctx, &data);
  cloud_rd_reset_context(ctx);

  ctx->store.status = OC_CLOUD_INITIALIZED;
  ctx->store.cps = OC_CPS_READYTOREGISTER;

  oc_cloud_store_dump_async(&ctx->store);

  if (ctx->cloud_manager) {
    oc_cloud_manager_restart(ctx);
  }
  return 0;
}

void
oc_cloud_update_by_resource(oc_cloud_context_t *ctx,
                            const oc_cloud_conf_update_t *data)
{
  assert(data->ci_server != NULL);
  if (oc_string_is_empty(data->ci_server)) {
    OC_CLOUD_DBG("got forced deregister via provisioning of empty cis");
    if (cloud_reset(ctx->device, false, false, CLOUD_DEREGISTER_TIMEOUT) != 0) {
      OC_CLOUD_DBG("reset failed");
    }
    return;
  }

  // if deregistering or other cloud API was active then closing of the endpoint
  // triggers the handler with timeout error, which ensures that/ the operation
  // is interrupted
  oc_cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  oc_cloud_store_reinitialize(&ctx->store);
  cloud_manager_stop(ctx);
  oc_cloud_deregister_stop(ctx);

  cloud_set_cloudconf(ctx, data);
  cloud_rd_reset_context(ctx);

  ctx->store.status = OC_CLOUD_INITIALIZED;
  ctx->store.cps = OC_CPS_READYTOREGISTER;
  if (ctx->cloud_manager) {
    oc_cloud_manager_restart(ctx);
  }
}

#ifdef OC_SESSION_EVENTS
static void
cloud_ep_session_event_handler(const oc_endpoint_t *endpoint,
                               oc_session_state_t state, void *user_data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)user_data;
  if (oc_endpoint_compare(endpoint, ctx->cloud_ep) != 0) {
    OC_CLOUD_DBG("session handler skipped: endpoint does not match");
    return;
  }
  OC_CLOUD_DBG("cloud_ep_session_event_handler ep_state: %d (current: %d)",
               (int)state, (int)ctx->cloud_ep_state);
  bool state_changed = ctx->cloud_ep_state != state;
  if (!state_changed) {
    return;
  }

  ctx->cloud_ep_state = state;
  if (ctx->cloud_ep_state == OC_SESSION_DISCONNECTED) {
    OC_CLOUD_INFO("Session disconnected");
    if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0 && ctx->cloud_manager) {
      cloud_manager_restart(ctx);
    }
  }
}
#endif /* OC_SESSION_EVENTS */

#ifdef OC_NETWORK_MONITOR

static void
cloud_interface_up_event_handler(oc_cloud_context_t *ctx, void *user_data)
{
  (void)user_data;
  if (ctx->store.status == OC_CLOUD_INITIALIZED && ctx->cloud_manager) {
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

#endif /* OC_NETWORK_MONITOR */

void
cloud_set_last_error(oc_cloud_context_t *ctx, oc_cloud_error_t error)
{
  if (error != ctx->last_error) {
    ctx->last_error = error;
    oc_resource_t *cloud_conf =
      oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, ctx->device);
    if (cloud_conf != NULL) {
      oc_notify_resource_changed(cloud_conf);
    }
  }
}

void
cloud_set_cps(oc_cloud_context_t *ctx, oc_cps_t cps)
{
  if (cps != ctx->store.cps) {
    ctx->store.cps = cps;
    oc_resource_t *cloud_conf =
      oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, ctx->device);
    if (cloud_conf != NULL) {
      oc_notify_resource_changed(cloud_conf);
    }
  }
}

void
cloud_set_cps_and_last_error(oc_cloud_context_t *ctx, oc_cps_t cps,
                             oc_cloud_error_t error)
{
  if ((error != ctx->last_error) || (cps != ctx->store.cps)) {
    ctx->store.cps = cps;
    ctx->last_error = error;
    oc_resource_t *cloud_conf =
      oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, ctx->device);
    if (cloud_conf != NULL) {
      oc_notify_resource_changed(cloud_conf);
    }
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
  if (!ctx->cloud_manager) {
    OC_CLOUD_ERR("cloud manager is not running");
    return;
  }
  OC_CLOUD_DBG("oc_cloud_manager_restart");
#ifdef OC_SESSION_EVENTS
  if (ctx->cloud_ep_state == OC_SESSION_CONNECTED) {
    bool is_tcp = (ctx->cloud_ep->flags & TCP) != 0;
    oc_cloud_close_endpoint(ctx->cloud_ep);
    if (is_tcp) {
      return;
    }
  }
#endif /* OC_SESSION_EVENTS */
  oc_reset_delayed_callback(ctx, restart_manager, 0);
}

bool
oc_cloud_manager_is_started(const oc_cloud_context_t *ctx)
{
  return ctx->cloud_manager;
}

int
oc_cloud_manager_start(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL) {
    return -1;
  }

  ctx->on_status_change.cb = cb;
  ctx->on_status_change.user_data = data;

  cloud_manager_start(ctx);
  ctx->cloud_manager = true;
#ifdef OC_SESSION_EVENTS
  oc_remove_session_event_callback_v1(cloud_ep_session_event_handler, ctx,
                                      false);
  oc_add_session_event_callback_v1(cloud_ep_session_event_handler, ctx);
#endif /* OC_SESSION_EVENTS */
#ifdef OC_NETWORK_MONITOR
  oc_remove_network_interface_event_callback(cloud_interface_event_handler);
  oc_add_network_interface_event_callback(cloud_interface_event_handler);
#endif /* OC_NETWORK_MONITOR */

  return 0;
}

int
oc_cloud_manager_stop(oc_cloud_context_t *ctx)
{
  if (ctx == NULL) {
    return -1;
  }

#ifdef OC_SESSION_EVENTS
  oc_remove_session_event_callback_v1(cloud_ep_session_event_handler, ctx,
                                      false);
#endif /* OC_SESSION_EVENTS */
#ifdef OC_NETWORK_MONITOR
  if (cloud_context_size() == 0) {
    oc_remove_network_interface_event_callback(cloud_interface_event_handler);
  }
#endif /* OC_NETWORK_MONITOR */
  oc_remove_delayed_callback(ctx, restart_manager);
  oc_remove_delayed_callback(ctx, start_manager);
  cloud_rd_reset_context(ctx);
  cloud_manager_stop(ctx);
  oc_cloud_store_reinitialize(&ctx->store);
  oc_cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  ctx->cloud_manager = false;

  return 0;
}

bool
oc_cloud_init(void)
{
  if (!oc_ri_on_delete_resource_add_callback(oc_cloud_delete_resource)) {
    return false;
  }
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    if (cloud_context_init(device) == NULL) {
      return false;
    }
    oc_cloud_add_resource(oc_core_get_resource_by_index(OCF_P, 0));
    oc_cloud_add_resource(oc_core_get_resource_by_index(OCF_D, device));
  }
  return true;
}

void
oc_cloud_shutdown(void)
{
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    oc_cloud_context_t *ctx = oc_cloud_get_context(device);
    if (ctx == NULL) {
      OC_CLOUD_ERR("invalid cloud context for device=%zu", device);
      continue;
    }
    cloud_manager_stop(ctx);
#ifdef OC_SESSION_EVENTS
    oc_remove_session_event_callback_v1(cloud_ep_session_event_handler, ctx,
                                        false);
#endif /* OC_SESSION_EVENTS */
    cloud_context_deinit(ctx);
    OC_CLOUD_DBG("cloud_shutdown for %d", (int)device);
  }
  oc_ri_on_delete_resource_remove_callback(oc_cloud_delete_resource);
}

#endif /* OC_CLOUD */
