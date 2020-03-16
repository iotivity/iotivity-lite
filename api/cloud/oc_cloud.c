/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifdef OC_CLOUD

#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_collection.h"
#include "oc_core_res.h"
#include "oc_network_monitor.h"
#ifdef OC_SECURITY
#include "security/oc_tls.h"
#endif /* OC_SECURITY */

OC_LIST(cloud_context_list);
OC_MEMB(cloud_context_pool, oc_cloud_context_t, OC_MAX_NUM_DEVICES);

void
cloud_manager_cb(oc_cloud_context_t *ctx)
{
  OC_DBG("cloud manager status changed %d", (int)ctx->store.status);
  cloud_rd_manager_status_changed(ctx);

  if (ctx->callback) {
    ctx->callback(ctx, ctx->store.status, ctx->user_data);
  }
}

void
cloud_set_string(oc_string_t *dst, const char *data, size_t len)
{
  if (oc_string(*dst)) {
    oc_free_string(dst);
  }
  if (data && len) {
    oc_new_string(dst, data, len);
  } else {
    memset(dst, 0, sizeof(*dst));
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
cloud_close_endpoint(oc_endpoint_t *cloud_ep)
{
  OC_DBG("cloud_close_endpoint");
#ifdef OC_SECURITY
  oc_tls_peer_t *peer = oc_tls_get_peer(cloud_ep);
  if (peer) {
    OC_DBG("cloud_close_endpoint: oc_tls_close_connection\n");
    oc_tls_close_connection(cloud_ep);
  } else
#endif /* OC_SECURITY */
  {
#ifdef OC_TCP
    OC_DBG("cloud_close_endpoint: oc_connectivity_end_session\n");
    oc_connectivity_end_session(cloud_ep);
#endif /* OC_TCP */
  }
}

#ifdef OC_SECURITY
static void
cloud_deregister_on_reset_internal(oc_cloud_context_t *ctx,
                                   oc_cloud_status_t status, void *data)
{
  (void)status;
  (void)data;
  cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  cloud_store_initialize(&ctx->store);
  cloud_manager_stop(ctx);
  ctx->last_error = 0;
  ctx->cps = 0;
}
#endif /* OC_SECURITY */

int
oc_cloud_reset_context(size_t device)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(device);
  if (!ctx) {
    return -1;
  }

#ifdef OC_SECURITY
  if (oc_tls_connected(ctx->cloud_ep)) {
    if (oc_cloud_deregister(ctx, cloud_deregister_on_reset_internal, ctx) ==
        0) {
      return 0;
    }
  }
#endif /* OC_SECURITY */

  cloud_store_initialize(&ctx->store);
  cloud_manager_stop(ctx);
  ctx->last_error = 0;
  ctx->cps = 0;
  return 0;
}

int
oc_cloud_provision_conf_resource(oc_cloud_context_t *ctx, const char *server,
                                 const char *access_token,
                                 const char *server_id,
                                 const char *auth_provider)
{
  if (!server || !access_token || !server_id) {
    return -1;
  }

  cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  cloud_store_initialize(&ctx->store);
  cloud_manager_stop(ctx);

  cloud_set_string(&ctx->store.ci_server, server, strlen(server));
  cloud_set_string(&ctx->store.access_token, access_token,
                   strlen(access_token));
  cloud_set_string(&ctx->store.sid, server_id, strlen(server_id));

  if (auth_provider) {
    cloud_set_string(&ctx->store.auth_provider, auth_provider,
                     strlen(auth_provider));
  }

  ctx->store.status = OC_CLOUD_INITIALIZED;
  ctx->cps = OC_CPS_READYTOREGISTER;

  cloud_store_dump_async(&ctx->store);

  if (ctx->cloud_manager) {
    cloud_reconnect(ctx);
  }

  return 0;
}

void
cloud_update_by_resource(oc_cloud_context_t *ctx,
                         const cloud_conf_update_t *data)
{
  cloud_close_endpoint(ctx->cloud_ep);
  memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  cloud_store_initialize(&ctx->store);
  cloud_manager_stop(ctx);
  if (data->auth_provider && data->auth_provider_len) {
    cloud_set_string(&ctx->store.auth_provider, data->auth_provider,
                     data->auth_provider_len);
  }
  if (data->access_token && data->access_token_len) {
    cloud_set_string(&ctx->store.access_token, data->access_token,
                     data->access_token_len);
  }
  if (data->ci_server && data->ci_server_len) {
    cloud_set_string(&ctx->store.ci_server, data->ci_server,
                     data->ci_server_len);
  }
  if (data->sid && data->sid_len) {
    cloud_set_string(&ctx->store.sid, data->sid, data->sid_len);
  }
  ctx->store.status = OC_CLOUD_INITIALIZED;
  ctx->cps = OC_CPS_READYTOREGISTER;
  if (ctx->cloud_manager) {
    cloud_reconnect(ctx);
  }
}

#ifdef OC_SESSION_EVENTS
static void
cloud_ep_session_event_handler(const oc_endpoint_t *endpoint,
                               oc_session_state_t state)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(endpoint->device);
  if (ctx && oc_endpoint_compare(endpoint, ctx->cloud_ep) == 0) {
    OC_DBG("[CM] cloud_ep_session_event_handler ep_state: %d\n", (int)state);
    ctx->cloud_ep_state = state;
    if (ctx->cloud_ep_state == OC_SESSION_DISCONNECTED && ctx->cloud_manager) {
      cloud_manager_restart(ctx);
    }
  }
}
#endif /* OC_SESSION_EVENTS */

static void
cloud_interface_event_handler(oc_interface_event_t event)
{
  if (event == NETWORK_INTERFACE_UP) {
    for (oc_cloud_context_t *ctx = oc_list_head(cloud_context_list); ctx;
         ctx = ctx->next) {
      switch (ctx->store.status) {
      case OC_CLOUD_INITIALIZED:
        cloud_manager_restart(ctx);
      }
    }
  }
}

oc_cloud_context_t *
oc_cloud_get_context(size_t device)
{
  oc_cloud_context_t *ctx = oc_list_head(cloud_context_list);
  while (ctx != NULL && ctx->device != device) {
    ctx = ctx->next;
  }
  return ctx;
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
cloud_reconnect(oc_cloud_context_t *ctx)
{
  OC_DBG("[CM] cloud_reconnect\n");
#ifdef OC_SESSION_EVENTS
  if (ctx->cloud_ep_state == OC_SESSION_CONNECTED) {
    cloud_close_endpoint(ctx->cloud_ep);
    return;
  }
#endif /* OC_SESSION_EVENTS */
  oc_remove_delayed_callback(ctx, restart_manager);
  oc_set_delayed_callback(ctx, restart_manager, 0);
}

int
oc_cloud_manager_start(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  ctx->callback = cb;
  ctx->user_data = data;

  cloud_manager_start(ctx);
  ctx->cloud_manager = true;
#ifdef OC_SESSION_EVENTS
  oc_remove_session_event_callback(cloud_ep_session_event_handler);
  oc_remove_network_interface_event_callback(cloud_interface_event_handler);
  oc_add_session_event_callback(cloud_ep_session_event_handler);
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
  if (oc_list_length(cloud_context_list) == 0) {
    oc_remove_session_event_callback(cloud_ep_session_event_handler);
    oc_remove_network_interface_event_callback(cloud_interface_event_handler);
  }
#endif /* OC_SESSION_EVENTS */
  oc_remove_delayed_callback(ctx, restart_manager);
  oc_remove_delayed_callback(ctx, start_manager);
  cloud_rd_deinit(ctx);
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
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_cloud_context_t *ctx =
      (oc_cloud_context_t *)oc_memb_alloc(&cloud_context_pool);
    if (!ctx) {
      OC_ERR("insufficient memory to create cloud context");
      return -1;
    }
    ctx->next = NULL;
    ctx->device = device;
    ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
    ctx->cloud_ep = oc_new_endpoint();
    cloud_store_load(&ctx->store);

    oc_list_add(cloud_context_list, ctx);

    ctx->cloud_conf = oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, device);

    oc_cloud_add_resource(oc_core_get_resource_by_index(OCF_P, device));
    oc_cloud_add_resource(oc_core_get_resource_by_index(OCF_D, device));
  }
  return 0;
}

void
oc_cloud_shutdown(void)
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_cloud_context_t *ctx = oc_cloud_get_context(device);
    if (ctx) {
      cloud_rd_deinit(ctx);
      cloud_manager_stop(ctx);
      cloud_store_deinit(&ctx->store);
      cloud_close_endpoint(ctx->cloud_ep);
      oc_free_endpoint(ctx->cloud_ep);
      oc_list_remove(cloud_context_list, ctx);
      oc_memb_free(&cloud_context_pool, ctx);
      OC_DBG("cloud_shutdown for %d", (int)device);
    }
  }
}
#else  /* OC_CLOUD*/
typedef int dummy_declaration;
#endif /* !OC_CLOUD */
