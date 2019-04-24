/****************************************************************************
 *
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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "cloud.h"
#include "cloud_internal.h"
#include "oc_api.h"
#include "oc_collection.h"
#include "oc_core_res.h"
#include "oc_network_monitor.h"
#ifdef OC_SECURITY
#include "security/oc_tls.h"
#endif

OC_LIST(cloud_context_list);
OC_MEMB(cloud_context_pool, cloud_context_t, OC_MAX_NUM_DEVICES);

void cloud_manager_cb(cloud_context_t *ctx) {
  OC_DBG("cloud manager status changed %d", (int)ctx->store.status);
  cloud_rd_manager_status_changed(ctx);

  if (ctx->callback) {
    ctx->callback(ctx->store.status, ctx->user_data);
  }
}

void cloud_set_string(oc_string_t *dst, const char *data, size_t len) {
  if (oc_string(*dst)) {
    oc_free_string(dst);
  }
  if (data && len) {
    oc_new_string(dst, data, len);
  } else {
    memset(dst, 0, sizeof(*dst));
  }
}

static oc_event_callback_retval_t start_manager(void *user_data) {
  cloud_context_t *ctx = (cloud_context_t *)user_data;
  oc_free_endpoint(ctx->cloud_ep);
  ctx->cloud_ep = oc_new_endpoint();
  cloud_manager_start(ctx);
  return OC_EVENT_DONE;
}

static void cloud_manager_restart(cloud_context_t *ctx) {
  cloud_manager_stop(ctx);
  oc_remove_delayed_callback(ctx, start_manager);
  oc_set_delayed_callback(ctx, start_manager, 0);
}

static oc_event_callback_retval_t restart_manager(void *user_data) {
  cloud_context_t *ctx = (cloud_context_t *)user_data;
  cloud_manager_restart(ctx);
  return OC_EVENT_DONE;
}

void cloud_update_by_resource(cloud_context_t *ctx,
                              const cloud_conf_update_t *data) {
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
  ctx->store.status = CLOUD_INITIALIZED;
  cloud_reconnect(ctx);
}

#ifdef OC_SESSION_EVENTS
static void cloud_ep_session_event_handler(const oc_endpoint_t *endpoint,
                                           oc_session_state_t state) {
  cloud_context_t *ctx = cloud_find_context(endpoint->device);
  if (ctx) {
    OC_DBG("[CM] cloud_ep_session_event_handler ep_state: %d\n", (int)state);
    ctx->cloud_ep_state = state;
    if (ctx->cloud_ep_state == OC_SESSION_DISCONNECTED) {
      cloud_manager_restart(ctx);
    }
  }
}
#endif /* OC_SESSION_EVENTS */

static void cloud_interface_event_handler(oc_interface_event_t event) {
  if (event == NETWORK_INTERFACE_UP) {
    for (cloud_context_t *ctx = oc_list_head(cloud_context_list); ctx;
         ctx = ctx->next) {
      switch (ctx->store.status) {
      case CLOUD_RECONNECTING:
      case CLOUD_INITIALIZED:
        cloud_manager_restart(ctx);
      }
    }
  }
}

int cloud_init(size_t device_index, cloud_cb_t callback, void *user_data) {
  cloud_context_t *ctx = (cloud_context_t *)oc_memb_alloc(&cloud_context_pool);
  if (!ctx) {
    OC_WRN("insufficient memory to create new collection");
    return -1;
  }
  memset(ctx, 0, sizeof(*ctx));

  ctx->next = NULL;
  ctx->callback = callback;
  ctx->user_data = user_data;
  ctx->device_index = device_index;
  ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
  ctx->cloud_ep = oc_new_endpoint();
  cloud_store_load(&ctx->store);
  cloud_manager_start(ctx);

  oc_list_add(cloud_context_list, ctx);
  if (!cloud_resource_init(ctx)) {
    oc_memb_free(&cloud_context_pool, ctx);
    return -1;
  }

#ifdef OC_SESSION_EVENTS
  if (oc_list_length(cloud_context_list) == 1) {
    oc_add_session_event_callback(cloud_ep_session_event_handler);
    oc_add_network_interface_event_callback(cloud_interface_event_handler);
  }
#endif /* OC_SESSION_EVENTS */

  cloud_rd_publish(oc_core_get_resource_by_index(OCF_P, device_index));
  cloud_rd_publish(oc_core_get_resource_by_index(OCF_D, device_index));
  cloud_rd_publish(ctx->cloud_conf);

  return 0;
}

cloud_context_t *cloud_find_context(size_t device_index) {
  cloud_context_t *ctx = oc_list_head(cloud_context_list);
  while (ctx != NULL && ctx->device_index != device_index) {
    ctx = ctx->next;
  }
  return ctx;
}

static void cloud_close_endpoint(oc_endpoint_t *cloud_ep) {
  OC_DBG("[CM] cloud_close_endpoint\n");
#ifdef OC_SESSION_EVENTS
#ifdef OC_SECURITY
  oc_tls_peer_t *peer = oc_tls_get_peer(cloud_ep);
  if (peer) {
    OC_DBG("[CM] cloud_close_endpoint: oc_tls_close_connection\n");
    oc_tls_close_connection(cloud_ep);
  } else
#endif /* OC_SECURITY */
  {
#ifdef OC_TCP
    OC_DBG("[CM] cloud_close_endpoint: oc_connectivity_end_session\n");
    oc_connectivity_end_session(cloud_ep);
#endif /* OC_TCP */
  }
#endif /* OC_SESSION_EVENTS */
}

void cloud_shutdown(size_t device_index) {
  cloud_context_t *ctx = cloud_find_context(device_index);
  if (!ctx) {
    return;
  }
  oc_list_remove(cloud_context_list, ctx);

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
  oc_delete_resource(ctx->cloud_conf);
  cloud_store_deinit(&ctx->store);

  cloud_close_endpoint(ctx->cloud_ep);
  oc_free_endpoint(ctx->cloud_ep);

  oc_memb_free(&cloud_context_pool, ctx);

  OC_DBG("cloud_shutdown for %d", (int)device_index);
}

void cloud_set_last_error(cloud_context_t *ctx, cloud_error_t error) {
  if (error != ctx->last_error) {
    ctx->last_error = error;
    oc_notify_observers(ctx->cloud_conf);
  }
}

void cloud_reconnect(cloud_context_t *ctx) {
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