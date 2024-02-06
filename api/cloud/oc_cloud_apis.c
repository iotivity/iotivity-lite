/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "api/cloud/oc_cloud_apis_internal.h"
#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_deregister_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/cloud/oc_cloud_log_internal.h"
#include "api/cloud/oc_cloud_manager_internal.h"
#include "api/cloud/oc_cloud_store_internal.h"
#include "api/oc_endpoint_internal.h"
#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_cloud.h"
#include "oc_cloud_access.h"
#include "oc_core_res.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "rd_client_internal.h"

#ifdef OC_SECURITY
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#include <assert.h>

// oc_cloud_do_deregister might invoke oc_cloud_do_refresh_token or
// oc_cloud_do_login so we might have 2 concurrent allocations per device
OC_MEMB(g_api_params, cloud_api_param_t, OC_MAX_NUM_DEVICES * 2);

cloud_api_param_t *
oc_cloud_api_new_param(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                       uint16_t timeout)
{
  cloud_api_param_t *ap = oc_memb_alloc(&g_api_params);
  if (ap == NULL) {
    return NULL;
  }
  ap->ctx = ctx;
  ap->cb = cb;
  ap->data = data;
  ap->timeout = timeout;
  return ap;
}

void
oc_cloud_api_free_param(cloud_api_param_t *p)
{
  oc_memb_free(&g_api_params, p);
}

#ifdef OC_SECURITY

static bool
cloud_tls_connected(const oc_endpoint_t *endpoint)
{
  const oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  return (peer != NULL && peer->role == MBEDTLS_SSL_IS_CLIENT &&
          peer->ssl_ctx.state == MBEDTLS_SSL_HANDSHAKE_OVER);
}

#endif /* OC_SECURITY */

bool
oc_cloud_set_access_conf(oc_cloud_context_t *ctx, oc_response_handler_t handler,
                         void *user_data, uint16_t timeout,
                         oc_cloud_access_conf_t *conf)
{
  if (!oc_cloud_set_endpoint(ctx)) {
    OC_CLOUD_ERR("invalid cloud server");
    return false;
  }

  *conf = (oc_cloud_access_conf_t){
    .endpoint = ctx->cloud_ep,
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = handler,
    .user_data = user_data,
    .timeout = timeout,
  };
  return true;
}

int
oc_cloud_do_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                     uint16_t timeout)
{
  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    cb(ctx, ctx->store.status, data);
    return 0;
  }

  if (ctx->store.status != OC_CLOUD_INITIALIZED) {
    OC_CLOUD_ERR("invalid cloud status(%d)", (int)ctx->store.status);
    return -1;
  }

  cloud_api_param_t *p = oc_cloud_api_new_param(ctx, cb, data, timeout);
  if (p == NULL) {
    OC_CLOUD_ERR("cannot allocate cloud parameters");
    return -1;
  }

  OC_CLOUD_DBG("try register device %zu", ctx->device);
  oc_cloud_access_conf_t conf;
  if (!oc_cloud_set_access_conf(ctx, oc_cloud_register_handler, p, timeout,
                                &conf)) {
    goto error;
  }
  if (oc_cloud_access_register(conf, oc_string(ctx->store.auth_provider), NULL,
                               oc_string(ctx->store.uid),
                               oc_string(ctx->store.access_token))) {
    ctx->store.cps = OC_CPS_REGISTERING;
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  oc_cloud_api_free_param(p);
  return -1;
}

int
oc_cloud_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL || cb == NULL) {
    return -1;
  }
  return oc_cloud_do_register(ctx, cb, data, /*timeout*/ 0);
}

int
oc_cloud_do_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                  uint16_t timeout)
{
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) != 0) {
    cb(ctx, ctx->store.status, data);
    return 0;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    OC_CLOUD_ERR("invalid cloud status(%d)", (int)ctx->store.status);
    return -1;
  }

  cloud_api_param_t *p = oc_cloud_api_new_param(ctx, cb, data, timeout);
  if (p == NULL) {
    OC_CLOUD_ERR("cannot allocate cloud parameters");
    return -1;
  }

  OC_CLOUD_DBG("try login device %zu", ctx->device);
  oc_cloud_access_conf_t conf;
  if (!oc_cloud_set_access_conf(ctx, oc_cloud_login_handler, p, timeout,
                                &conf)) {
    goto error;
  }
  if (oc_cloud_access_login(conf, oc_string(ctx->store.uid),
                            oc_string(ctx->store.access_token))) {
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  oc_cloud_api_free_param(p);
  return -1;
}

int
oc_cloud_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL || cb == NULL) {
    return -1;
  }
  return oc_cloud_do_login(ctx, cb, data, /*timeout*/ 0);
}

int
oc_cloud_get_token_expiry(const oc_cloud_context_t *ctx)
{
  return (int)ctx->store.expires_in;
}

void
oc_cloud_set_published_resources_ttl(oc_cloud_context_t *ctx, uint32_t ttl)
{
  ctx->time_to_live = ttl;
}

static void
cloud_logout_internal(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  if (cloud_is_connection_error_code(data->code)) {
    cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
    ctx->store.status |= OC_CLOUD_FAILURE;
  } else if (data->code >= OC_STATUS_BAD_REQUEST) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
    ctx->store.status |= OC_CLOUD_FAILURE;
  } else {
    ctx->store.status &= ~OC_CLOUD_LOGGED_IN;
    ctx->store.status |= OC_CLOUD_LOGGED_OUT;
  }

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  oc_cloud_api_free_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_LOGGED_OUT);
}

int
oc_cloud_do_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                   uint16_t timeout)
{
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    OC_CLOUD_ERR("invalid cloud status(%d)", (int)ctx->store.status);
    return -1;
  }
  cloud_api_param_t *p = oc_cloud_api_new_param(ctx, cb, data, timeout);
  if (p == NULL) {
    OC_CLOUD_ERR("cannot allocate cloud parameters");
    return -1;
  }

  OC_CLOUD_DBG("try logout device %zu", ctx->device);
  oc_cloud_access_conf_t conf;
  if (!oc_cloud_set_access_conf(ctx, cloud_logout_internal, p, timeout,
                                &conf)) {
    goto error;
  }
  if (oc_cloud_access_logout(conf, oc_string(ctx->store.uid),
                             oc_string(ctx->store.access_token))) {
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  oc_cloud_api_free_param(p);
  return -1;
}

int
oc_cloud_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL || cb == NULL) {
    return -1;
  }
  return oc_cloud_do_logout(ctx, cb, data, /*timeout*/ 0);
}

int
oc_cloud_deregister(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }
  return oc_cloud_do_deregister(ctx, /*sync*/ true, /*timeout*/ 0, cb, data);
}

int
oc_cloud_do_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                          uint16_t timeout)
{
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    return -1;
  }

  cloud_api_param_t *p = oc_cloud_api_new_param(ctx, cb, data, timeout);
  if (p == NULL) {
    OC_CLOUD_ERR("cannot allocate cloud parameters");
    return -1;
  }

  OC_CLOUD_DBG("try refresh token for device %zu", ctx->device);
  if (!oc_cloud_set_endpoint(ctx)) {
    goto error;
  }
  oc_cloud_access_conf_t conf = {
    .endpoint = ctx->cloud_ep,
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = oc_cloud_refresh_token_handler,
    .user_data = p,
    .timeout = timeout,
  };
  if (oc_cloud_access_refresh_access_token(
        conf, oc_string(ctx->store.auth_provider), oc_string(ctx->store.uid),
        oc_string(ctx->store.refresh_token))) {
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
  oc_cloud_api_free_param(p);
  return -1;
}

int
oc_cloud_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }
  return oc_cloud_do_refresh_token(ctx, cb, data, 0);
}

int
oc_cloud_discover_resources(const oc_cloud_context_t *ctx,
                            oc_discovery_all_handler_t handler, void *user_data)
{
  if (ctx == NULL || (ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    return -1;
  }
  if (oc_do_ip_discovery_all_at_endpoint(handler, ctx->cloud_ep, user_data)) {
    return 0;
  }
  return -1;
}

bool
cloud_send_ping(const oc_endpoint_t *endpoint, uint16_t timeout_seconds,
                oc_response_handler_t handler, void *user_data)
{
#ifdef OC_SECURITY
  if (!cloud_tls_connected(endpoint)) {
    return false;
  }
#endif /* OC_SECURITY */
#ifdef OC_TCP
  if (endpoint->flags & TCP) {
    return oc_send_ping(false, endpoint, timeout_seconds, handler, user_data);
  }
#endif /* OC_TCP */
  return oc_do_get_with_timeout(OC_RSRVD_RD_URI, endpoint, NULL,
                                timeout_seconds, handler, LOW_QOS, user_data);
}

const char *
oc_cloud_action_to_str(oc_cloud_action_t action)
{
  switch (action) {
  case OC_CLOUD_ACTION_REGISTER:
    return OC_CLOUD_ACTION_REGISTER_STR;
  case OC_CLOUD_ACTION_LOGIN:
    return OC_CLOUD_ACTION_LOGIN_STR;
  case OC_CLOUD_ACTION_REFRESH_TOKEN:
    return OC_CLOUD_ACTION_REFRESH_TOKEN_STR;
  default:
    return OC_CLOUD_ACTION_UNKNOWN_STR;
  }
}

#endif /* OC_CLOUD */
