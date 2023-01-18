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

#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_cloud.h"
#include "oc_cloud_access_internal.h"
#include "oc_cloud_internal.h"
#include "oc_core_res.h"
#include "rd_client.h"
#include "port/oc_log.h"
#ifdef OC_SECURITY
#include "security/oc_tls.h"
#endif /* OC_SECURITY */

#include <assert.h>

OC_MEMB(api_params, cloud_api_param_t, 1);

cloud_api_param_t *
alloc_api_param(void)
{
  return (cloud_api_param_t *)oc_memb_alloc(&api_params);
}

void
free_api_param(cloud_api_param_t *p)
{
  oc_memb_free(&api_params, p);
}

int
conv_cloud_endpoint(oc_cloud_context_t *ctx)
{
  int ret = 0;
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(oc_endpoint_t));
  if (ctx->cloud_ep && memcmp(&ep, ctx->cloud_ep, sizeof(oc_endpoint_t)) == 0) {
    ret = oc_string_to_endpoint(&ctx->store.ci_server, ctx->cloud_ep, NULL);
#ifdef OC_DNS_CACHE
    oc_dns_clear_cache();
#endif /* OC_DNS_CACHE */
  }
  return ret;
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

int
oc_cloud_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL || cb == NULL) {
    return -1;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    cb(ctx, ctx->store.status, data);
    return 0;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p == NULL) {
    OC_ERR("cannot allocate cloud parameters");
    return -1;
  }
  p->ctx = ctx;
  p->cb = cb;
  p->data = data;

  if (ctx->store.status != OC_CLOUD_INITIALIZED) {
    OC_ERR("invalid cloud status(%d)", (int)ctx->store.status);
    free_api_param(p);
    return -1;
  }

  OC_DBG("try register device %zu\n", ctx->device);
  if (oc_string(ctx->store.ci_server) == NULL ||
      conv_cloud_endpoint(ctx) != 0) {
    cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
    free_api_param(p);
    return -1;
  }

  oc_cloud_access_conf_t conf = {
    .endpoint = ctx->cloud_ep,
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = oc_cloud_register_handler,
    .user_data = p,
    .timeout = 0,
  };
  if (cloud_access_register(conf, oc_string(ctx->store.auth_provider), NULL,
                            oc_string(ctx->store.uid),
                            oc_string(ctx->store.access_token))) {
    ctx->store.cps = OC_CPS_REGISTERING;
    return 0;
  }

  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  free_api_param(p);
  return -1;
}

int
oc_cloud_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL || cb == NULL) {
    return -1;
  }

  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) != 0) {
    cb(ctx, ctx->store.status, data);
    return 0;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p == NULL) {
    OC_ERR("cannot allocate cloud parameters");
    return -1;
  }
  p->ctx = ctx;
  p->cb = cb;
  p->data = data;

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    OC_ERR("invalid cloud status(%d)", (int)ctx->store.status);
    free_api_param(p);
    return -1;
  }

  OC_DBG("try login device %zu\n", ctx->device);
  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = oc_cloud_login_handler,
    .user_data = p,
  };
  if (conv_cloud_endpoint(ctx) != 0) {
    goto error;
  }
  conf.endpoint = ctx->cloud_ep;

  if (cloud_access_login(conf, oc_string(ctx->store.uid),
                         oc_string(ctx->store.access_token))) {
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  free_api_param(p);
  return -1;
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
  if (data->code >= OC_STATUS_SERVICE_UNAVAILABLE) {
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
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_LOGGED_OUT);
}

int
oc_cloud_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (ctx == NULL || cb == NULL) {
    return -1;
  }

  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    OC_ERR("invalid cloud status(%d)", (int)ctx->store.status);
    return -1;
  }
  cloud_api_param_t *p = alloc_api_param();
  if (p == NULL) {
    OC_ERR("cannot allocate cloud parameters");
    return -1;
  }
  p->ctx = ctx;
  p->cb = cb;
  p->data = data;

  OC_DBG("try logout device %zu", ctx->device);
  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_logout_internal,
    .user_data = p,
  };
  if (conv_cloud_endpoint(ctx) != 0) {
    goto error;
  }
  conf.endpoint = ctx->cloud_ep;
  if (cloud_access_logout(conf, oc_string(ctx->store.uid),
                          oc_string(ctx->store.access_token))) {
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  free_api_param(p);
  return -1;
}

static void
cloud_deregistered_internal(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  if (data->code < OC_STATUS_BAD_REQUEST ||
      data->code >= OC_STATUS_SERVICE_UNAVAILABLE) {
    ctx->store.status = OC_CLOUD_DEREGISTERED;
  } else if (data->code >= OC_STATUS_BAD_REQUEST) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
    ctx->store.status |= OC_CLOUD_FAILURE;
  }

  ctx->store.cps = OC_CPS_UNINITIALIZED;

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_DEREGISTERED);

  cloud_store_dump_async(&ctx->store);
}

static bool
check_accesstoken_for_deregister(oc_cloud_context_t *ctx)
{
// This value is calculated by coap_oscore_serialize_message for deregister
// message with empty query parameters. The value should remain the same
// unless some global options are added to coap requests.
// The deregister request won't be sent if the total size of its header is
// greater than COAP_MAX_HEADER_SIZE, so we must ensure that the query
// is not too large.
// Some older cloud implementations require tokens in deregister requests.
// To facilitate support for such implementations we append access token
// to the request query if the resulting query size is within the limit.
#define DEREGISTER_EMPTY_QUERY_HEADER_SIZE 38

  oc_string_t query = cloud_access_deregister_query(
    oc_string(ctx->store.uid), oc_string(ctx->store.access_token), ctx->device);
  size_t query_size = oc_string_len(query);
  oc_free_string(&query);

  return DEREGISTER_EMPTY_QUERY_HEADER_SIZE + query_size <=
         COAP_MAX_HEADER_SIZE;
}

static int
cloud_deregister(cloud_api_param_t *p, bool useAccessToken)
{
  assert(p != NULL);

  oc_cloud_context_t *ctx = p->ctx;
  OC_DBG("try deregister device %zu\n", ctx->device);
  cloud_set_cps(ctx, OC_CPS_DEREGISTERING);

  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_deregistered_internal,
    .user_data = p,
  };
  if (oc_string(ctx->store.ci_server) == NULL ||
      conv_cloud_endpoint(ctx) != 0) {
    goto error;
  }
  conf.endpoint = ctx->cloud_ep;

  if (cloud_access_deregister(
        conf, oc_string(ctx->store.uid),
        useAccessToken ? oc_string(ctx->store.access_token) : NULL)) {
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  free_api_param(p);
  return -1;
}

static void
cloud_login_for_deregister(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                           void *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data;

  if ((status & OC_CLOUD_LOGGED_IN) == 0) {
    OC_ERR("Failed to login to cloud for deregister");
    free_api_param(p);
    oc_cloud_clear_context(ctx);
    return;
  }

  if (cloud_deregister(p, false) != 0) {
    OC_ERR("Failed to deregister from cloud");
    oc_cloud_clear_context(ctx);
  }
}

static void
cloud_refresh_token_for_deregister(oc_cloud_context_t *ctx,
                                   oc_cloud_status_t status, void *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data;

  if ((status & OC_CLOUD_REFRESHED_TOKEN) == 0) {
    OC_ERR("Failed to refresh access token for deregister");
    free_api_param(p);
    oc_cloud_clear_context(ctx);
    return;
  }

  // short access token -> we can use it in query and deregister without
  // login
  if (check_accesstoken_for_deregister(ctx)) {
    if (cloud_deregister(p, true) != 0) {
      OC_ERR("Failed to deregister from cloud");
      oc_cloud_clear_context(ctx);
    }
    return;
  }

  // long access token -> we must login and then deregister without token
  if (oc_cloud_login(ctx, cloud_login_for_deregister, p) != 0) {
    OC_ERR("Failed to login to cloud for deregister");
    free_api_param(p);
    oc_cloud_clear_context(ctx);
    return;
  }
}

int
oc_cloud_deregister(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  if (!(ctx->store.status & OC_CLOUD_REGISTERED)) {
    return -1;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p == NULL) {
    OC_ERR("cannot allocate cloud parameters");
    return -1;
  }
  p->ctx = ctx;
  p->cb = cb;
  p->data = data;

  bool canUseAccessToken = check_accesstoken_for_deregister(ctx);
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    bool hasRefreshToken =
      cloud_has_refresh_token(ctx) && !cloud_has_permanent_access_token(ctx);
    if (hasRefreshToken) {
      if (oc_cloud_refresh_token(ctx, cloud_refresh_token_for_deregister, p) !=
          0) {
        OC_ERR("Failed to refresh token for deregister");
        free_api_param(p);
        return -1;
      }
      return 0;
    }

    if (canUseAccessToken) {
      // short access token -> we can use it in query and deregister without
      // login
      return cloud_deregister(p, true);
    }

    // long access token -> we must login and then deregister without token
    if (oc_cloud_login(ctx, cloud_login_for_deregister, p) != 0) {
      OC_ERR("Failed to login to cloud for deregister");
      free_api_param(p);
      return -1;
    }
    return 0;
  }

  return cloud_deregister(p, canUseAccessToken);
}

int
oc_cloud_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  if (!(ctx->store.status & OC_CLOUD_REGISTERED)) {
    return -1;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p == NULL) {
    OC_ERR("cannot allocate cloud parameters");
    return -1;
  }
  p->ctx = ctx;
  p->cb = cb;
  p->data = data;

  OC_DBG("try refresh token for device %zu\n", ctx->device);
  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = oc_cloud_refresh_token_handler,
    .user_data = p,
  };
  if (conv_cloud_endpoint(ctx) != 0) {
    goto error;
  }
  conf.endpoint = ctx->cloud_ep;
  if (cloud_access_refresh_access_token(conf, oc_string(ctx->store.uid),
                                        oc_string(ctx->store.refresh_token))) {
    return 0;
  }

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
  free_api_param(p);
  return -1;
}

int
oc_cloud_discover_resources(oc_cloud_context_t *ctx,
                            oc_discovery_all_handler_t handler, void *user_data)
{
  if (!ctx) {
    return -1;
  }

  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN)) {
    return -1;
  }

  if (oc_do_ip_discovery_all_at_endpoint(handler, ctx->cloud_ep, user_data)) {
    return 0;
  }

  return -1;
}

bool
cloud_send_ping(oc_endpoint_t *endpoint, uint16_t timeout_seconds,
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

#endif /* OC_CLOUD */
