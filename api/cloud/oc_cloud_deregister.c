/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
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
#include "oc_cloud_internal.h"
#include "oc_cloud_access_internal.h"
#include "oc_cloud_context_internal.h"
#include "oc_cloud_deregister_internal.h"
#include "oc_cloud_manager_internal.h"
#include "oc_cloud_store_internal.h"

#ifdef OC_SECURITY

static void
cloud_deregister_on_reset_handler(oc_cloud_context_t *ctx,
                                  oc_cloud_status_t status, void *data)
{
  (void)status;
  (void)data;
  OC_DBG("[Cloud] cloud_deregister_on_reset_handler device=%zu", ctx->device);
  cloud_context_clear(ctx);
}

static oc_event_callback_retval_t
cloud_deregister_context_clear_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  cloud_context_clear(ctx);
  return OC_EVENT_DONE;
}

static void
cloud_deregister_on_reset_async_handler(oc_cloud_context_t *ctx,
                                        oc_cloud_status_t status, void *data)
{
  (void)status;
  (void)data;
  OC_DBG("[Cloud] cloud_deregister_on_reset_async_handler device=%zu",
         ctx->device);
  // this call might be invoked because of timeout (delayed call of
  // oc_ri_remove_client_cb_with_notify_503 when the request is fired), however
  // cloud_context_clear among other things closes the connected endpoint. This
  // also invokes oc_ri_remove_client_cb_with_notify_503 for this call,
  // causing memory issues. We schedule the context clear in a delayed callback,
  // so this call removes itself from the queue of calls for the endpoint.
  cloud_reset_delayed_callback(ctx, cloud_deregister_context_clear_async, 0);
}

static int
cloud_deregister_on_reset_sync(oc_cloud_context_t *ctx, bool sync,
                               uint16_t timeout)
{
  OC_DBG("[Cloud] cloud deregister on reset");
  oc_cloud_cb_t handler = sync ? &cloud_deregister_on_reset_handler
                               : &cloud_deregister_on_reset_async_handler;
  int err = cloud_deregister(ctx, sync, timeout, handler, ctx);
  if (err == 0 || err == CLOUD_DEREGISTER_ERROR_ALREADY_DEREGISTERING) {
    return 0;
  }
  return -1;
}

static oc_event_callback_retval_t
cloud_deregister_on_reset_async(void *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data;
  oc_cloud_context_t *ctx = p->ctx;
  uint16_t timeout = p->timeout;
  free_api_param(p);
  if (cloud_deregister_on_reset_sync(ctx, /*sync*/ false, timeout) != 0) {
    OC_ERR("[Cloud] failed to deregister from cloud");
    cloud_context_clear(ctx);
  }
  return OC_EVENT_DONE;
}

bool
cloud_deregister_on_reset(oc_cloud_context_t *ctx, bool sync, uint16_t timeout)
{
  cloud_manager_stop(ctx);
  if (sync) {
    return cloud_deregister_on_reset_sync(ctx, true, 0) == 0;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p == NULL) {
    OC_ERR("[Cloud] cannot allocate cloud parameters for reset");
    return false;
  }
  p->ctx = ctx;
  p->timeout = timeout;
  cloud_reset_delayed_callback(p, cloud_deregister_on_reset_async, 0);
  return true;
}

#endif /* OC_SECURITY */

static void
cloud_deregistered_internal(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  OC_DBG("Cloud deregister: deregistered for device=%zu", ctx->device);

  if (data->code < OC_STATUS_BAD_REQUEST ||
      cloud_is_connection_error_code(data->code)) {
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
cloud_deregister_by_request(cloud_api_param_t *p, uint16_t timeout,
                            bool useAccessToken)
{
  assert(p != NULL);

  oc_cloud_context_t *ctx = p->ctx;
  OC_DBG("try deregister device %zu by DELETE request", ctx->device);
  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_deregistered_internal,
    .user_data = p,
    .timeout = timeout,
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
  return -1;
}

static void
cloud_deregister_try_logged_in(oc_cloud_context_t *ctx,
                               oc_cloud_status_t status, void *data)
{
  OC_DBG("Cloud deregister: logged in for device=%zu", ctx->device);
  cloud_api_param_t *p = (cloud_api_param_t *)data;

  if ((status & OC_CLOUD_LOGGED_IN) == 0) {
    OC_ERR("Failed to login to cloud for deregister");
    free_api_param(p);
    cloud_context_clear(ctx);
    return;
  }

  if (cloud_deregister_by_request(p, p->timeout, false) != 0) {
    OC_ERR("Failed to deregister from cloud");
    free_api_param(p);
    cloud_context_clear(ctx);
    return;
  }
}

static oc_event_callback_retval_t
cloud_deregister_refreshed_token_async(void *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data;
  // short access token -> we can use it in query and deregister without login
  if (check_accesstoken_for_deregister(p->ctx)) {
    if (cloud_deregister_by_request(p, p->timeout, true) != 0) {
      OC_ERR("Failed to deregister from cloud");
      free_api_param(p);
      cloud_context_clear(p->ctx);
    }
    return OC_EVENT_DONE;
  }

  // long access token -> we must login and then deregister without token
  if (cloud_login(p->ctx, cloud_deregister_try_logged_in, p, p->timeout) != 0) {
    OC_ERR("Failed to login to cloud for deregister");
    free_api_param(p);
    cloud_context_clear(p->ctx);
    return OC_EVENT_DONE;
  }
  return OC_EVENT_DONE;
}

static void
cloud_deregister_try_refreshed_token(oc_cloud_context_t *ctx,
                                     oc_cloud_status_t status, void *data)
{
  OC_DBG("Cloud deregister: refreshed token for device=%zu", ctx->device);
  cloud_api_param_t *p = (cloud_api_param_t *)data;
  if ((status & OC_CLOUD_REFRESHED_TOKEN) == 0) {
    OC_ERR("Failed to refresh access token for deregister");
    free_api_param(p);
    cloud_context_clear(ctx);
    return;
  }

  // invoke in a delayed callback so, the cloud_api_param_t* structure allocated
  // by cloud_deregister is deallocated before new one is allocated
  oc_set_delayed_callback(p, cloud_deregister_refreshed_token_async, 0);
}

int
cloud_deregister(oc_cloud_context_t *ctx, bool sync, uint16_t timeout,
                 oc_cloud_cb_t cb, void *data)
{
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    OC_ERR("invalid cloud status(%d) for deregister", (int)ctx->store.status);
    return -1;
  }

  if (cloud_is_deregistering(ctx)) {
    OC_DBG("Device(%zu) is already deregistering, skipped", ctx->device);
    return CLOUD_DEREGISTER_ERROR_ALREADY_DEREGISTERING;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p == NULL) {
    OC_ERR("cannot allocate cloud parameters");
    return -1;
  }
  p->ctx = ctx;
  p->cb = cb;
  p->data = data;
  p->timeout = timeout;

  OC_DBG("Deregistering of device=%zu started", ctx->device);
  cloud_set_cps(ctx, OC_CPS_DEREGISTERING);

  bool canUseAccessToken = check_accesstoken_for_deregister(ctx);
  bool isLoggedIn = (ctx->store.status & OC_CLOUD_LOGGED_IN) != 0;
  // either we have a short access token or we are already logged in, so we can
  // execute deregister
  if (canUseAccessToken || isLoggedIn) {
    if (cloud_deregister_by_request(p, p->timeout, canUseAccessToken) != 0) {
      OC_ERR("Failed to deregister from cloud");
      free_api_param(p);
      return -1;
    }
    return 0;
  }

  if (sync) {
    OC_ERR("Asynchronous deregister from cloud not allowed");
    free_api_param(p);
    return -1;
  }

  // otherwise we must log in, try first with an refresh token if we have it
  bool hasRefreshToken = cloud_context_has_refresh_token(ctx) &&
                         !cloud_context_has_permanent_access_token(ctx);
  if (hasRefreshToken) {
    if (cloud_refresh_token(ctx, cloud_deregister_try_refreshed_token, p,
                            timeout) != 0) {
      OC_ERR("Failed to refresh token for deregister");
      free_api_param(p);
      return -1;
    }
    return 0;
  }

  // otherwise try full log in
  if (cloud_login(ctx, cloud_deregister_try_logged_in, p, timeout) != 0) {
    OC_ERR("Failed to login to cloud for deregister");
    free_api_param(p);
    return -1;
  }
  return 0;
}

static bool
cloud_match_context(const void *cb_data, const void *filter_data)
{
  const cloud_api_param_t *p = (const cloud_api_param_t *)cb_data;
  const oc_cloud_context_t *ctx = (const oc_cloud_context_t *)filter_data;
  return p->ctx == ctx;
}

static void
cloud_free_api_param(void *cb_data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)cb_data;
  free_api_param(p);
}

void
cloud_deregister_stop(oc_cloud_context_t *ctx)
{
  oc_remove_delayed_callback_by_filter(cloud_deregister_refreshed_token_async,
                                       cloud_match_context, ctx, true,
                                       cloud_free_api_param);
#ifdef OC_SECURITY
  oc_remove_delayed_callback(ctx, cloud_deregister_context_clear_async);
  oc_remove_delayed_callback_by_filter(cloud_deregister_on_reset_async,
                                       cloud_match_context, ctx, true,
                                       cloud_free_api_param);
#endif /* OC_SECURITY */
}

#endif /* OC_CLOUD */
