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
#include "oc_cloud_access_internal.h"
#include "oc_cloud_context_internal.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_manager_internal.h"
#include "oc_cloud_store_internal.h"
#include "oc_endpoint.h"
#include "port/oc_log.h"
#include "rd_client.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#include "security/oc_tls.h"
#endif /* OC_SECURITY */
#include <assert.h>
#include <stdint.h>

static void cloud_start_process(oc_cloud_context_t *ctx);
static oc_event_callback_retval_t cloud_manager_reconnect_async(void *data);
static oc_event_callback_retval_t cloud_manager_register_async(void *data);
static oc_event_callback_retval_t cloud_manager_login_async(void *data);
static oc_event_callback_retval_t cloud_manager_refresh_token_async(void *data);
static oc_event_callback_retval_t cloud_manager_send_ping_async(void *data);

static uint8_t g_retry_timeout[MAX_RETRY_COUNT] = { 2, 4, 8, 16, 32, 64 };

bool
cloud_manager_set_retry(const uint8_t retry_timeout[],
                        size_t retry_timeout_size)
{
  if (retry_timeout == NULL || retry_timeout_size == 0 ||
      retry_timeout_size > MAX_RETRY_COUNT) {
    return false;
  }

  for (size_t i = 0; i < retry_timeout_size; ++i) {
    if (retry_timeout[i] == 0) {
      return false;
    }
  }

  memset(&g_retry_timeout, 0, sizeof(g_retry_timeout[0]) * MAX_RETRY_COUNT);
  memcpy(&g_retry_timeout, retry_timeout,
         sizeof(retry_timeout[0]) * retry_timeout_size);
  return true;
}

size_t
cloud_manager_get_retry(uint8_t *buffer, size_t buffer_size)
{
  assert(buffer != NULL);

  size_t cfg_size = 0;
  for (size_t i = 0; i < MAX_RETRY_COUNT; ++i) {
    if (g_retry_timeout[i] == 0) {
      break;
    }
    ++cfg_size;
  }

  if (buffer_size < cfg_size) {
    return (size_t)-1;
  }

  if (cfg_size > 0) {
    memcpy(buffer, &g_retry_timeout[0], sizeof(g_retry_timeout[0]) * cfg_size);
  }
  return cfg_size;
}

static oc_event_callback_retval_t
cloud_manager_callback_handler_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  cloud_manager_cb(ctx);
  ctx->store.status &=
    ~(OC_CLOUD_FAILURE | OC_CLOUD_LOGGED_OUT | OC_CLOUD_REFRESHED_TOKEN |
      OC_CLOUD_TOKEN_EXPIRY | OC_CLOUD_DEREGISTERED);
  return OC_EVENT_DONE;
}

void
cloud_manager_start(oc_cloud_context_t *ctx)
{
  OC_DBG("[CM] cloud_manager_start");

  cloud_start_process(ctx);
}

void
cloud_manager_stop(oc_cloud_context_t *ctx)
{
  OC_DBG("[CM] cloud_manager_stop");
  oc_remove_delayed_callback(ctx, cloud_manager_reconnect_async);
  oc_remove_delayed_callback(ctx, cloud_manager_register_async);
  oc_remove_delayed_callback(ctx, cloud_manager_login_async);
  oc_remove_delayed_callback(ctx, cloud_manager_send_ping_async);
  oc_remove_delayed_callback(ctx, cloud_manager_refresh_token_async);
  oc_remove_delayed_callback(ctx, cloud_manager_callback_handler_async);
}

static oc_event_callback_retval_t
cloud_manager_reconnect_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  cloud_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
  oc_cloud_manager_restart(ctx);
  return OC_EVENT_DONE;
}

static bool
is_refresh_token_retry_over(const oc_cloud_context_t *ctx)
{
  return ctx->retry_refresh_token_count >= MAX_RETRY_COUNT ||
         g_retry_timeout[ctx->retry_refresh_token_count] == 0;
}

static bool
is_retry_over(const oc_cloud_context_t *ctx)
{
  return ctx->retry_count >= MAX_RETRY_COUNT ||
         g_retry_timeout[ctx->retry_count] == 0;
}

static void
cloud_start_process(oc_cloud_context_t *ctx)
{
  ctx->retry_count = 0;
  ctx->retry_refresh_token_count = 0;

#ifdef OC_SECURITY
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  if (pstat->s != OC_DOS_RFNOP && pstat->s != OC_DOS_RFPRO) {
    return;
  }
#endif

  if (ctx->store.status == OC_CLOUD_INITIALIZED &&
      ctx->store.cps == OC_CPS_READYTOREGISTER) {
    cloud_reset_delayed_callback(ctx, cloud_manager_register_async,
                                 g_retry_timeout[0]);
    goto finish;
  }
  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    if (cloud_context_has_permanent_access_token(ctx)) {
      cloud_reset_delayed_callback(ctx, cloud_manager_login_async,
                                   g_retry_timeout[0]);
      goto finish;
    }
    if (cloud_context_has_refresh_token(ctx)) {
      cloud_reset_delayed_callback(ctx, cloud_manager_refresh_token_async,
                                   g_retry_timeout[0]);
      goto finish;
    }
  }

finish:
  _oc_signal_event_loop();
}

static uint16_t
check_expires_in(int64_t expires_in)
{
  if (expires_in <= 0) {
    return 0;
  }
  if (expires_in > 60 * 60) {
    // if time is more than 1h then set expires to (expires_in - 10min).
    expires_in = expires_in - 10 * 60;
  } else if (expires_in > 4 * 60) {
    // if time is more than 240sec then set expires to (expires_in - 2min).
    expires_in = expires_in - 2 * 60;
  } else if (expires_in > 20) {
    // if time is more than 20sec then set expires to (expires_in - 10sec).
    expires_in = expires_in - 10;
  }
  return expires_in > UINT16_MAX ? UINT16_MAX : (uint16_t)expires_in;
}

static bool
cloud_is_connection_error_or_timeout(oc_status_t code)
{
  return cloud_is_timeout_error_code(code) ||
         cloud_is_connection_error_code(code);
}

static oc_cloud_error_t
_register_handler_check_data_error(const oc_client_response_t *data)
{
  if (cloud_is_connection_error_or_timeout(data->code)) {
    return CLOUD_ERROR_CONNECT;
  }
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    return CLOUD_ERROR_RESPONSE;
  }
  return CLOUD_OK;
}

bool
cloud_manager_handle_register_response(oc_cloud_context_t *ctx,
                                       const oc_rep_t *payload)
{
  assert(ctx != NULL);
  assert(payload != NULL);

  const char *access_token = NULL;
  size_t access_token_size = 0;
  if (!oc_rep_get_string(payload, ACCESS_TOKEN_KEY, (char **)&access_token,
                         &access_token_size) ||
      access_token_size == 0) {
    return false;
  }

  const char *refresh_token = NULL;
  size_t refresh_token_size = 0;
  if (!oc_rep_get_string(payload, REFRESH_TOKEN_KEY, (char **)&refresh_token,
                         &refresh_token_size) ||
      refresh_token_size == 0) {
    return false;
  }

  const char *uid = NULL;
  size_t uid_size = 0;
  if (!oc_rep_get_string(payload, USER_ID_KEY, (char **)&uid, &uid_size) ||
      uid_size == 0) {
    return false;
  }

  int64_t expires_in = 0;
  if (!oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in)) {
    return false;
  }

  cloud_set_string(&ctx->store.access_token, access_token, access_token_size);
  cloud_set_string(&ctx->store.refresh_token, refresh_token,
                   refresh_token_size);
  cloud_set_string(&ctx->store.uid, uid, uid_size);
  ctx->store.expires_in = expires_in;
  if (ctx->store.expires_in > 0) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
  }
  return true;
}

bool
cloud_manager_handle_redirect_response(oc_cloud_context_t *ctx,
                                       const oc_rep_t *payload)
{
  assert(ctx != NULL);
  assert(payload != NULL);

  char *value = NULL;
  size_t size = 0;
  if (oc_rep_get_string(payload, REDIRECTURI_KEY, &value, &size) && size > 0) {
    const char *ci_server = oc_string(ctx->store.ci_server);
    if ((ctx->cloud_ep != NULL) &&
        (ci_server == NULL || oc_string_len(ctx->store.ci_server) != size ||
         strcmp(ci_server, value) != 0)) {
      cloud_close_endpoint(ctx->cloud_ep);
      memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
      ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
    }
    cloud_set_string(&ctx->store.ci_server, value, size);
    return true;
  }

  return false;
}

static int
_register_handler(oc_cloud_context_t *ctx, const oc_client_response_t *data,
                  bool retryIsActive)
{
  oc_cloud_error_t err = _register_handler_check_data_error(data);
  if (err != CLOUD_OK) {
    goto error;
  }

  if (ctx->store.status != OC_CLOUD_INITIALIZED) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  const oc_rep_t *payload = data->payload;
  if (!cloud_manager_handle_register_response(ctx, payload)) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  if (cloud_manager_handle_redirect_response(ctx, payload)) {
    OC_DBG("redirect detected");
  }

  cloud_store_dump_async(&ctx->store);
  ctx->retry_count = 0;
  ctx->store.status |= OC_CLOUD_REGISTERED;

  cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERED, CLOUD_OK);

  return 0;

error:
  ctx->store.status |= OC_CLOUD_FAILURE;
  if (err == CLOUD_ERROR_CONNECT && retryIsActive && !is_retry_over(ctx)) {
    // While retrying, keep last error (clec) to CLOUD_OK
    cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERING, CLOUD_OK);
  } else {
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
  }
  return err;
}

void
oc_cloud_register_handler(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _register_handler(ctx, data, /*retryIsActive*/ false);

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY);
}

static void
cloud_schedule_retry(oc_cloud_context_t *ctx, oc_trigger_t callback,
                     bool is_timeout, bool is_refresh_token)
{
  uint16_t interval;
  if (is_refresh_token) {
    interval = g_retry_timeout[ctx->retry_refresh_token_count];
    ++ctx->retry_refresh_token_count;
  } else {
    interval = g_retry_timeout[ctx->retry_count];
    ++ctx->retry_count;
  }
  oc_set_delayed_callback(ctx, callback, is_timeout ? 0 : interval);
}

static void
cloud_manager_register_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  oc_remove_delayed_callback(ctx, cloud_manager_register_async);
  bool retry = false;
  if (_register_handler(ctx, data, /*retryIsActive*/ true) == 0) {
    cloud_reset_delayed_callback(ctx, cloud_manager_login_async,
                                 g_retry_timeout[ctx->retry_count]);
    goto finish;
  }

  if (((ctx->store.status & ~OC_CLOUD_FAILURE) == OC_CLOUD_INITIALIZED) &&
      cloud_is_connection_error_or_timeout(data->code) && !is_retry_over(ctx)) {
    retry = true;
  }

finish:
  cloud_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
  if (retry) {
    // must be invoked after cloud_manager_callback_handler_async
    cloud_schedule_retry(ctx, cloud_manager_register_async,
                         cloud_is_timeout_error_code(data->code), false);
  }
}

static oc_event_callback_retval_t
cloud_manager_register_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if (ctx->store.status != OC_CLOUD_INITIALIZED) {
    return OC_EVENT_DONE;
  }

  OC_DBG("[CM] try register(%d)", ctx->retry_count);
  if (is_retry_over(ctx)) {
    // for register, we don't try to reconnect because the access token has
    // short validity
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
    ctx->store.status |= OC_CLOUD_FAILURE;
    cloud_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return OC_EVENT_DONE;
  }

  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_manager_register_handler,
    .user_data = data,
    .timeout = g_retry_timeout[ctx->retry_count],
  };
  if (oc_string(ctx->store.ci_server) == NULL ||
      conv_cloud_endpoint(ctx) != 0) {
    OC_ERR("invalid cloud server");
    goto retry;
  }
  conf.endpoint = ctx->cloud_ep;
  if (!cloud_access_register(conf, oc_string(ctx->store.auth_provider), NULL,
                             oc_string(ctx->store.uid),
                             oc_string(ctx->store.access_token))) {
    OC_ERR("failed to sent register request to cloud");
    goto retry;
  }

  cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERING, CLOUD_OK);
  return OC_EVENT_DONE;

retry:
  // While retrying, keep last error (clec) to CLOUD_OK
  cloud_set_last_error(ctx, CLOUD_OK);
  oc_set_delayed_callback(data, cloud_manager_register_async,
                          g_retry_timeout[ctx->retry_count]);
  ++ctx->retry_count;
  return OC_EVENT_DONE;
}

static oc_cloud_error_t
_login_handler_check_data_error(const oc_client_response_t *data)
{
  if (cloud_is_connection_error_or_timeout(data->code)) {
    return CLOUD_ERROR_CONNECT;
  }
  if (data->code == OC_STATUS_UNAUTHORIZED) {
    return CLOUD_ERROR_UNAUTHORIZED;
  }
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    return CLOUD_ERROR_RESPONSE;
  }
  return CLOUD_OK;
}

static oc_cloud_error_t
_login_handler(oc_cloud_context_t *ctx, const oc_client_response_t *data,
               bool retryIsActive, bool clearCtxOnUnauthorized)
{
  const oc_cps_t cps_ok =
    cloud_is_deregistering(ctx) ? OC_CPS_DEREGISTERING : OC_CPS_REGISTERED;
  oc_cloud_error_t err = _login_handler_check_data_error(data);
  if (err != CLOUD_OK) {
    goto error;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  int64_t expires_in = 0;
  if (!oc_rep_get_int(data->payload, EXPIRESIN_KEY, &expires_in)) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }
  ctx->store.expires_in = expires_in;
  if (ctx->store.expires_in > 0) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
  }
  cloud_store_dump_async(&ctx->store);

  ctx->retry_count = 0;
  ctx->store.status |= OC_CLOUD_LOGGED_IN;
  cloud_set_cps_and_last_error(ctx, cps_ok, CLOUD_OK);
  return CLOUD_OK;

error:
  if (err == CLOUD_ERROR_CONNECT && retryIsActive && !is_retry_over(ctx)) {
    // While retrying, keep last error (clec) to CLOUD_OK
    cloud_set_cps_and_last_error(ctx, cps_ok, CLOUD_OK);
  } else {
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
  }
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    cloud_context_clear_access_token(ctx);
    if (clearCtxOnUnauthorized) {
      cloud_context_clear(ctx);
    }
  }

  ctx->store.status |= OC_CLOUD_FAILURE;
  return err;
}

void
oc_cloud_login_handler(oc_client_response_t *data)
{
  OC_DBG("login handler");
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _login_handler(ctx, data, /*retryIsActive*/ false,
                 /*clearCtxOnUnauthorized*/ false);

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY);
}

static bool
on_keepalive_response_default(oc_cloud_context_t *ctx, bool response_received,
                              uint64_t *next_ping)
{
  if (response_received) {
    *next_ping = 20 * 1000;
    ctx->retry_count = 0;
  } else {
    *next_ping = 4 * 1000;
    uint64_t keepalive_ping_timeout_ms =
      ((uint64_t)(ctx->keepalive.ping_timeout)) * 1000;
    // we don't want to ping more often than once per second
    if (keepalive_ping_timeout_ms >= (*next_ping + 1000)) {
      *next_ping = (keepalive_ping_timeout_ms - *next_ping);
    }
    ++ctx->retry_count;
  }
  return !is_retry_over(ctx);
}

static bool
on_keepalive_response(oc_cloud_context_t *ctx, bool response_received,
                      uint64_t *next_ping)
{
  bool ok = false;
  if (ctx->keepalive.on_response != NULL) {
    ok = ctx->keepalive.on_response(response_received, next_ping,
                                    &ctx->keepalive.ping_timeout,
                                    ctx->keepalive.user_data);
  } else {
    ok = on_keepalive_response_default(ctx, response_received, next_ping);
  }
  if (!ok) {
    OC_ERR("[CM] keepalive failed");
  } else {
    OC_DBG("[CM] keepalive sends the next ping in %llu milliseconds with %u "
           "seconds timeout",
           (long long unsigned)*next_ping, ctx->keepalive.ping_timeout);
  }
  return ok;
}

static void
cloud_manager_login_handler(oc_client_response_t *data)
{
  OC_DBG("[CM] login handler(%d)", data->code);

  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  oc_remove_delayed_callback(ctx, cloud_manager_login_async);
  bool handleUnauthorizedByRefresh = cloud_context_has_refresh_token(ctx);
  bool retry = false;
  oc_cloud_error_t ret = _login_handler(ctx, data, /*retryIsActive*/ true,
                                        !handleUnauthorizedByRefresh);
  if (ret == CLOUD_OK) {
    uint64_t next_ping = 0;
    on_keepalive_response(ctx, true, &next_ping);
    cloud_reset_delayed_callback_ms(ctx, cloud_manager_send_ping_async,
                                    next_ping);
    if (ctx->store.expires_in > 0) {
      cloud_reset_delayed_callback(ctx, cloud_manager_refresh_token_async,
                                   check_expires_in(ctx->store.expires_in));
    }
    goto finish;
  }
  if (ret == CLOUD_ERROR_UNAUTHORIZED) {
    if (handleUnauthorizedByRefresh) {
      cloud_reset_delayed_callback(ctx, cloud_manager_refresh_token_async,
                                   g_retry_timeout[0]);
    }
    goto finish;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    goto finish;
  }
  if (!is_retry_over(ctx)) {
    retry = true;
  } else {
    cloud_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
  }

finish:
  cloud_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
  if (retry) {
    // must be invoked after cloud_manager_callback_handler_async
    cloud_schedule_retry(ctx, cloud_manager_login_async,
                         cloud_is_timeout_error_code(data->code), false);
  }
}

static oc_event_callback_retval_t
cloud_manager_login_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    return OC_EVENT_DONE;
  }

  OC_DBG("[CM] try login (%d)", ctx->retry_count);
  if (is_retry_over(ctx)) {
    cloud_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
    return OC_EVENT_DONE;
  }

  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_manager_login_handler,
    .user_data = ctx,
    .timeout = g_retry_timeout[ctx->retry_count],
  };
  if (conv_cloud_endpoint(ctx) != 0) {
    OC_ERR("invalid cloud server");
    goto retry;
  }
  conf.endpoint = ctx->cloud_ep;
  if (!cloud_access_login(conf, oc_string(ctx->store.uid),
                          oc_string(ctx->store.access_token))) {
    OC_ERR("failed to sent sign in request to cloud");
    goto retry;
  }

  return OC_EVENT_DONE;

retry:
  // While retrying, keep last error (clec) to CLOUD_OK
  cloud_set_last_error(ctx, CLOUD_OK);
  oc_set_delayed_callback(ctx, cloud_manager_login_async,
                          g_retry_timeout[ctx->retry_count]);
  ++ctx->retry_count;
  return OC_EVENT_DONE;
}

static oc_cloud_error_t
_refresh_token_handler_check_data_error(const oc_client_response_t *data)
{
  if (cloud_is_connection_error_or_timeout(data->code)) {
    return CLOUD_ERROR_CONNECT;
  }
  if (data->code == OC_STATUS_UNAUTHORIZED) {
    return CLOUD_ERROR_UNAUTHORIZED;
  }
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    return CLOUD_ERROR_REFRESH_ACCESS_TOKEN;
  }
  return CLOUD_OK;
}

bool
cloud_manager_handle_refresh_token_response(oc_cloud_context_t *ctx,
                                            const oc_rep_t *payload)
{
  assert(ctx != NULL);
  assert(payload != NULL);

  char *access_value = NULL;
  size_t access_size = 0;
  if (!oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &access_value,
                         &access_size) ||
      access_size == 0) {
    return false;
  }

  char *refresh_value = NULL;
  size_t refresh_size = 0;
  if (!oc_rep_get_string(payload, REFRESH_TOKEN_KEY, &refresh_value,
                         &refresh_size) ||
      refresh_size == 0) {
    return false;
  }

  int64_t expires_in = 0;
  if (!oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in)) {
    return false;
  }

  cloud_set_string(&ctx->store.access_token, access_value, access_size);
  cloud_set_string(&ctx->store.refresh_token, refresh_value, refresh_size);
  ctx->store.expires_in = expires_in;
  if (ctx->store.expires_in > 0) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
  }
  return true;
}

static oc_cloud_error_t
_refresh_token_handler(oc_cloud_context_t *ctx,
                       const oc_client_response_t *data, bool retryIsActive)
{
  oc_cloud_error_t err = _refresh_token_handler_check_data_error(data);
  if (err != CLOUD_OK) {
    goto error;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    err = CLOUD_ERROR_REFRESH_ACCESS_TOKEN;
    goto error;
  }

  const oc_rep_t *payload = data->payload;
  if (!cloud_manager_handle_refresh_token_response(ctx, payload)) {
    err = CLOUD_ERROR_REFRESH_ACCESS_TOKEN;
    goto error;
  }

  cloud_store_dump_async(&ctx->store);

  cloud_set_last_error(ctx, CLOUD_OK);
  ctx->retry_count = 0;
  ctx->retry_refresh_token_count = 0;
  ctx->store.status |= OC_CLOUD_REFRESHED_TOKEN;

  return CLOUD_OK;

error:
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    cloud_context_clear(ctx);
    ctx->store.status |= OC_CLOUD_FAILURE;
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
    return err;
  }

  ctx->store.status |= OC_CLOUD_FAILURE;
  // we cannot be considered as logged in when refresh token fails.
  ctx->store.status &= ~OC_CLOUD_LOGGED_IN;
  if (err == CLOUD_ERROR_CONNECT) {
    if (retryIsActive && !is_refresh_token_retry_over(ctx)) {
      // While retrying keep last error (clec) to CLOUD_OK
      cloud_set_last_error(ctx, CLOUD_OK);
    } else {
      cloud_set_last_error(ctx, err);
    }
    return err;
  }

  ctx->store.status &= ~OC_CLOUD_REGISTERED;
  cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
  return err;
}

void
oc_cloud_refresh_token_handler(oc_client_response_t *data)
{
  OC_DBG("refresh token handler");
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _refresh_token_handler(ctx, data, /*retryIsActive*/ false);

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &=
    ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY | OC_CLOUD_REFRESHED_TOKEN);
}

static void
cloud_manager_refresh_token_handler(oc_client_response_t *data)
{
  OC_DBG("[CM] refresh token handler(%d)", data->code);
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  oc_remove_delayed_callback(ctx, cloud_manager_refresh_token_async);
  bool retry = false;
  if (_refresh_token_handler(ctx, data, /*retryIsActive*/ true) == CLOUD_OK) {
    cloud_reset_delayed_callback(ctx, cloud_manager_login_async,
                                 g_retry_timeout[ctx->retry_count]);
    goto finish;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0 &&
      !is_refresh_token_retry_over(ctx)) {
    retry = true;
  }

finish:
  cloud_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
  if (retry) {
    // must be invoked after cloud_manager_callback_handler_async
    cloud_schedule_retry(ctx, cloud_manager_refresh_token_async,
                         cloud_is_timeout_error_code(data->code), true);
  }
}

static oc_event_callback_retval_t
cloud_manager_refresh_token_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    return OC_EVENT_DONE;
  }
  oc_remove_delayed_callback(ctx, cloud_manager_send_ping_async);
  OC_DBG("[CM] try refresh token(%d)", ctx->retry_refresh_token_count);

  if (is_refresh_token_retry_over(ctx)) {
    cloud_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
    return OC_EVENT_DONE;
  }

  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_manager_refresh_token_handler,
    .user_data = ctx,
    .timeout = g_retry_timeout[ctx->retry_refresh_token_count],
  };
  if (conv_cloud_endpoint(ctx) != 0) {
    OC_ERR("invalid cloud server");
    goto retry;
  }
  conf.endpoint = ctx->cloud_ep;

  if (!cloud_access_refresh_access_token(conf, oc_string(ctx->store.uid),
                                         oc_string(ctx->store.refresh_token))) {
    goto retry;
  }

  return OC_EVENT_DONE;

retry:
  cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
  oc_set_delayed_callback(ctx, cloud_manager_refresh_token_async,
                          g_retry_timeout[ctx->retry_refresh_token_count]);
  ++ctx->retry_refresh_token_count;
  return OC_EVENT_DONE;
}

static void
cloud_manager_send_ping_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    return;
  }
  OC_DBG("[CM] send ping handler(%d)", data->code);

  bool response_received = true;
  if (data->code == OC_PING_TIMEOUT ||
      data->code == OC_STATUS_SERVICE_UNAVAILABLE ||
      cloud_is_timeout_error_code(data->code)) {
    response_received = false;
  }
  uint64_t next_ping = 0;
  bool want_continue =
    on_keepalive_response(ctx, response_received, &next_ping);
  if (want_continue) {
    cloud_reset_delayed_callback_ms(ctx, cloud_manager_send_ping_async,
                                    next_ping);
    return;
  }
  OC_DBG("[CM] ping fails with code(%d)", data->code);
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  cloud_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
}

static oc_event_callback_retval_t
cloud_manager_send_ping_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    return OC_EVENT_DONE;
  }

  OC_DBG("[CM] try send ping");
  if (!cloud_send_ping(ctx->cloud_ep, ctx->keepalive.ping_timeout,
                       cloud_manager_send_ping_handler, ctx)) {
    // While retrying, keep last error (clec) to CLOUD_OK
    cloud_set_last_error(ctx, CLOUD_OK);
  }

  return OC_EVENT_DONE;
}

#endif /* OC_CLOUD */
