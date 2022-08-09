/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifdef OC_CLOUD

#include "oc_api.h"
#include "oc_cloud_internal.h"
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

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"
#define USER_ID_KEY "uid"
#define EXPIRESIN_KEY "expiresin"

#define PING_DELAY 20
#define PING_DELAY_ON_TIMEOUT (PING_DELAY / 5)

static void cloud_start_process(oc_cloud_context_t *ctx);
static oc_event_callback_retval_t reconnect(void *data);
static oc_event_callback_retval_t cloud_register(void *data);
static oc_event_callback_retval_t cloud_login(void *data);
static oc_event_callback_retval_t refresh_token(void *data);
static oc_event_callback_retval_t send_ping(void *data);

static uint8_t g_retry_timeout[MAX_RETRY_COUNT] = { 2, 4, 8, 16, 32, 64 };

bool
cloud_set_retry(const uint8_t retry_timeout[], size_t retry_timeout_size)
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
cloud_get_retry(uint8_t *buffer, size_t buffer_size)
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
callback_handler(void *data)
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
  OC_DBG("[CM] cloud_manager_start\n");

  cloud_start_process(ctx);
}

void
cloud_manager_stop(oc_cloud_context_t *ctx)
{
  OC_DBG("[CM] cloud_manager_stop\n");
  oc_remove_delayed_callback(ctx, reconnect);
  oc_remove_delayed_callback(ctx, cloud_register);
  oc_remove_delayed_callback(ctx, cloud_login);
  oc_remove_delayed_callback(ctx, send_ping);
  oc_remove_delayed_callback(ctx, refresh_token);
  oc_remove_delayed_callback(ctx, callback_handler);
}

// Remove callback (if it exists) and schedule it again
static void
reset_delayed_callback(void *cb_data, oc_trigger_t callback, uint16_t seconds)
{
  oc_remove_delayed_callback(cb_data, callback);
  oc_set_delayed_callback(cb_data, callback, seconds);
}

static oc_event_callback_retval_t
reconnect(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  reset_delayed_callback(ctx, callback_handler, 0);
  oc_cloud_manager_restart(ctx);
  return OC_EVENT_DONE;
}

static bool
is_refresh_token_retry_over(oc_cloud_context_t *ctx)
{
  return ctx->retry_refresh_token_count >= MAX_RETRY_COUNT ||
         g_retry_timeout[ctx->retry_refresh_token_count] == 0;
}

static bool
is_retry_over(oc_cloud_context_t *ctx)
{
  return ctx->retry_count >= MAX_RETRY_COUNT ||
         g_retry_timeout[ctx->retry_count] == 0;
}

bool
cloud_has_refresh_token(const oc_cloud_context_t *ctx)
{
  return oc_string(ctx->store.refresh_token) != NULL &&
         oc_string_len(ctx->store.refresh_token) > 0;
}

bool
cloud_has_permanent_access_token(const oc_cloud_context_t *ctx)
{
  return oc_string(ctx->store.access_token) != NULL &&
         oc_string_len(ctx->store.access_token) > 0 &&
         ctx->store.expires_in < 0;
}

void
cloud_clear_access_token(oc_cloud_context_t *ctx)
{
  cloud_set_string(&ctx->store.access_token, NULL, 0);
  ctx->store.expires_in = 0;
}

static void
cloud_start_process(oc_cloud_context_t *ctx)
{
  ctx->retry_count = 0;
  ctx->retry_refresh_token_count = 0;

#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  if (pstat->s != OC_DOS_RFNOP && pstat->s != OC_DOS_RFPRO) {
    return;
  }
#endif

  if (ctx->store.status == OC_CLOUD_INITIALIZED &&
      ctx->store.cps == OC_CPS_READYTOREGISTER) {
    reset_delayed_callback(ctx, cloud_register, g_retry_timeout[0]);
    goto finish;
  }
  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    if (cloud_has_permanent_access_token(ctx)) {
      reset_delayed_callback(ctx, cloud_login, g_retry_timeout[0]);
      goto finish;
    }
    if (cloud_has_refresh_token(ctx)) {
      reset_delayed_callback(ctx, refresh_token, g_retry_timeout[0]);
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

static oc_cloud_error_t
_register_handler_check_data_error(oc_client_response_t *data)
{
  if (data->code == OC_STATUS_SERVICE_UNAVAILABLE ||
      data->code == OC_STATUS_GATEWAY_TIMEOUT) {
    return CLOUD_ERROR_CONNECT;
  }
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    return CLOUD_ERROR_RESPONSE;
  }
  return CLOUD_OK;
}

static int
_register_handler(oc_cloud_context_t *ctx, oc_client_response_t *data,
                  bool retry)
{
  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _register_handler_check_data_error(data);
  if (err != CLOUD_OK) {
    goto error;
  }

  if (ctx->store.status != OC_CLOUD_INITIALIZED) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  oc_rep_t *payload = data->payload;
  char *access_token = NULL;
  size_t access_token_size = 0;
  if (!oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &access_token,
                         &access_token_size) ||
      access_token_size == 0) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  char *refresh_token = NULL;
  size_t refresh_token_size = 0;
  if (!oc_rep_get_string(payload, REFRESH_TOKEN_KEY, &refresh_token,
                         &refresh_token_size) ||
      refresh_token_size == 0) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  char *uid = NULL;
  size_t uid_size = 0;
  if (!oc_rep_get_string(payload, USER_ID_KEY, &uid, &uid_size) ||
      uid_size == 0) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  int64_t expires_in = 0;
  if (!oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in)) {
    err = CLOUD_ERROR_RESPONSE;
    goto error;
  }

  cloud_set_string(&ctx->store.access_token, access_token, access_token_size);
  cloud_set_string(&ctx->store.refresh_token, refresh_token,
                   refresh_token_size);
  cloud_set_string(&ctx->store.uid, uid, uid_size);
  ctx->store.expires_in = expires_in;
  if (ctx->store.expires_in > 0) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
  }

  char *value = NULL;
  size_t size = 0;
  if (oc_rep_get_string(payload, REDIRECTURI_KEY, &value, &size) && size > 0) {
    char *ci_server = oc_string(ctx->store.ci_server);
    if (!ci_server || oc_string_len(ctx->store.ci_server) != size ||
        strcmp(ci_server, value)) {
      cloud_close_endpoint(ctx->cloud_ep);
      memset(ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
      ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
    }
    cloud_set_string(&ctx->store.ci_server, value, size);
  }

  cloud_store_dump_async(&ctx->store);
  ctx->retry_count = 0;
  ctx->store.status |= OC_CLOUD_REGISTERED;

  cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERED, CLOUD_OK);

  return 0;

error:
  ctx->store.status |= OC_CLOUD_FAILURE;
  if (err == CLOUD_ERROR_CONNECT && retry) {
    if (!is_retry_over(ctx)) {
      // While retrying, keep last error (clec) to CLOUD_OK
      cps = OC_CPS_REGISTERING;
      err = CLOUD_OK;
    }
  }
  cloud_set_cps_and_last_error(ctx, cps, err);
  return -1;
}

void
oc_cloud_register_handler(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _register_handler(ctx, data, false);

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY);
}

static void
cloud_register_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  int ret = _register_handler(ctx, data, true);
  oc_remove_delayed_callback(ctx, cloud_register);
  if (ret == 0) {
    reset_delayed_callback(ctx, cloud_login, g_retry_timeout[ctx->retry_count]);
    goto finish;
  }

  if (ctx->store.status == OC_CLOUD_INITIALIZED) {
    oc_set_delayed_callback(ctx, cloud_register,
                            g_retry_timeout[ctx->retry_count]);
  }

finish:
  reset_delayed_callback(ctx, callback_handler, 0);
}

static oc_event_callback_retval_t
cloud_register(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;

  if ((ctx->store.status == OC_CLOUD_INITIALIZED) == 0) {
    return OC_EVENT_DONE;
  }
  OC_DBG("[CM] try register(%d)\n", ctx->retry_count);
  if (!is_retry_over(ctx)) {
    if (oc_string(ctx->store.ci_server) && (conv_cloud_endpoint(ctx) == 0) &&
        cloud_access_register(
          ctx->cloud_ep, oc_string(ctx->store.auth_provider), NULL,
          oc_string(ctx->store.uid), oc_string(ctx->store.access_token),
          ctx->device, ctx->selected_identity_cred_id, cloud_register_handler,
          data)) {
      cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERING, CLOUD_OK);
    } else {
      // While retrying, keep last error (clec) to CLOUD_OK
      cloud_set_last_error(ctx, CLOUD_OK);
    }
    oc_set_delayed_callback(data, cloud_register,
                            g_retry_timeout[ctx->retry_count]);
    ctx->retry_count++;
  } else {
    // for register, we don't try to reconnect because the access token has
    // short validity
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
    ctx->store.status |= OC_CLOUD_FAILURE;
    reset_delayed_callback(ctx, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}

static oc_cloud_error_t
_login_handler_check_data_error(oc_client_response_t *data)
{
  if (data->code == OC_STATUS_SERVICE_UNAVAILABLE ||
      data->code == OC_STATUS_GATEWAY_TIMEOUT) {
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
_login_handler(oc_cloud_context_t *ctx, oc_client_response_t *data,
               bool clearCtxOnUnauthorized)
{
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
  cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERED, CLOUD_OK);
  return CLOUD_OK;

error:
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    cloud_clear_access_token(ctx);
    if (clearCtxOnUnauthorized) {
      oc_cloud_clear_context(ctx);
    }
  }

  ctx->store.status |= OC_CLOUD_FAILURE;
  cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
  return err;
}

void
oc_cloud_login_handler(oc_client_response_t *data)
{
  OC_DBG("login handler");
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _login_handler(ctx, data, false);

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY);
}

static void
cloud_login_handler(oc_client_response_t *data)
{
  OC_DBG("[CM] login handler(%d)\n", data->code);

  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  bool handleUnauthorizedByRefresh = cloud_has_refresh_token(ctx);
  oc_cloud_error_t ret =
    _login_handler(ctx, data, !handleUnauthorizedByRefresh);
  oc_remove_delayed_callback(ctx, cloud_login);
  if (ret == CLOUD_OK) {
    reset_delayed_callback(ctx, send_ping, PING_DELAY);
    if (ctx->store.expires_in > 0) {
      reset_delayed_callback(ctx, refresh_token,
                             check_expires_in(ctx->store.expires_in));
    }
    goto finish;
  }
  if (ret == CLOUD_ERROR_UNAUTHORIZED) {
    if (handleUnauthorizedByRefresh) {
      reset_delayed_callback(ctx, refresh_token, g_retry_timeout[0]);
    }
    goto finish;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    oc_set_delayed_callback(ctx, cloud_login,
                            g_retry_timeout[ctx->retry_count]);
  }

finish:
  reset_delayed_callback(ctx, callback_handler, 0);
}

static oc_event_callback_retval_t
cloud_login(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    return OC_EVENT_DONE;
  }
  OC_DBG("[CM] try login (%d)\n", ctx->retry_count);
  if (!is_retry_over(ctx)) {
    if ((conv_cloud_endpoint(ctx) != 0) ||
        !cloud_access_login(ctx->cloud_ep, oc_string(ctx->store.uid),
                            oc_string(ctx->store.access_token), ctx->device,
                            ctx->selected_identity_cred_id, cloud_login_handler,
                            ctx)) {
      // While retrying, keep last error (clec) to CLOUD_OK
      cloud_set_last_error(ctx, CLOUD_OK);
    }

    oc_set_delayed_callback(ctx, cloud_login,
                            g_retry_timeout[ctx->retry_count]);
    ctx->retry_count++;
  } else {
    reset_delayed_callback(ctx, reconnect, 0);
  }

  return OC_EVENT_DONE;
}

static oc_cloud_error_t
_refresh_token_handler_check_data_error(oc_client_response_t *data)
{
  if (data->code == OC_STATUS_SERVICE_UNAVAILABLE ||
      data->code == OC_STATUS_GATEWAY_TIMEOUT) {
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

static oc_cloud_error_t
_refresh_token_handler(oc_cloud_context_t *ctx, oc_client_response_t *data)
{
  oc_cloud_error_t err = _refresh_token_handler_check_data_error(data);
  if (err != CLOUD_OK) {
    goto error;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    err = CLOUD_ERROR_REFRESH_ACCESS_TOKEN;
    goto error;
  }

  oc_rep_t *payload = data->payload;

  char *access_value = NULL, *refresh_value = NULL;
  size_t access_size = 0, refresh_size = 0;
  int64_t expires_in = 0;
  if (!oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &access_value,
                         &access_size) ||
      access_size == 0) {
    err = CLOUD_ERROR_REFRESH_ACCESS_TOKEN;
    goto error;
  }
  if (!oc_rep_get_string(payload, REFRESH_TOKEN_KEY, &refresh_value,
                         &refresh_size) ||
      refresh_size == 0) {
    err = CLOUD_ERROR_REFRESH_ACCESS_TOKEN;
    goto error;
  }
  if (!oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in)) {
    err = CLOUD_ERROR_REFRESH_ACCESS_TOKEN;
    goto error;
  }
  cloud_set_string(&ctx->store.access_token, access_value, access_size);
  cloud_set_string(&ctx->store.refresh_token, refresh_value, refresh_size);
  ctx->store.expires_in = expires_in;
  if (ctx->store.expires_in > 0) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
  }

  cloud_store_dump_async(&ctx->store);

  cloud_set_last_error(ctx, CLOUD_OK);
  ctx->retry_count = 0;
  ctx->store.status |= OC_CLOUD_REFRESHED_TOKEN;

  return CLOUD_OK;

error:
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    oc_cloud_clear_context(ctx);
    ctx->store.status |= OC_CLOUD_FAILURE;
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
    return err;
  }

  ctx->store.status |= OC_CLOUD_FAILURE;
  // we cannot be considered as logged in when refresh token fails.
  ctx->store.status &= ~OC_CLOUD_LOGGED_IN;
  if (err == CLOUD_ERROR_CONNECT) {
    cloud_set_last_error(ctx, err);
    return err;
  }

  ctx->store.status &= ~OC_CLOUD_REGISTERED;
  cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
  return err;
}

void
oc_cloud_refresh_token_handler(oc_client_response_t *data)
{
  OC_DBG("refresh token handler\n");
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _refresh_token_handler(ctx, data);

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &=
    ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY | OC_CLOUD_REFRESHED_TOKEN);
}

static void
refresh_token_handler(oc_client_response_t *data)
{
  OC_DBG("[CM] refresh token handler(%d)\n", data->code);
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  oc_cloud_error_t ret = _refresh_token_handler(ctx, data);
  oc_remove_delayed_callback(ctx, refresh_token);
  if (ret == CLOUD_OK) {
    ctx->retry_refresh_token_count = 0;
    reset_delayed_callback(ctx, cloud_login, g_retry_timeout[ctx->retry_count]);
    goto finish;
  }

  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    oc_set_delayed_callback(ctx, refresh_token,
                            g_retry_timeout[ctx->retry_refresh_token_count]);
  }

finish:
  reset_delayed_callback(ctx, callback_handler, 0);
}

static oc_event_callback_retval_t
refresh_token(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;

  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    return OC_EVENT_DONE;
  }
  oc_remove_delayed_callback(ctx, send_ping);
  OC_DBG("[CM] try refresh token(%d)\n", ctx->retry_refresh_token_count);

  if (!is_refresh_token_retry_over(ctx)) {
    if ((conv_cloud_endpoint(ctx) != 0) ||
        !cloud_access_refresh_access_token(
          ctx->cloud_ep, oc_string(ctx->store.uid),
          oc_string(ctx->store.refresh_token), ctx->device,
          ctx->selected_identity_cred_id, refresh_token_handler, ctx)) {
      cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
    }
    oc_set_delayed_callback(ctx, refresh_token,
                            g_retry_timeout[ctx->retry_refresh_token_count]);

    ctx->retry_refresh_token_count++;
  } else {
    reset_delayed_callback(ctx, reconnect, 0);
  }

  return OC_EVENT_DONE;
}

static void
send_ping_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN)) {
    return;
  }
  OC_DBG("[CM] send ping handler(%d)\n", data->code);

  if (data->code == OC_PING_TIMEOUT ||
      data->code == OC_STATUS_SERVICE_UNAVAILABLE)
    goto error;

  ctx->retry_count = 0;
  reset_delayed_callback(ctx, send_ping, PING_DELAY);
  return;

error:
  reset_delayed_callback(ctx, send_ping, PING_DELAY_ON_TIMEOUT);
  if (data->code == OC_PING_TIMEOUT ||
      data->code == OC_STATUS_SERVICE_UNAVAILABLE) {
    cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  }
}

static oc_event_callback_retval_t
send_ping(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;

  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN)) {
    return OC_EVENT_DONE;
  }

  OC_DBG("[CM] try send ping(%d)\n", ctx->retry_count);
  if (!is_retry_over(ctx)) {
    if (!cloud_send_ping(ctx->cloud_ep, 1, send_ping_handler, ctx)) {
      // While retrying, keep last error (clec) to CLOUD_OK
      cloud_set_last_error(ctx, CLOUD_OK);
    }
    ctx->retry_count++;
  } else {
    reset_delayed_callback(ctx, reconnect, 0);
  }

  return OC_EVENT_DONE;
}
#else  /* OC_CLOUD*/
typedef int dummy_declaration;
#endif /* !OC_CLOUD */
