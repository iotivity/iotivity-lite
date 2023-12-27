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

#include "api/oc_server_api_internal.h"
#include "oc_api.h"
#include "oc_cloud_access.h"
#include "oc_cloud_context_internal.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_access_internal.h"
#include "oc_cloud_log_internal.h"
#include "oc_cloud_manager_internal.h"
#include "oc_cloud_store_internal.h"
#include "oc_endpoint.h"
#include "rd_client_internal.h"
#include "port/oc_random.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#include <assert.h>
#include <stdint.h>

#define MILLISECONDS_PER_SECOND (1000)
#define MILLISECONDS_PER_MINUTE (60 * MILLISECONDS_PER_SECOND)
#define MILLISECONDS_PER_HOUR (60 * MILLISECONDS_PER_MINUTE)

#define MIN_DELAYED_VALUE_MS (256)

static void cloud_start_process(oc_cloud_context_t *ctx);
static oc_event_callback_retval_t cloud_manager_reconnect_async(void *data);
static oc_event_callback_retval_t cloud_manager_register_async(void *data);
static oc_event_callback_retval_t cloud_manager_login_async(void *data);
static oc_event_callback_retval_t cloud_manager_refresh_token_async(void *data);
static oc_event_callback_retval_t cloud_manager_send_ping_async(void *data);

static uint8_t g_retry_timeout[] = { 2, 4, 8, 16, 32, 64 };

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
  OC_CLOUD_DBG("cloud_manager_start");
  cloud_start_process(ctx);
}

void
cloud_manager_stop(const oc_cloud_context_t *ctx)
{
  OC_CLOUD_DBG("cloud_manager_stop");
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
  oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
  oc_cloud_manager_restart(ctx);
  return OC_EVENT_DONE;
}

static bool
OC_NONNULL()
  default_schedule_action(oc_cloud_action_t action, uint8_t retry_count,
                          oc_status_t last_status, uint64_t *delay,
                          uint16_t *timeout)
{
  (void)action;
  if (retry_count > OC_ARRAY_SIZE(g_retry_timeout)) {
    return false;
  }
  if (retry_count == 0) {
    *delay = oc_random_value() % MIN_DELAYED_VALUE_MS;
    *timeout = g_retry_timeout[retry_count];
    return true;
  }
  retry_count--;
  *timeout = g_retry_timeout[retry_count];
  if (cloud_is_timeout_error_code(last_status)) {
    *delay = MIN_DELAYED_VALUE_MS;
  } else {
    // for delay use timeout/2 value + random [0, timeout/2]
    *delay =
      (uint64_t)(g_retry_timeout[retry_count]) * MILLISECONDS_PER_SECOND / 2;
  }
  // Include a random delay to prevent multiple devices from attempting to
  // connect or make requests simultaneously.
  *delay += oc_random_value() % *delay;
  return true;
}

static bool
on_action_response_set_retry(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                             uint8_t retry_count, oc_status_t last_status,
                             uint64_t *delay)
{
  bool ok = false;
  if (ctx->schedule_action.on_schedule_action != NULL) {
    ok = ctx->schedule_action.on_schedule_action(
      action, retry_count, last_status, delay, &ctx->schedule_action.timeout,
      ctx->schedule_action.user_data);
  } else {
    ok = default_schedule_action(action, retry_count, last_status, delay,
                                 &ctx->schedule_action.timeout);
  }
  if (!ok) {
    OC_CLOUD_DBG("for retry(%d), action(%s) is stopped", retry_count,
                 oc_cloud_action_to_str(action));
    return false;
  }
  OC_CLOUD_DBG(
    "for retry(%d), action(%s) is delayed for %llu milliseconds with "
    "and set with %u seconds timeout",
    retry_count, oc_cloud_action_to_str(action), (long long unsigned)*delay,
    ctx->schedule_action.timeout);
  return true;
}

static bool
cloud_schedule_action(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                      oc_trigger_t callback, oc_status_t last_code,
                      bool is_retry)
{
  uint64_t interval = 0;
  uint8_t count = 0;

  if (action == OC_CLOUD_ACTION_REFRESH_TOKEN) {
    if (is_retry) {
      count = ++ctx->retry_refresh_token_count;
    } else {
      ctx->retry_refresh_token_count = 0;
    }
  } else {
    if (is_retry) {
      count = ++ctx->retry_count;
    } else {
      ctx->retry_count = 0;
    }
  }
  if (!on_action_response_set_retry(ctx, action, count, last_code, &interval)) {
    return false;
  }
  oc_reset_delayed_callback_ms(ctx, callback, interval);
  return true;
}

static bool
cloud_schedule_retry(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                     oc_trigger_t callback, oc_status_t last_code)
{
  return cloud_schedule_action(ctx, action, callback, last_code, true);
}

static bool
cloud_schedule_first_attempt(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                             oc_trigger_t callback)
{
  return cloud_schedule_action(ctx, action, callback, OC_STATUS_OK, false);
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
  oc_trigger_t cbk = NULL;
  oc_cloud_action_t action = OC_CLOUD_ACTION_UNKNOWN;
  if (ctx->store.status == OC_CLOUD_INITIALIZED &&
      ctx->store.cps == OC_CPS_READYTOREGISTER) {
    cbk = cloud_manager_register_async;
    action = OC_CLOUD_ACTION_REGISTER;
  }
  if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
    if (cloud_context_has_permanent_access_token(ctx)) {
      cbk = cloud_manager_login_async;
      action = OC_CLOUD_ACTION_LOGIN;
    } else {
      if (cloud_context_has_refresh_token(ctx)) {
        cbk = cloud_manager_refresh_token_async;
        action = OC_CLOUD_ACTION_REFRESH_TOKEN;
      }
    }
  }
  if (cbk != NULL && action != OC_CLOUD_ACTION_UNKNOWN &&
      !cloud_schedule_first_attempt(ctx, action, cbk)) {
    OC_CLOUD_ERR("Cannot start cloud process with action(%s)",
                 oc_cloud_action_to_str(action));
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
    ctx->store.status |= OC_CLOUD_FAILURE;
    oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 2);
  }
  _oc_signal_event_loop();
}

static uint64_t
refresh_token_expires_in_ms(int64_t expires_in_ms)
{
  if (expires_in_ms <= 0) {
    return 0;
  }

  if (expires_in_ms > (int64_t)MILLISECONDS_PER_HOUR) {
    // if time is more than 1h then set expires to (expires_in_ms - 10min).
    return (uint64_t)(expires_in_ms - (int64_t)(10 * MILLISECONDS_PER_MINUTE));
  }
  if (expires_in_ms > (int64_t)(4 * MILLISECONDS_PER_MINUTE)) {
    // if time is more than 240sec then set expires to (expires_in_ms - 2min).
    return (uint64_t)(expires_in_ms - (int64_t)(2 * MILLISECONDS_PER_MINUTE));
  }
  if (expires_in_ms > (int64_t)(20 * MILLISECONDS_PER_SECOND)) {
    // if time is more than 20sec then set expires to (expires_in_ms - 10sec).
    return (uint64_t)(expires_in_ms - (int64_t)(10 * MILLISECONDS_PER_SECOND));
  }
  return (uint64_t)expires_in_ms;
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

  oc_set_string(&ctx->store.access_token, access_token, access_token_size);
  oc_set_string(&ctx->store.refresh_token, refresh_token, refresh_token_size);
  oc_set_string(&ctx->store.uid, uid, uid_size);
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
    oc_set_string(&ctx->store.ci_server, value, size);
    return true;
  }

  return false;
}

static oc_cloud_error_t
_register_handler(oc_cloud_context_t *ctx, const oc_client_response_t *data,
                  oc_cps_t *cps)
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
    OC_CLOUD_DBG("redirect detected");
  }

  cloud_store_dump_async(&ctx->store);
  ctx->retry_count = 0;
  ctx->store.status |= OC_CLOUD_REGISTERED;
  OC_CLOUD_INFO("Registration succeeded");
  *cps = OC_CPS_REGISTERED;
  return CLOUD_OK;

error:
  ctx->store.status |= OC_CLOUD_FAILURE;
  *cps = OC_CPS_FAILED;
  return err;
}

void
oc_cloud_register_handler(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _register_handler(ctx, data, &cps);
  cloud_set_cps_and_last_error(ctx, cps, err);

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY);
}

static void
cloud_manager_register_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  oc_remove_delayed_callback(ctx, cloud_manager_register_async);
  bool retry = false;
  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _register_handler(ctx, data, &cps);
  if (err == CLOUD_OK) {
    if (!cloud_schedule_first_attempt(ctx, OC_CLOUD_ACTION_LOGIN,
                                      cloud_manager_login_async)) {
      OC_CLOUD_ERR(
        "Cannot schedule login after successful register, restarting");
      cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
      ctx->store.status |= OC_CLOUD_FAILURE;
      oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
      return;
    }
    goto finish;
  }

  if (((ctx->store.status & ~OC_CLOUD_FAILURE) == OC_CLOUD_INITIALIZED) &&
      cloud_is_connection_error_or_timeout(data->code)) {
    retry = true;
  }

finish:
  oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
  if (retry && cloud_schedule_retry(ctx, OC_CLOUD_ACTION_REGISTER,
                                    cloud_manager_register_async, data->code)) {
    OC_CLOUD_DBG("Registration failed with error(%d), retrying", (int)err);
    // While retrying, keep last error (clec) to CLOUD_OK
    cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERING, CLOUD_OK);
    return;
  }
  cloud_set_cps_and_last_error(ctx, cps, err);
}

static oc_event_callback_retval_t
cloud_manager_register_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if (ctx->store.status != OC_CLOUD_INITIALIZED) {
    return OC_EVENT_DONE;
  }

  OC_CLOUD_DBG("try register(%d)", ctx->retry_count);
  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_manager_register_handler,
    .user_data = data,
    .timeout = ctx->schedule_action.timeout,
  };
  if (oc_string(ctx->store.ci_server) == NULL ||
      conv_cloud_endpoint(ctx) != 0) {
    OC_CLOUD_ERR("invalid cloud server");
    goto retry;
  }
  OC_CLOUD_INFO("Registering to %s", oc_string(ctx->store.ci_server));
  conf.endpoint = ctx->cloud_ep;
  if (!oc_cloud_access_register(conf, oc_string(ctx->store.auth_provider), NULL,
                                oc_string(ctx->store.uid),
                                oc_string(ctx->store.access_token))) {
    OC_CLOUD_ERR("failed to sent register request to cloud");
    goto retry;
  }

  cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERING, CLOUD_OK);
  return OC_EVENT_DONE;

retry:
  if (!cloud_schedule_retry(ctx, OC_CLOUD_ACTION_REGISTER,
                            cloud_manager_register_async,
                            OC_STATUS_SERVICE_UNAVAILABLE)) {
    OC_CLOUD_ERR("Cannot schedule retry register");
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
    return OC_EVENT_DONE;
  }
  // While retrying, keep last error (clec) to CLOUD_OK
  cloud_set_last_error(ctx, CLOUD_OK);
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
               oc_cps_t *cps)
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
  OC_CLOUD_INFO("Login succeeded");
  *cps = cps_ok;
  return CLOUD_OK;

error:
  *cps = OC_CPS_FAILED;
  if (err == CLOUD_ERROR_CONNECT) {
    *cps = cps_ok;
  }
  return err;
}

void
oc_cloud_login_handler(oc_client_response_t *data)
{
  OC_CLOUD_DBG("login handler");
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _login_handler(ctx, data, &cps);
  if (err != CLOUD_OK) {
    cps = OC_CPS_FAILED;
  }
  cloud_set_cps_and_last_error(ctx, cps, err);
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
    *next_ping = 20UL * MILLISECONDS_PER_SECOND;
    ctx->retry_count = 0;
  } else {
    *next_ping = 4UL * MILLISECONDS_PER_SECOND;
    uint64_t keepalive_ping_timeout_ms =
      ((uint64_t)(ctx->keepalive.ping_timeout)) * MILLISECONDS_PER_SECOND;
    // we don't want to ping more often than once per second
    if (keepalive_ping_timeout_ms >= (*next_ping + MILLISECONDS_PER_SECOND)) {
      *next_ping = (keepalive_ping_timeout_ms - *next_ping);
    }
    ++ctx->retry_count;
  }
  return !(ctx->retry_count >= OC_ARRAY_SIZE(g_retry_timeout));
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
    OC_CLOUD_ERR("keepalive failed");
    return false;
  }
  OC_CLOUD_DBG("keepalive sends the next ping in %llu milliseconds with %u "
               "seconds timeout",
               (long long unsigned)*next_ping, ctx->keepalive.ping_timeout);
  return true;
}

static void
cloud_manager_login_handler(oc_client_response_t *data)
{
  OC_CLOUD_DBG("login handler(%d)", data->code);

  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  oc_remove_delayed_callback(ctx, cloud_manager_login_async);
  bool handleUnauthorizedByRefresh = cloud_context_has_refresh_token(ctx);
  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _login_handler(ctx, data, &cps);
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    cloud_set_cps_and_last_error(ctx, cps, err);
    oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return;
  }
  if (err == CLOUD_OK) {
    cloud_set_cps_and_last_error(ctx, cps, err);
    uint64_t next_ping = 0;
    on_keepalive_response(ctx, true, &next_ping);
    oc_reset_delayed_callback_ms(ctx, cloud_manager_send_ping_async, next_ping);
    if (ctx->store.expires_in > 0) {
      oc_reset_delayed_callback_ms(
        ctx, cloud_manager_refresh_token_async,
        refresh_token_expires_in_ms(ctx->store.expires_in *
                                    MILLISECONDS_PER_SECOND));
    }
    oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return;
  }
  ctx->store.status |= OC_CLOUD_FAILURE;
  if (err == CLOUD_ERROR_CONNECT &&
      cloud_schedule_retry(ctx, OC_CLOUD_ACTION_LOGIN,
                           cloud_manager_login_async, data->code)) {
    OC_CLOUD_DBG("Login failed with error(%d), retrying", (int)err);
    // While retrying, keep last error (clec) to CLOUD_OK
    cloud_set_cps_and_last_error(ctx, cps, CLOUD_OK);
    oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return;
  }
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    cloud_set_cps_and_last_error(ctx, cps, err);
    cloud_context_clear_access_token(ctx);
    if (!handleUnauthorizedByRefresh) {
      cloud_context_clear(ctx);
    } else {
      if (!cloud_schedule_first_attempt(ctx, OC_CLOUD_ACTION_REFRESH_TOKEN,
                                        cloud_manager_refresh_token_async)) {
        OC_CLOUD_ERR("Cannot schedule refresh token after unauthorized");
        cloud_context_clear(ctx);
      }
    }
    oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return;
  }
  cloud_set_cps_and_last_error(ctx, cps, err);
  OC_CLOUD_ERR("Login failed with error(%d), restarting", (int)err);
  oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
}

static oc_event_callback_retval_t
cloud_manager_login_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    return OC_EVENT_DONE;
  }

  OC_CLOUD_DBG("try login (%d)", ctx->retry_count);

  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_manager_login_handler,
    .user_data = ctx,
    .timeout = ctx->schedule_action.timeout,
  };
  if (oc_string(ctx->store.ci_server) == NULL ||
      conv_cloud_endpoint(ctx) != 0) {
    OC_CLOUD_ERR("invalid cloud server");
    goto retry;
  }
  OC_CLOUD_INFO("Login to %s", oc_string(ctx->store.ci_server));
  conf.endpoint = ctx->cloud_ep;
  if (!oc_cloud_access_login(conf, oc_string(ctx->store.uid),
                             oc_string(ctx->store.access_token))) {
    OC_CLOUD_ERR("failed to sent sign in request to cloud");
    goto retry;
  }

  return OC_EVENT_DONE;

retry:
  if (!cloud_schedule_retry(ctx, OC_CLOUD_ACTION_LOGIN,
                            cloud_manager_login_async,
                            OC_STATUS_SERVICE_UNAVAILABLE)) {
    OC_CLOUD_ERR("Cannot schedule retry login, restarting");
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
    ctx->store.status |= OC_CLOUD_FAILURE;
    oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 2);
    return OC_EVENT_DONE;
  }
  // While retrying, keep last error (clec) to CLOUD_OK
  cloud_set_last_error(ctx, CLOUD_OK);
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

  oc_set_string(&ctx->store.access_token, access_value, access_size);
  oc_set_string(&ctx->store.refresh_token, refresh_value, refresh_size);
  ctx->store.expires_in = expires_in;
  if (ctx->store.expires_in > 0) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
  }
  return true;
}

static oc_cloud_error_t
_refresh_token_handler(oc_cloud_context_t *ctx,
                       const oc_client_response_t *data, oc_cps_t *cps)
{
  // let's keep the current cps
  *cps = ctx->store.cps;
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

  ctx->retry_count = 0;
  ctx->retry_refresh_token_count = 0;
  ctx->store.status |= OC_CLOUD_REFRESHED_TOKEN;
  OC_CLOUD_INFO("Refreshing of access token succeeded");

  return CLOUD_OK;

error:
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    ctx->store.status |= OC_CLOUD_FAILURE;
    *cps = OC_CPS_FAILED;
    return err;
  }

  ctx->store.status |= OC_CLOUD_FAILURE;
  // we cannot be considered as logged in when refresh token fails.
  ctx->store.status &= ~OC_CLOUD_LOGGED_IN;
  if (err == CLOUD_ERROR_CONNECT) {
    return err;
  }

  ctx->store.status &= ~OC_CLOUD_REGISTERED;
  *cps = OC_CPS_FAILED;
  return err;
}

void
oc_cloud_refresh_token_handler(oc_client_response_t *data)
{
  OC_CLOUD_DBG("refresh token handler");
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _refresh_token_handler(ctx, data, &cps);
  if (err == CLOUD_OK) {
    cloud_set_last_error(ctx, CLOUD_OK);
  } else if (err == CLOUD_ERROR_CONNECT) {
    OC_CLOUD_ERR("Refreshing of access token failed with error(%d)", (int)err);
    cloud_set_last_error(ctx, err);
  } else {
    OC_CLOUD_ERR("refreshing of access token failed with error(%d)", (int)err);
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
  }

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
  OC_CLOUD_DBG("refresh token handler(%d)", data->code);
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  oc_remove_delayed_callback(ctx, cloud_manager_refresh_token_async);

  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _refresh_token_handler(ctx, data, &cps);

  if (err == CLOUD_OK) {
    if (!cloud_schedule_first_attempt(ctx, OC_CLOUD_ACTION_LOGIN,
                                      cloud_manager_login_async)) {
      OC_CLOUD_ERR(
        "Cannot schedule login after successful refresh token, restarting");
      cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
      ctx->store.status |= OC_CLOUD_FAILURE;
      oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
      return;
    }
    cloud_set_last_error(ctx, CLOUD_OK);
    oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return;
  } else if (err == CLOUD_ERROR_UNAUTHORIZED) {
    OC_CLOUD_ERR("Refreshing of access token failed with error(%d)", (int)err);
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
    cloud_context_clear(ctx);
  } else if (err == CLOUD_ERROR_CONNECT) {
    if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
      if (!cloud_schedule_retry(ctx, OC_CLOUD_ACTION_REFRESH_TOKEN,
                                cloud_manager_refresh_token_async,
                                data->code)) {
        OC_CLOUD_ERR(
          "Refreshing of access token failed with error(%d), restarting",
          (int)err);
        cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED,
                                     CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
        ctx->store.status |= OC_CLOUD_FAILURE;
        oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
        return;
      }
      OC_CLOUD_DBG("Refreshing of access token failed with error(%d), retrying",
                   (int)err);
      cloud_set_last_error(ctx, CLOUD_OK);
    }
  } else {
    OC_CLOUD_ERR("refreshing of access token failed with error(%d)", (int)err);
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
  }

  oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
}

static oc_event_callback_retval_t
cloud_manager_refresh_token_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    return OC_EVENT_DONE;
  }
  oc_remove_delayed_callback(ctx, cloud_manager_send_ping_async);
  OC_CLOUD_DBG("try refresh token(%d)", ctx->retry_refresh_token_count);

  oc_cloud_access_conf_t conf = {
    .device = ctx->device,
    .selected_identity_cred_id = ctx->selected_identity_cred_id,
    .handler = cloud_manager_refresh_token_handler,
    .user_data = ctx,
    .timeout = ctx->schedule_action.timeout,
  };
  if (oc_string(ctx->store.ci_server) == NULL ||
      conv_cloud_endpoint(ctx) != 0) {
    OC_CLOUD_ERR("invalid cloud server");
    goto retry;
  }
  OC_CLOUD_INFO("Refreshing access token for %s",
                oc_string(ctx->store.ci_server));
  conf.endpoint = ctx->cloud_ep;
  if (!oc_cloud_access_refresh_access_token(
        conf, oc_string(ctx->store.auth_provider), oc_string(ctx->store.uid),
        oc_string(ctx->store.refresh_token))) {
    goto retry;
  }

  return OC_EVENT_DONE;

retry:
  if (!cloud_schedule_retry(ctx, OC_CLOUD_ACTION_REFRESH_TOKEN,
                            cloud_manager_refresh_token_async,
                            OC_STATUS_SERVICE_UNAVAILABLE)) {
    OC_CLOUD_ERR("Cannot schedule refresh token, restarting");
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED,
                                 CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
    ctx->store.status |= OC_CLOUD_FAILURE;
    oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 2);
    return OC_EVENT_DONE;
  }
  cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
  return OC_EVENT_DONE;
}

static void
cloud_manager_send_ping_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    return;
  }
  OC_CLOUD_DBG("send ping handler(%d)", data->code);

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
    oc_reset_delayed_callback_ms(ctx, cloud_manager_send_ping_async, next_ping);
    return;
  }
  OC_CLOUD_DBG("ping fails with code(%d), restarting", data->code);
  cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
  oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
}

static oc_event_callback_retval_t
cloud_manager_send_ping_async(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    return OC_EVENT_DONE;
  }

  OC_CLOUD_DBG("try send ping");
  if (!cloud_send_ping(ctx->cloud_ep, ctx->keepalive.ping_timeout,
                       cloud_manager_send_ping_handler, ctx)) {
    // While retrying, keep last error (clec) to CLOUD_OK
    cloud_set_last_error(ctx, CLOUD_OK);
  }

  return OC_EVENT_DONE;
}

#endif /* OC_CLOUD */
