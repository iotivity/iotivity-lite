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

#include "api/cloud/oc_cloud_access_internal.h"
#include "api/cloud/oc_cloud_apis_internal.h"
#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/cloud/oc_cloud_log_internal.h"
#include "api/cloud/oc_cloud_manager_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/cloud/oc_cloud_schedule_internal.h"
#include "api/cloud/oc_cloud_store_internal.h"
#include "api/cloud/rd_client_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_server_api_internal.h"
#include "oc_api.h"
#include "oc_cloud_access.h"
#include "oc_endpoint.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#include <assert.h>
#include <stdint.h>

static void cloud_start_process(oc_cloud_context_t *ctx);
static oc_event_callback_retval_t cloud_manager_reconnect_async(void *data);
static oc_event_callback_retval_t cloud_manager_register_async(void *data);
static oc_event_callback_retval_t cloud_manager_login_async(void *data);
static oc_event_callback_retval_t cloud_manager_refresh_token_async(void *data);
static oc_event_callback_retval_t cloud_manager_send_ping_async(void *data);

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
cloud_schedule_retry(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                     oc_trigger_t callback)
{
  return cloud_schedule_action(ctx, action, callback, true);
}

static bool
cloud_schedule_first_attempt(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                             oc_trigger_t callback)
{
  return cloud_schedule_action(ctx, action, callback, false);
}

static void
cloud_start_process(oc_cloud_context_t *ctx)
{
  cloud_retry_reset(&ctx->retry);
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
    oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
  }
  _oc_signal_event_loop();
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

static const oc_string_t *
manager_payload_get_string_property(const oc_rep_t *payload,
                                    oc_string_view_t key)
{
  const oc_rep_t *rep =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, key.data, key.length);
  if (rep == NULL || oc_string_is_empty(&rep->value.string)) {
    return NULL;
  }
  return &rep->value.string;
}

bool
cloud_manager_handle_register_response(oc_cloud_context_t *ctx,
                                       const oc_rep_t *payload)
{
  assert(ctx != NULL);
  assert(payload != NULL);

  const oc_string_t *access_token = manager_payload_get_string_property(
    payload, OC_STRING_VIEW(ACCESS_TOKEN_KEY));
  if (access_token == NULL) {
    return false;
  }

  const oc_string_t *refresh_token = manager_payload_get_string_property(
    payload, OC_STRING_VIEW(REFRESH_TOKEN_KEY));
  if (refresh_token == NULL) {
    return false;
  }

  const oc_string_t *uid =
    manager_payload_get_string_property(payload, OC_STRING_VIEW(USER_ID_KEY));
  if (uid == NULL) {
    return false;
  }

  int64_t expires_in = 0;
  if (!oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in)) {
    return false;
  }

  oc_copy_string(&ctx->store.access_token, access_token);
  oc_copy_string(&ctx->store.refresh_token, refresh_token);
  oc_copy_string(&ctx->store.uid, uid);
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

  const oc_rep_t *redirect =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, REDIRECTURI_KEY,
                               OC_CHAR_ARRAY_LEN(REDIRECTURI_KEY));
  if (redirect == NULL) {
    return false;
  }
  const oc_string_t *redirecturi = &redirect->value.string;
  if (redirecturi->size <= 1) {
    return false;
  }
  if (oc_endpoint_addresses_is_selected(&ctx->store.ci_servers,
                                        oc_string_view2(redirecturi))) {
    return true;
  }

  const oc_endpoint_address_t *originalCis = ctx->store.ci_servers.selected;
  oc_uuid_t sid = OCF_COAPCLOUDCONF_DEFAULT_SID;
  // OCF Cloud Security Specification, 6.2:
  // "If OCF Cloud provides "redirecturi" Value as response during Device
  // Registration, the redirected to OCF Cloud is assumed to have the same OCF
  // Cloud UUID and to use the same trust anchor"
  if (originalCis != NULL) {
    assert(originalCis->metadata.id_type ==
           OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID);
    sid = originalCis->metadata.id.uuid;
  }

  if (!oc_endpoint_addresses_contains(&ctx->store.ci_servers,
                                      oc_string_view2(redirecturi)) &&
      oc_endpoint_addresses_add(&ctx->store.ci_servers,
                                oc_endpoint_address_make_view_with_uuid(
                                  oc_string_view2(redirecturi), sid)) == NULL) {
    OC_CLOUD_ERR("failed to add server to the list");
    return false;
  }

  // remove the original server from the list
  if (originalCis != NULL) {
    oc_endpoint_addresses_remove(&ctx->store.ci_servers, originalCis);
  }

  // select the new server
  oc_endpoint_addresses_select_by_uri(&ctx->store.ci_servers,
                                      oc_string_view2(redirecturi));

  if (ctx->cloud_ep != NULL) {
    oc_cloud_reset_endpoint(ctx);
  }
  return true;
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
    OC_CLOUD_DBG("redirect processed");
  }

  oc_cloud_store_dump_async(&ctx->store);
  cloud_retry_reset(&ctx->retry);
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
  oc_cloud_api_free_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY);
}

bool
cloud_manager_register_check_retry_with_changed_server(
  const oc_cloud_context_t *ctx)
{
  if (ctx->registration_ctx.remaining_server_changes == 0) {
    OC_CLOUD_DBG("No more servers to try");
    return false;
  }

  if (!ctx->registration_ctx.server_changed) {
    OC_CLOUD_DBG("Server has not changed, retrying skipped");
    return false;
  }

  // if the initial server is not in the list of endpoints -> the list has been
  // modified, so we stop retrying
  return oc_endpoint_addresses_contains(
    &ctx->store.ci_servers,
    oc_string_view2(&ctx->registration_ctx.initial_server));
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
  if (retry) {
    if (cloud_schedule_retry(ctx, OC_CLOUD_ACTION_REGISTER,
                             cloud_manager_register_async)) {
      OC_CLOUD_DBG("Registration failed with error(%d), retrying", (int)err);
    } else if (cloud_manager_register_check_retry_with_changed_server(ctx)) {
      --ctx->registration_ctx.remaining_server_changes;
      ctx->registration_ctx.server_changed = false;
      OC_CLOUD_DBG("Registration failed with error(%d), retrying by "
                   "reconnecting to another server (remaining server changes "
                   "attempts: %d)",
                   (int)err, ctx->registration_ctx.remaining_server_changes);
      oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
    } else {
      retry = false;
    }
    if (retry) {
      // While retrying, keep last error (clec) to CLOUD_OK
      cloud_set_cps_and_last_error(ctx, OC_CPS_REGISTERING, CLOUD_OK);
      return;
    }
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

  OC_CLOUD_DBG("try register(%d)", ctx->retry.count);
  oc_cloud_access_conf_t conf;
  if (!oc_cloud_set_access_conf(ctx, cloud_manager_register_handler, ctx,
                                ctx->schedule_action.timeout, &conf)) {
    goto retry;
  }
  oc_cloud_endpoint_log("Registering to ", ctx->cloud_ep);
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
                            cloud_manager_register_async)) {
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
  oc_cloud_store_dump_async(&ctx->store);

  cloud_retry_reset(&ctx->retry);
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
    ctx->store.status |= OC_CLOUD_FAILURE;
  }
  cloud_set_cps_and_last_error(ctx, cps, err);
  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  oc_cloud_api_free_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_TOKEN_EXPIRY);
}

static bool
on_keepalive_response_default(oc_cloud_context_t *ctx, bool response_received,
                              uint64_t *next_ping)
{
  if (response_received) {
    *next_ping = 20UL * MILLISECONDS_PER_SECOND;
    ctx->retry.count = 0;
  } else {
    *next_ping = 4UL * MILLISECONDS_PER_SECOND;
    uint64_t keepalive_ping_timeout_ms =
      ((uint64_t)(ctx->keepalive.ping_timeout)) * MILLISECONDS_PER_SECOND;
    // we don't want to ping more often than once per second
    if (keepalive_ping_timeout_ms >= (*next_ping + MILLISECONDS_PER_SECOND)) {
      *next_ping = (keepalive_ping_timeout_ms - *next_ping);
    }
    ++ctx->retry.count;
  }
  return !cloud_retry_is_over(ctx->retry.count);
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

uint64_t
cloud_manager_calculate_refresh_token_expiration(uint64_t expires_in_ms)
{
  assert(expires_in_ms > 0);

  if (expires_in_ms > (uint64_t)MILLISECONDS_PER_HOUR) {
    // if time is more than 1h then set expires to (expires_in_ms - 10min).
    return expires_in_ms - (uint64_t)(10 * MILLISECONDS_PER_MINUTE);
  }
  if (expires_in_ms > (int64_t)(4 * MILLISECONDS_PER_MINUTE)) {
    // if time is more than 240sec then set expires to (expires_in_ms - 2min).
    return expires_in_ms - (uint64_t)(2 * MILLISECONDS_PER_MINUTE);
  }
  if (expires_in_ms > (int64_t)(20 * MILLISECONDS_PER_SECOND)) {
    // if time is more than 20sec then set expires to (expires_in_ms - 10sec).
    return expires_in_ms - (uint64_t)(10 * MILLISECONDS_PER_SECOND);
  }
  return expires_in_ms;
}

static void
cloud_manager_login_handler(oc_client_response_t *data)
{
  OC_CLOUD_DBG("login handler(%d)", data->code);

  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;

  oc_remove_delayed_callback(ctx, cloud_manager_login_async);
  if ((ctx->store.status & OC_CLOUD_REGISTERED) == 0) {
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_RESPONSE);
    oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return;
  }
  oc_cps_t cps = OC_CPS_FAILED;
  oc_cloud_error_t err = _login_handler(ctx, data, &cps);
  if (err == CLOUD_OK) {
    cloud_set_cps_and_last_error(ctx, cps, err);
    uint64_t next_ping = 0;
    on_keepalive_response(ctx, true, &next_ping);
    oc_reset_delayed_callback_ms(ctx, cloud_manager_send_ping_async, next_ping);
    if (ctx->store.expires_in > 0) {
      oc_reset_delayed_callback_ms(
        ctx, cloud_manager_refresh_token_async,
        cloud_manager_calculate_refresh_token_expiration(
          (uint64_t)(ctx->store.expires_in * MILLISECONDS_PER_SECOND)));
    }
    oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
    return;
  }
  ctx->store.status |= OC_CLOUD_FAILURE;

  if (err == CLOUD_ERROR_CONNECT) {
    if (cloud_schedule_retry(ctx, OC_CLOUD_ACTION_LOGIN,
                             cloud_manager_login_async)) {
      OC_CLOUD_DBG("Login failed with error(%d), retrying", (int)err);
      // While retrying, keep last error (clec) to CLOUD_OK
      cloud_set_cps_and_last_error(ctx, cps, CLOUD_OK);
      oc_reset_delayed_callback(ctx, cloud_manager_callback_handler_async, 0);
      return;
    }
    cps = OC_CPS_FAILED;
  }
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    cloud_set_cps_and_last_error(ctx, cps, err);
    cloud_context_clear_access_token(ctx);
    bool handleUnauthorizedByRefresh = cloud_context_has_refresh_token(ctx);
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

  OC_CLOUD_DBG("try login(%d)", ctx->retry.count);
  oc_cloud_access_conf_t conf;
  if (!oc_cloud_set_access_conf(ctx, cloud_manager_login_handler, ctx,
                                ctx->schedule_action.timeout, &conf)) {
    goto retry;
  }
  oc_cloud_endpoint_log("Login to ", ctx->cloud_ep);
  if (!oc_cloud_access_login(conf, oc_string(ctx->store.uid),
                             oc_string(ctx->store.access_token))) {
    OC_CLOUD_ERR("failed to sent sign in request to cloud");
    goto retry;
  }

  return OC_EVENT_DONE;

retry:
  if (!cloud_schedule_retry(ctx, OC_CLOUD_ACTION_LOGIN,
                            cloud_manager_login_async)) {
    OC_CLOUD_ERR("Cannot schedule retry login, restarting");
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, CLOUD_ERROR_CONNECT);
    ctx->store.status |= OC_CLOUD_FAILURE;
    oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
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

  oc_cloud_store_dump_async(&ctx->store);

  cloud_retry_reset(&ctx->retry);
  ctx->store.status |= OC_CLOUD_REFRESHED_TOKEN;
  OC_CLOUD_INFO("Refreshing of access token succeeded");

  return CLOUD_OK;

error:
  ctx->store.status |= OC_CLOUD_FAILURE;
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    *cps = OC_CPS_FAILED;
    return err;
  }

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
  oc_cloud_api_free_param(p);

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
    goto finish;
  }
  if (err == CLOUD_ERROR_UNAUTHORIZED) {
    OC_CLOUD_ERR("Refreshing of access token failed with error(%d)", (int)err);
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);
    cloud_context_clear(ctx);
    goto finish;
  }
  if (err == CLOUD_ERROR_CONNECT) {
    if ((ctx->store.status & OC_CLOUD_REGISTERED) != 0) {
      if (!cloud_schedule_retry(ctx, OC_CLOUD_ACTION_REFRESH_TOKEN,
                                cloud_manager_refresh_token_async)) {
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
    goto finish;
  }
  OC_CLOUD_ERR("refreshing of access token failed with error(%d)", (int)err);
  cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED, err);

finish:
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

  OC_CLOUD_DBG("try refresh token(%d)", ctx->retry.refresh_token_count);
  oc_cloud_access_conf_t conf;
  if (!oc_cloud_set_access_conf(ctx, cloud_manager_refresh_token_handler, ctx,
                                ctx->schedule_action.timeout, &conf)) {
    goto retry;
  }

  oc_cloud_endpoint_log("Refreshing access token for ", ctx->cloud_ep);
  if (!oc_cloud_access_refresh_access_token(
        conf, oc_string(ctx->store.auth_provider), oc_string(ctx->store.uid),
        oc_string(ctx->store.refresh_token))) {
    goto retry;
  }

  return OC_EVENT_DONE;

retry:
  if (!cloud_schedule_retry(ctx, OC_CLOUD_ACTION_REFRESH_TOKEN,
                            cloud_manager_refresh_token_async)) {
    OC_CLOUD_ERR("Cannot schedule refresh token, restarting");
    cloud_set_cps_and_last_error(ctx, OC_CPS_FAILED,
                                 CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
    ctx->store.status |= OC_CLOUD_FAILURE;
    oc_reset_delayed_callback(ctx, cloud_manager_reconnect_async, 0);
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
