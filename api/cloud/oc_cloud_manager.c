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
#include "security/oc_tls.h"
#endif /* OC_SECURITY */
#include <stdint.h>

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"
#define USER_ID_KEY "uid"
#define EXPIRESIN_KEY "expiresin"

#define PING_DELAY 20
#define PING_DELAY_ON_TIMEOUT 3
#define MAX_RETRY_COUNT (5)

struct oc_memb rep_objects_pool = { sizeof(oc_rep_t), 0, 0, 0, 0 };

static void cloud_start_process(oc_cloud_context_t *ctx);
static oc_event_callback_retval_t cloud_register(void *data);
static oc_event_callback_retval_t cloud_login(void *data);
static oc_event_callback_retval_t refresh_token(void *data);
static oc_event_callback_retval_t send_ping(void *data);

static uint16_t session_timeout[5] = { 3, 60, 1200, 24000, 60 };
static uint8_t message_timeout[5] = { 1, 2, 4, 8, 10 };

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
  oc_remove_delayed_callback(ctx, cloud_register);
  oc_remove_delayed_callback(ctx, cloud_login);
  oc_remove_delayed_callback(ctx, send_ping);
  oc_remove_delayed_callback(ctx, refresh_token);
  oc_remove_delayed_callback(ctx, callback_handler);
}

static void
reconnect(oc_cloud_context_t *ctx)
{
  oc_set_delayed_callback(ctx, callback_handler, 0);
  oc_remove_delayed_callback(ctx, refresh_token);
  cloud_reconnect(ctx);
}

static bool
is_refresh_token_retry_over(oc_cloud_context_t *ctx)
{
  if (ctx->retry_refresh_token_count < MAX_RETRY_COUNT)
    return false;

  reconnect(ctx);
  return true;
}

static bool
is_retry_over(oc_cloud_context_t *ctx)
{
  if (ctx->retry_count < MAX_RETRY_COUNT)
    return false;

  reconnect(ctx);
  return true;
}

static void
cloud_start_process(oc_cloud_context_t *ctx)
{
  ctx->retry_count = 0;

  if (ctx->store.status == OC_CLOUD_INITIALIZED) {
    oc_set_delayed_callback(ctx, cloud_register, session_timeout[0]);
  } else {
    if (oc_string(ctx->store.refresh_token) &&
        oc_string_len(ctx->store.refresh_token) > 0) {
      oc_set_delayed_callback(ctx, refresh_token, session_timeout[0]);
    } else {
      oc_set_delayed_callback(ctx, cloud_login, session_timeout[0]);
    }
  }
  _oc_signal_event_loop();
}

static int
_register_handler(oc_cloud_context_t *ctx, oc_client_response_t *data)
{
  if (data->code >= OC_STATUS_SERVICE_UNAVAILABLE) {
    cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
    goto error;
  } else if (data->code >= OC_STATUS_BAD_REQUEST) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
    goto error;
  }

  if (ctx->store.status != OC_CLOUD_INITIALIZED) {
    goto error;
  }

  oc_rep_t *payload = data->payload;

  ctx->store.status = 0;

  char *value = NULL;
  size_t size = 0;

  if (oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &value, &size) && size > 0) {
    cloud_set_string(&ctx->store.access_token, value, size);
  }

  value = NULL;
  size = 0;
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

  value = NULL;
  size = 0;
  if (oc_rep_get_string(payload, REFRESH_TOKEN_KEY, &value, &size) &&
      size > 0) {
    cloud_set_string(&ctx->store.refresh_token, value, size);
  }

  value = NULL;
  size = 0;
  if (oc_rep_get_string(payload, USER_ID_KEY, &value, &size) && size > 0) {
    cloud_set_string(&ctx->store.uid, value, size);
  }

  int64_t expires_in = 0;
  if (oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in) && expires_in > 0 &&
      expires_in <= UINT16_MAX) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
    ctx->expires_in = (uint16_t)expires_in;
  } else {
    ctx->expires_in = 0;
  }

  cloud_store_dump_async(&ctx->store);
  ctx->retry_count = 0;
  cloud_set_last_error(ctx, CLOUD_OK);

  ctx->store.status |= OC_CLOUD_REGISTERED;
  ctx->cps = OC_CPS_REGISTERED;

  return 0;

error:
  ctx->cps = OC_CPS_FAILED;
  ctx->store.status |= OC_CLOUD_FAILURE;
  if (ctx->last_error == 0) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
  }
  return -1;
}

void
oc_cloud_register_handler(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _register_handler(ctx, data);

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
  int ret = _register_handler(ctx, data);
  if (ret == 0) {
    oc_remove_delayed_callback(ctx, cloud_register);
    oc_set_delayed_callback(ctx, callback_handler, 0);
    oc_set_delayed_callback(ctx, cloud_login,
                            message_timeout[ctx->retry_count]);
  } else {
    oc_remove_delayed_callback(ctx, cloud_register);
    if (data->code != OC_STATUS_UNAUTHORIZED) {
      oc_set_delayed_callback(ctx, cloud_register,
                              message_timeout[ctx->retry_count]);
    }
    oc_set_delayed_callback(ctx, callback_handler, 0);
  }
}

static oc_event_callback_retval_t
cloud_register(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;

  if (ctx->store.status == OC_CLOUD_INITIALIZED) {
    OC_DBG("[CM] try register(%d)\n", ctx->retry_count);
    ctx->retry_count++;
    if (!is_retry_over(ctx)) {
      bool cannotConnect = true;
      if (oc_string(ctx->store.ci_server) && conv_cloud_endpoint(ctx) == 0 &&
          cloud_access_register(
            ctx->cloud_ep, oc_string(ctx->store.auth_provider), NULL,
            oc_string(ctx->store.uid), oc_string(ctx->store.access_token),
            ctx->device, cloud_register_handler, data)) {
        cannotConnect = false;
        ctx->cps = OC_CPS_REGISTERING;
      }
      if (cannotConnect) {
        cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
      }
      oc_set_delayed_callback(data, cloud_register,
                              session_timeout[ctx->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static int
_login_handler(oc_cloud_context_t *ctx, oc_client_response_t *data)
{
  if (data->code >= OC_STATUS_SERVICE_UNAVAILABLE) {
    cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
    goto error;
  } else if (data->code >= OC_STATUS_BAD_REQUEST) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
    goto error;
  }

  if (!(ctx->store.status & OC_CLOUD_REGISTERED)) {
    goto error;
  }

  ctx->retry_count = 0;
  ctx->store.status |= OC_CLOUD_LOGGED_IN;
  cloud_set_last_error(ctx, CLOUD_OK);

  if (ctx->expires_in) {
    ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
  }
  return 0;

error:
  ctx->cps = OC_CPS_FAILED;
  ctx->store.status |= OC_CLOUD_FAILURE;
  if (ctx->last_error == 0) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
  }
  return -1;
}

void
oc_cloud_login_handler(oc_client_response_t *data)
{
  OC_DBG("login handler");
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  _login_handler(ctx, data);

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
  int ret = _login_handler(ctx, data);
  if (ret == 0) {
    oc_remove_delayed_callback(ctx, cloud_login);
    oc_set_delayed_callback(ctx, callback_handler, 0);
    oc_set_delayed_callback(ctx, send_ping, PING_DELAY);
    if (ctx->store.status & OC_CLOUD_TOKEN_EXPIRY) {
      oc_set_delayed_callback(ctx, refresh_token, ctx->expires_in);
    }
  } else {
    oc_remove_delayed_callback(ctx, cloud_login);
    if (data->code != OC_STATUS_UNAUTHORIZED) {
      oc_set_delayed_callback(ctx, cloud_login,
                              message_timeout[ctx->retry_count]);
    } else {
      if (oc_string(ctx->store.refresh_token) &&
          oc_string_len(ctx->store.refresh_token) > 0) {
        oc_remove_delayed_callback(ctx, refresh_token);
        oc_set_delayed_callback(ctx, refresh_token, session_timeout[0]);
      }
    }
    oc_set_delayed_callback(ctx, callback_handler, 0);
  }
}

static oc_event_callback_retval_t
cloud_login(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;

  if (ctx->store.status & OC_CLOUD_REGISTERED) {
    OC_DBG("[CM] try login (%d)\n", ctx->retry_count);
    ctx->retry_count++;
    if (!is_retry_over(ctx)) {
      bool cannotConnect = true;
      if (conv_cloud_endpoint(ctx) == 0 &&
          cloud_access_login(ctx->cloud_ep, oc_string(ctx->store.uid),
                             oc_string(ctx->store.access_token), ctx->device,
                             cloud_login_handler, ctx)) {
        cannotConnect = false;
      }
      if (cannotConnect) {
        cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
      }
      oc_set_delayed_callback(ctx, cloud_login,
                              session_timeout[ctx->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static int
_refresh_token_handler(oc_cloud_context_t *ctx, oc_client_response_t *data)
{
  if (data->code >= OC_STATUS_SERVICE_UNAVAILABLE) {
    cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
    goto error;
  } else if (data->code >= OC_STATUS_BAD_REQUEST) {
    cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
    goto error;
  }

  if (!(ctx->store.status & OC_CLOUD_REGISTERED)) {
    goto error;
  }

  oc_rep_t *payload = data->payload;

  char *access_value = NULL, *refresh_value = NULL;
  size_t access_size = 0, refresh_size = 0;
  int64_t expires_in = 0;
  if (oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &access_value,
                        &access_size)) {
    if (!oc_rep_get_string(payload, REFRESH_TOKEN_KEY, &refresh_value,
                           &refresh_size)) {
      goto error;
    }
    cloud_set_string(&ctx->store.access_token, access_value, access_size);
    cloud_set_string(&ctx->store.refresh_token, refresh_value, refresh_size);
  } else {
    goto error;
  }

  ctx->expires_in = 0;
  if (oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in)) {
    if (expires_in > 0 && expires_in <= UINT16_MAX) {
      ctx->expires_in = (uint16_t)expires_in;
      ctx->store.status |= OC_CLOUD_TOKEN_EXPIRY;
    }
  }

  cloud_store_dump_async(&ctx->store);

  cloud_set_last_error(ctx, CLOUD_OK);
  ctx->retry_count = 0;
  ctx->store.status |= OC_CLOUD_REFRESHED_TOKEN;

  return 0;

error:
  if (ctx->last_error == 0) {
    cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
  }
  ctx->cps = OC_CPS_FAILED;
  ctx->store.status |= OC_CLOUD_FAILURE;
  return -1;
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
  int ret = _refresh_token_handler(ctx, data);
  if (ret == 0) {
    oc_remove_delayed_callback(ctx, send_ping);
    oc_remove_delayed_callback(ctx, refresh_token);
    ctx->retry_refresh_token_count = 0;
    oc_set_delayed_callback(ctx, cloud_login,
                            session_timeout[ctx->retry_count]);
  } else {
    oc_remove_delayed_callback(ctx, refresh_token);
    if (data->code != OC_STATUS_UNAUTHORIZED) {
      oc_set_delayed_callback(ctx, refresh_token,
                              message_timeout[ctx->retry_refresh_token_count]);
    }
  }
  oc_set_delayed_callback(ctx, callback_handler, 0);
}

static oc_event_callback_retval_t
refresh_token(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;

  if (!(ctx->store.status & OC_CLOUD_REGISTERED)) {
    return OC_EVENT_DONE;
  }
  OC_DBG("[CM] try refresh token(%d)\n", ctx->retry_refresh_token_count);

  ctx->retry_refresh_token_count++;
  if (!is_refresh_token_retry_over(ctx)) {
    bool cannotConnect = true;
    if (conv_cloud_endpoint(ctx) == 0 &&
        cloud_access_refresh_access_token(
          ctx->cloud_ep, oc_string(ctx->store.uid),
          oc_string(ctx->store.refresh_token), ctx->device,
          refresh_token_handler, ctx)) {
      cannotConnect = false;
    }
    if (cannotConnect) {
      cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
    }
    oc_set_delayed_callback(ctx, cloud_login,
                            session_timeout[ctx->retry_refresh_token_count]);
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

  if (data->code == OC_PING_TIMEOUT)
    goto error;

  oc_remove_delayed_callback(ctx, send_ping);
  ctx->retry_count = 0;
  oc_set_delayed_callback(ctx, send_ping, PING_DELAY);
  return;

error:
  oc_remove_delayed_callback(ctx, send_ping);
  oc_set_delayed_callback(ctx, send_ping, PING_DELAY_ON_TIMEOUT);
  if (data->code == OC_PING_TIMEOUT) {
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
  ctx->retry_count++;
  if (!is_retry_over(ctx)) {
    if (!oc_send_ping(false, ctx->cloud_ep, 1, send_ping_handler, ctx)) {
      cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
    }
  }

  return OC_EVENT_DONE;
}
#else  /* OC_CLOUD*/
typedef int dummy_declaration;
#endif /* !OC_CLOUD */
