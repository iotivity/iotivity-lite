/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik  All Rights Reserved.
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

#include "cloud_internal.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "port/oc_log.h"
#include "rd_client.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"
#define USER_ID_KEY "uid"
#define EXPIRESIN_KEY "expiresin"

#define PING_DELAY 20
#define PING_DELAY_ON_TIMEOUT 3
#define MAX_CONTEXT_SIZE (2)
#define MAX_RETRY_COUNT (5)
#define REFRESH_TOKEN_DELAY (30 * 60)
#define REFRESH_TOKEN_DELAY_ON_SIGN_IN 3

struct oc_memb rep_objects_pool = {sizeof(oc_rep_t), 0, 0, 0, 0};

static void cloud_start_process(cloud_context_t *ctx);
static oc_event_callback_retval_t sign_up(void *data);
static oc_event_callback_retval_t sign_in(void *data);
static oc_event_callback_retval_t refresh_token(void *data);
static oc_event_callback_retval_t refresh_token_on_sign_in(void *data);
static oc_event_callback_retval_t send_ping(void *data);

static uint16_t session_timeout[5] = {3, 60, 1200, 24000, 60};
static uint8_t message_timeout[5] = {1, 2, 4, 8, 10};

static oc_event_callback_retval_t callback_handler(void *data) {
  cloud_context_t *ctx = (cloud_context_t *)data;
  cloud_manager_cb(ctx);

  return OC_EVENT_DONE;
}

static oc_rep_t *get_res_payload(oc_client_response_t *data) {
#ifndef RES_PAYLOAD_PARSE
  return data->payload;
#else
  OC_DBG("[CM] get_res_payload - %d, %d", rep_objects_pool.size,
         rep_objects_pool.num);
  oc_rep_t *payload = NULL;
  oc_rep_set_pool(&rep_objects_pool);
  int err = oc_parse_rep(data->payload, data->payload_len, &payload);
  if (err != 0) {
    OC_ERR("Error parsing payload!");
  }
  return payload;
#endif /* RES_PAYLOAD_PARSE */
}

static void free_res_payload(oc_rep_t *payload) {
#ifdef RES_PAYLOAD_PARSE
  oc_free_rep(payload);
#else
  (void)payload;
#endif /* RES_PAYLOAD_PARSE */
}

void cloud_manager_start(cloud_context_t *ctx) {
  OC_DBG("[CM] cloud_manager_start\n");
  if (ctx->store.status == CLOUD_SIGNED_IN ||
      ctx->store.status == CLOUD_REFRESHED_TOKEN)
    ctx->store.status = CLOUD_SIGNED_UP;
  cloud_start_process(ctx);
}

void cloud_manager_stop(cloud_context_t *ctx) {
  OC_DBG("[CM] cloud_manager_stop\n");
  oc_remove_delayed_callback(ctx, sign_up);
  oc_remove_delayed_callback(ctx, sign_in);
  oc_remove_delayed_callback(ctx, send_ping);
  oc_remove_delayed_callback(ctx, refresh_token);
  oc_remove_delayed_callback(ctx, refresh_token_on_sign_in);
  oc_remove_delayed_callback(ctx, callback_handler);
}

static bool is_retry_over(cloud_context_t *ctx) {
  if (ctx->retry_count < MAX_RETRY_COUNT)
    return false;

  if (ctx->store.status != CLOUD_RECONNECTING) {
    ctx->store.status = CLOUD_RECONNECTING;
    oc_set_delayed_callback(ctx, callback_handler, 0);
  }
  oc_remove_delayed_callback(ctx, refresh_token);
  oc_remove_delayed_callback(ctx, refresh_token_on_sign_in);
  cloud_reconnect(ctx);
  return true;
}

static void cloud_start_process(cloud_context_t *ctx) {
  ctx->retry_count = 0;

  if (ctx->store.status == CLOUD_INITIALIZED) {
    oc_set_delayed_callback(ctx, sign_up, session_timeout[0]);
  } else {
    oc_set_delayed_callback(ctx, sign_in, session_timeout[0]);
  }
  _oc_signal_event_loop();
}

static void sign_up_handler(oc_client_response_t *data) {
  cloud_context_t *ctx = (cloud_context_t *)data->user_data;
  OC_DBG("[CM] sign up handler(%d)\n", data->code);

  if (ctx->store.status != CLOUD_INITIALIZED &&
      ctx->store.status != CLOUD_RECONNECTING)
    return;

  oc_rep_t *payload = get_res_payload(data);

  if (data->code != OC_STATUS_CHANGED)
    goto error;

  char *value = NULL;
  size_t size = 0;

  if (oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &value, &size) && size > 0) {
    cloud_set_string(&ctx->store.access_token, value, size);
  }

  value = NULL;
  size = 0;
  if (oc_rep_get_string(payload, REDIRECTURI_KEY, &value, &size) && size > 0) {
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
  if (oc_rep_get_int(payload, EXPIRESIN_KEY, &expires_in)) {
    ctx->store.expires_in = expires_in;
  }

  ctx->store.status = CLOUD_SIGNED_UP;
  cloud_store_dump_async(&ctx->store);

  oc_remove_delayed_callback(ctx, sign_up);
  ctx->retry_count = 0;
  cloud_set_last_error(ctx, CLOUD_OK);
  oc_set_delayed_callback(ctx, callback_handler, 0);
  oc_set_delayed_callback(ctx, sign_in, message_timeout[ctx->retry_count]);

  free_res_payload(payload);
  return;

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
  oc_remove_delayed_callback(ctx, sign_up);
  if (data->code != OC_STATUS_UNAUTHORIZED) {
    oc_set_delayed_callback(ctx, sign_up, message_timeout[ctx->retry_count]);
    ctx->store.status = CLOUD_RECONNECTING;
  } else {
    ctx->store.status = CLOUD_FAILED;
  }

  oc_set_delayed_callback(ctx, callback_handler, 0);
  free_res_payload(payload);
}

static oc_event_callback_retval_t sign_up(void *data) {
  cloud_context_t *ctx = (cloud_context_t *)data;

  if (ctx->store.status == CLOUD_INITIALIZED ||
      ctx->store.status == CLOUD_RECONNECTING) {
    OC_DBG("[CM] try sign up(%d)\n", ctx->retry_count);
    ctx->retry_count++;
    if (!is_retry_over(ctx)) {
      bool cannotConnect = true;
      if (oc_string(ctx->store.ci_server) &&
          0 == oc_string_to_endpoint(&ctx->store.ci_server, ctx->cloud_ep,
                                     NULL) &&
          cloud_access_sign_up(
              ctx->cloud_ep, oc_string(ctx->store.auth_provider),
              oc_string(ctx->store.uid), oc_string(ctx->store.access_token),
              ctx->device_index, sign_up_handler, ctx)) {
        cannotConnect = false;
      }
      if (cannotConnect) {
        cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
      }
      oc_set_delayed_callback(ctx, sign_up, session_timeout[ctx->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t refresh_token_on_sign_in(void *data) {
  cloud_context_t *ctx = (cloud_context_t *)data;
  refresh_token(ctx);
  if (ctx->store.status == CLOUD_SIGNED_IN) {
    return OC_EVENT_DONE;
  }
  oc_set_delayed_callback(ctx, refresh_token, REFRESH_TOKEN_DELAY);
  return OC_EVENT_DONE;
}

static void sign_in_handler(oc_client_response_t *data) {
  cloud_context_t *ctx = (cloud_context_t *)data->user_data;

  OC_DBG("[CM] sign in handler(%d)\n", data->code);

  if (ctx->store.status != CLOUD_SIGNED_UP &&
      ctx->store.status != CLOUD_REFRESHED_TOKEN &&
      ctx->store.status != CLOUD_RECONNECTING)
    return;
  if (data->code != OC_STATUS_CHANGED)
    goto error;
  oc_rep_t *payload = get_res_payload(data);

  oc_remove_delayed_callback(ctx, sign_in);
  ctx->retry_count = 0;
  uint16_t refreshDelay = ctx->store.status == CLOUD_REFRESHED_TOKEN ? REFRESH_TOKEN_DELAY : REFRESH_TOKEN_DELAY_ON_SIGN_IN;
  ctx->store.status = CLOUD_SIGNED_IN;
  cloud_set_last_error(ctx, CLOUD_OK);
  oc_set_delayed_callback(ctx, callback_handler, 0);
  oc_set_delayed_callback(ctx, send_ping, PING_DELAY);
  oc_set_delayed_callback(ctx, refresh_token_on_sign_in, refreshDelay);
  free_res_payload(payload);
  return;

error:

  oc_remove_delayed_callback(ctx, sign_in);
  cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
  if (data->code != OC_STATUS_UNAUTHORIZED) {
    oc_set_delayed_callback(ctx, sign_in, message_timeout[ctx->retry_count]);
    ctx->store.status = CLOUD_RECONNECTING;
  } else {
    ctx->store.status = CLOUD_FAILED;
  }
  oc_set_delayed_callback(ctx, callback_handler, 0);
}

static oc_event_callback_retval_t sign_in(void *data) {
  cloud_context_t *ctx = (cloud_context_t *)data;

  if (ctx->store.status == CLOUD_SIGNED_UP ||
      ctx->store.status == CLOUD_REFRESHED_TOKEN ||
      ctx->store.status == CLOUD_RECONNECTING) {
    OC_DBG("[CM] try sign in(%d)\n", ctx->retry_count);
    ctx->retry_count++;
    if (!is_retry_over(ctx)) {
      bool cannotConnect = true;
      if (0 == oc_string_to_endpoint(&ctx->store.ci_server, ctx->cloud_ep,
                                     NULL) &&
          cloud_access_sign_in(ctx->cloud_ep, oc_string(ctx->store.uid),
                               oc_string(ctx->store.access_token),
                               ctx->device_index, sign_in_handler, ctx)) {
        cannotConnect = false;
      }
      if (cannotConnect) {
        cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
      }
      oc_set_delayed_callback(ctx, sign_in, session_timeout[ctx->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static void refresh_token_handler(oc_client_response_t *data) {
  cloud_context_t *ctx = (cloud_context_t *)data->user_data;
  if (ctx->store.status != CLOUD_SIGNED_IN) {
    return;
  }
  OC_DBG("[CM] refresh token handler(%d)\n", data->code);

  oc_rep_t *payload = get_res_payload(data);

  if (data->code != OC_STATUS_CHANGED)
    goto error;

  char *access_value, *refresh_value = NULL;
  size_t access_size, refresh_size;
  oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &access_value, &access_size);
  oc_rep_get_string(payload, REFRESH_TOKEN_KEY, &refresh_value, &refresh_size);

  if (!access_value || !refresh_value) {
    goto error;
  }
  cloud_set_string(&ctx->store.access_token, access_value, access_size);
  cloud_set_string(&ctx->store.refresh_token, refresh_value, refresh_size);
  cloud_store_dump_async(&ctx->store);

  oc_remove_delayed_callback(ctx, send_ping);
  oc_remove_delayed_callback(ctx, refresh_token);
  oc_remove_delayed_callback(ctx, refresh_token_on_sign_in);
  cloud_set_last_error(ctx, CLOUD_OK);
  ctx->retry_count = 0;
  ctx->store.status = CLOUD_REFRESHED_TOKEN;
  oc_set_delayed_callback(ctx, sign_in, session_timeout[ctx->retry_count]);
  oc_set_delayed_callback(ctx, callback_handler, 0);
  free_res_payload(payload);
  return;

error:
  cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
  oc_set_delayed_callback(ctx, callback_handler, 0);
  free_res_payload(payload);
}

static oc_event_callback_retval_t refresh_token(void *data) {
  cloud_context_t *ctx = (cloud_context_t *)data;
  if (ctx->store.status != CLOUD_SIGNED_IN) {
    return OC_EVENT_DONE;
  }
  OC_DBG("[CM] try refresh token(%d)\n", ctx->retry_count);

  if (!cloud_access_refresh_access_token(
          ctx->cloud_ep, oc_string(ctx->store.uid),
          oc_string(ctx->store.refresh_token), ctx->device_index,
          refresh_token_handler, ctx)) {
    cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
  }

  return OC_EVENT_CONTINUE;
}

static void send_ping_handler(oc_client_response_t *data) {
  cloud_context_t *ctx = (cloud_context_t *)data->user_data;
  if (ctx->store.status != CLOUD_SIGNED_IN) {
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

static oc_event_callback_retval_t send_ping(void *data) {
  cloud_context_t *ctx = (cloud_context_t *)data;
  if (ctx->store.status != CLOUD_SIGNED_IN) {
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
