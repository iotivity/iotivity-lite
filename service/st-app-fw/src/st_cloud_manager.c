/****************************************************************************
 *
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

#include "st_cloud_manager.h"
#include "cloud_access.h"
#include "easysetup.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "rd_client.h"
#include "st_port.h"
#include "st_store.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#ifdef OC_SECURITY
#include "security/oc_tls.h"
#endif

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"

#define ONE_MINUTE (56)
#define MAX_CONTEXT_SIZE (2)
#define MAX_RETRY_COUNT (5)

typedef struct st_cloud_context
{
  struct st_cloud_context *next;
  st_cloud_manager_cb_t callback;
  oc_endpoint_t cloud_ep;
  size_t device_index;
  st_cloud_manager_status_t cloud_manager_status;
  uint8_t retry_count;
} st_cloud_context_t;

typedef enum {
  CI_TOKEN_EXPIRED = 4000004, // during sign up or sign in
  CI_TOKEN_REQEUST_EXPIRED = 4010004, // during normally request
  CI_AUTHORIZATION_FAILED = 4000005,
  CI_CERTIFICATE_FAILED = 4010008,
  CI_UNAUTHORIZED_TOKEN = 4010201,
  CI_FORBIDDEN = 4030003,
  CI_DEVICE_NOT_FOUND = 4040200,
  CI_INTERNAL_SERVER_ERROR = 5000000
} ci_error_code_t;

OC_LIST(st_cloud_context_list);
OC_MEMB(st_cloud_context_s, st_cloud_context_t, MAX_CONTEXT_SIZE);
struct oc_memb st_rep_objects_pool = { sizeof(oc_rep_t), 0, 0, 0, 0 };

static void cloud_start_process(st_cloud_context_t *context);
static oc_event_callback_retval_t sign_up(void *data);
static oc_event_callback_retval_t sign_in(void *data);
static oc_event_callback_retval_t refresh_token(void *data);
static oc_event_callback_retval_t set_dev_profile(void *data);
static oc_event_callback_retval_t publish_resource(void *data);
static oc_event_callback_retval_t find_ping(void *data);
static oc_event_callback_retval_t send_ping(void *data);

static uint16_t session_timeout[5] = { 3, 60, 1200, 24000, 60 };
static uint8_t message_timeout[5] = { 1, 2, 4, 8, 10 };
static uint16_t g_ping_interval = 1;

static oc_event_callback_retval_t
callback_handler(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  context->callback(context->cloud_manager_status);

  return OC_EVENT_DONE;
}

static oc_rep_t*
get_res_payload(oc_client_response_t *data)
{
#ifndef ST_RES_PAYLOAD_PARSE
  return data->payload;
#else
  OC_DBG("[ST_CM] get_res_payload - %d, %d", st_rep_objects_pool.size,  st_rep_objects_pool.num);
  oc_rep_t *payload = NULL;
  oc_rep_set_pool(&st_rep_objects_pool);
  int err = oc_parse_rep(data->payload, data->payload_len, &payload);
  if (err != 0) {
    OC_ERR("Error parsing payload!");
  }
  return payload;
#endif /* ST_RES_PAYLOAD_PARSE */
}

static void
free_res_payload(oc_rep_t *payload)
{
#ifdef ST_RES_PAYLOAD_PARSE
  oc_free_rep(payload);
#else
  (void)payload;
#endif /* ST_RES_PAYLOAD_PARSE */
}

#ifdef OC_SESSION_EVENTS
static void
session_event_handler(const oc_endpoint_t *endpoint, oc_session_state_t state)
{
  st_print_log("[ST_CM] session state (%s)\n",
               (state) ? "DISCONNECTED" : "CONNECTED");
  if (state == OC_SESSION_CONNECTED)
    return;

  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  while (context != NULL && context->device_index != endpoint->device) {
    context = context->next;
  }

  if (!context || context->cloud_manager_status == CLOUD_MANAGER_RECONNECTING ||
      0 != oc_endpoint_compare(endpoint, &context->cloud_ep))
    return;

  switch (context->cloud_manager_status) {
  case CLOUD_MANAGER_INITIALIZED:
    oc_remove_delayed_callback(context, sign_up);
    break;
  case CLOUD_MANAGER_SIGNED_UP:
    oc_remove_delayed_callback(context, sign_in);
    break;
  case CLOUD_MANAGER_SIGNED_IN: {
    st_store_t *store_info = st_store_get_info();
    if (store_info->cloudinfo.status != CLOUD_MANAGER_RES_PUBLISHED)
      oc_remove_delayed_callback(context, set_dev_profile);
    else
      oc_remove_delayed_callback(context, find_ping);
  } break;
  case CLOUD_MANAGER_DEV_PUBLISHED:
    oc_remove_delayed_callback(context, publish_resource);
    break;
  case CLOUD_MANAGER_RES_PUBLISHED:
    oc_remove_delayed_callback(context, find_ping);
    break;
  case CLOUD_MANAGER_FINISHED:
    oc_remove_delayed_callback(context, send_ping);
    break;
  default:
    return;
  }

  context->cloud_manager_status = CLOUD_MANAGER_RECONNECTING;
  oc_set_delayed_callback(context, callback_handler, 0);
  cloud_start_process(context);
}
#endif /* OC_SESSION_EVENTS */

static bool
st_check_cloud_connection(oc_endpoint_t *endpoint)
{
#ifdef OC_SECURITY
  return oc_tls_connected(endpoint);
#else
  return true;
#endif
}

int
st_cloud_manager_start(st_store_t *store_info, size_t device_index,
                       st_cloud_manager_cb_t cb)
{
  st_print_log("[ST_CM] st_cloud_manager_start in\n");
  if (!store_info || !cb)
    return -1;

  st_cloud_context_t *context =
    (st_cloud_context_t *)oc_memb_alloc(&st_cloud_context_s);
  if (!context)
    return -1;

  context->callback = cb;
  context->device_index = device_index;
  context->cloud_manager_status =
    (st_cloud_manager_status_t)store_info->cloudinfo.status;
  if (context->cloud_manager_status == CLOUD_MANAGER_RES_PUBLISHED)
    context->cloud_manager_status = CLOUD_MANAGER_SIGNED_UP;
  cloud_start_process(context);

#ifdef OC_SESSION_EVENTS
  if (oc_list_length(st_cloud_context_list) == 0) {
    oc_add_session_event_callback(session_event_handler);
  }
#endif /* OC_SESSION_EVENTS */
  oc_list_add(st_cloud_context_list, context);
  st_print_log("[ST_CM] st_cloud_manager_start success\n");
  return 0;
}

void
st_cloud_manager_stop(size_t device_index)
{
  st_print_log("[ST_CM] st_cloud_manager_stop in\n");
  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  while (context != NULL && context->device_index != device_index) {
    context = context->next;
  }
  if (!context) {
    st_print_log("[ST_CM] can't find any context regarding device(%zu)\n",
                 device_index);
    return;
  }

  if (context->cloud_manager_status == CLOUD_MANAGER_FINISHED)
    oc_remove_delayed_callback(context, send_ping);

  oc_list_remove(st_cloud_context_list, context);
  oc_memb_free(&st_cloud_context_s, context);
#ifdef OC_SESSION_EVENTS
  if (oc_list_length(st_cloud_context_list) == 0) {
    oc_remove_session_event_callback(session_event_handler);
  }
#endif /* OC_SESSION_EVENTS */
}

int
st_cloud_manager_check_connection(oc_string_t *ci_server)
{
  if (!ci_server)
    return -1;

  st_print_log("[ST_CM] check connection: %s\n", oc_string(*ci_server));
  oc_endpoint_t ep;

  return oc_string_to_endpoint(ci_server, &ep, NULL);
}

static bool
is_retry_over(st_cloud_context_t *context)
{
  if (context->retry_count < MAX_RETRY_COUNT)
    return false;

  if (context->cloud_manager_status != CLOUD_MANAGER_RECONNECTING) {
    context->cloud_manager_status = CLOUD_MANAGER_RECONNECTING;
    oc_set_delayed_callback(context, callback_handler, 0);
  }
#ifdef OC_TCP
  oc_connectivity_end_session(&context->cloud_ep);
#endif /* OC_TCP */
  cloud_start_process(context);
  return true;
}

static int
get_ci_error_code(oc_status_t response_code, int ci_code)
{
  int code = 0;
  switch (response_code) {
  case OC_STATUS_BAD_REQUEST:
    code = 400;
    break;
  case OC_STATUS_UNAUTHORIZED:
    code = 401;
    break;
  case OC_STATUS_FORBIDDEN:
    code = 403;
    break;
  case OC_STATUS_NOT_FOUND:
    code = 404;
    break;
  case OC_STATUS_INTERNAL_SERVER_ERROR:
    code = 500;
    break;
  default:
    break;
  }

  return (code * 10000 + ci_code);
}

static void
error_handler(st_cloud_context_t *context, oc_rep_t* res_payload,
  oc_status_t res_code, oc_trigger_t callback)
{
  int code;
  if (!oc_rep_get_int(res_payload, "code", &code))
    return;

  code = get_ci_error_code(res_code, code);
  char *message = NULL;
  size_t size;
  if (oc_rep_get_string(res_payload, "message", &message, &size))
    st_print_log("[ST_CM] ci message : %s (%d)\n", message, code);

  switch (code) {
  case CI_TOKEN_EXPIRED:
  case CI_TOKEN_REQEUST_EXPIRED:
    oc_remove_delayed_callback(context, callback);
    if (context->cloud_manager_status != CLOUD_MANAGER_RECONNECTING) {
      context->retry_count = 0;
      context->cloud_manager_status = CLOUD_MANAGER_RECONNECTING;
    }
    oc_set_delayed_callback(context, refresh_token,
                            session_timeout[context->retry_count]);
    break;
  case CI_DEVICE_NOT_FOUND:
    oc_remove_delayed_callback(context, callback);
    context->cloud_manager_status = CLOUD_MANAGER_RESETTING;
    oc_set_delayed_callback(context, callback_handler, 0);
    break;
  case CI_AUTHORIZATION_FAILED:
  case CI_CERTIFICATE_FAILED:
  case CI_UNAUTHORIZED_TOKEN:
  case CI_FORBIDDEN:
    oc_remove_delayed_callback(context, callback);
    context->cloud_manager_status = CLOUD_MANAGER_FAILED;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
    break;
  case CI_INTERNAL_SERVER_ERROR:
  default:
    break;
  }
}

static void
cloud_start_process(st_cloud_context_t *context)
{
  es_set_state(ES_STATE_REGISTERING_TO_CLOUD);
  context->retry_count = 0;

  st_store_t *store_info = st_store_get_info();
  if (store_info->cloudinfo.status == CLOUD_MANAGER_INITIALIZED) {
    oc_set_delayed_callback(context, sign_up, session_timeout[0]);
  } else {
    oc_set_delayed_callback(context, sign_in, session_timeout[0]);
  }
  _oc_signal_event_loop();
}

static void
sign_up_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[ST_CM] sign up handler(%d)\n", data->code);

  if (context->cloud_manager_status != CLOUD_MANAGER_INITIALIZED &&
      context->cloud_manager_status != CLOUD_MANAGER_RECONNECTING)
    return;

  oc_rep_t *payload = get_res_payload(data);

  if (data->code != OC_STATUS_CHANGED)
    goto error;

  char *token_value = NULL, *uri_value = NULL;
  size_t size;

  oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &token_value, &size);
  oc_rep_get_string(payload, REDIRECTURI_KEY, &uri_value, &size);

  if (!token_value || !uri_value) {
    goto error;
  }
  st_store_t *store_info = st_store_get_info();
  if (oc_string_len(store_info->cloudinfo.access_token) > 0)
    oc_free_string(&store_info->cloudinfo.access_token);
  oc_new_string(&store_info->cloudinfo.access_token, token_value,
                strlen(token_value));
  if (oc_string_len(store_info->cloudinfo.ci_server) > 0)
    oc_free_string(&store_info->cloudinfo.ci_server);
  oc_new_string(&store_info->cloudinfo.ci_server, uri_value, strlen(uri_value));
  store_info->cloudinfo.status = CLOUD_MANAGER_SIGNED_UP;
  st_store_dump_async();

  oc_remove_delayed_callback(context, sign_up);
  context->retry_count = 0;
  context->cloud_manager_status = CLOUD_MANAGER_SIGNED_UP;
  es_set_state(ES_STATE_REGISTERED_TO_CLOUD);
  free_res_payload(payload);
  return;

error:
  error_handler(data->user_data, payload, data->code, sign_up);
  free_res_payload(payload);
}

static oc_event_callback_retval_t
sign_up(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->cloud_manager_status == CLOUD_MANAGER_INITIALIZED ||
      context->cloud_manager_status == CLOUD_MANAGER_RECONNECTING) {
    st_print_log("[ST_CM] try sign up(%d)\n", context->retry_count);
    context->retry_count++;
    if (!is_retry_over(context)) {
      st_cloud_store_t cloudinfo = st_store_get_info()->cloudinfo;
      if (0 == oc_string_to_endpoint(&cloudinfo.ci_server, &context->cloud_ep,
                                     NULL)) {
        oc_sign_up(&context->cloud_ep, oc_string(cloudinfo.auth_provider),
                   oc_string(cloudinfo.uid), oc_string(cloudinfo.access_token),
                   context->device_index, sign_up_handler, context);
      }
      oc_set_delayed_callback(context, sign_up,
                              session_timeout[context->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static void
sign_in_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  oc_rep_t *payload = NULL;
  st_print_log("[ST_CM] sign in handler(%d)\n", data->code);

  if (context->cloud_manager_status != CLOUD_MANAGER_SIGNED_UP &&
      context->cloud_manager_status != CLOUD_MANAGER_RECONNECTING)
    return;
  if (data->code != OC_STATUS_CHANGED)
    goto error;

  oc_remove_delayed_callback(context, sign_in);
  context->retry_count = 0;
  context->cloud_manager_status = CLOUD_MANAGER_SIGNED_IN;

  st_store_t *store_info = st_store_get_info();
  if (store_info->cloudinfo.status != CLOUD_MANAGER_RES_PUBLISHED) {
    es_set_state(ES_STATE_PUBLISHING_RESOURCES_TO_CLOUD);
    oc_set_delayed_callback(context, set_dev_profile,
                            message_timeout[context->retry_count]);
  } else {
    es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
    oc_set_delayed_callback(context, find_ping,
                            message_timeout[context->retry_count]);
  }
  return;

error:
  payload = get_res_payload(data);
  error_handler(data->user_data, payload, data->code, sign_in);
  free_res_payload(payload);
}

static oc_event_callback_retval_t
sign_in(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->cloud_manager_status == CLOUD_MANAGER_SIGNED_UP ||
      context->cloud_manager_status == CLOUD_MANAGER_RECONNECTING) {
    st_print_log("[ST_CM] try sign in(%d)\n", context->retry_count);
    context->retry_count++;
    if (!is_retry_over(context)) {
      st_cloud_store_t cloudinfo = st_store_get_info()->cloudinfo;
      if (0 == oc_string_to_endpoint(&cloudinfo.ci_server, &context->cloud_ep,
                                     NULL)) {
        oc_sign_in(&context->cloud_ep, oc_string(cloudinfo.uid),
                   oc_string(cloudinfo.access_token), 0, sign_in_handler,
                   context);
      }
      oc_set_delayed_callback(context, sign_in,
                              session_timeout[context->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static void
refresh_token_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[ST_CM] refresh token handler(%d)\n", data->code);

  oc_rep_t *payload = get_res_payload(data);

  if (data->code != OC_STATUS_CHANGED)
    goto error;

  char *access_value, *refresh_value = NULL;
  size_t size;
  oc_rep_get_string(payload, ACCESS_TOKEN_KEY, &access_value, &size);
  oc_rep_get_string(payload, REFRESH_TOKEN_KEY, &refresh_value, &size);

  if (!access_value || !refresh_value) {
    goto error;
  }
  st_store_t *store_info = st_store_get_info();
  if (oc_string_len(store_info->cloudinfo.access_token) > 0)
    oc_free_string(&store_info->cloudinfo.access_token);
  oc_new_string(&store_info->cloudinfo.access_token, access_value,
                strlen(access_value));
  if (oc_string_len(store_info->cloudinfo.refresh_token) > 0)
    oc_free_string(&store_info->cloudinfo.refresh_token);
  oc_new_string(&store_info->cloudinfo.refresh_token, refresh_value,
                strlen(refresh_value));
  st_store_dump_async();

  oc_remove_delayed_callback(context, refresh_token);
  context->retry_count = 0;
  oc_set_delayed_callback(context, sign_in,
                          session_timeout[context->retry_count]);
  free_res_payload(payload);
  return;

error:
  error_handler(data->user_data, payload, data->code, refresh_token);
  free_res_payload(payload);
}

static oc_event_callback_retval_t
refresh_token(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[ST_CM] try refresh token(%d)\n", context->retry_count);
  context->retry_count++;
  if (!is_retry_over(context)) {
    st_cloud_store_t cloudinfo = st_store_get_info()->cloudinfo;
    oc_refresh_access_token(&context->cloud_ep, oc_string(cloudinfo.uid),
                            oc_string(cloudinfo.refresh_token),
                            context->device_index, refresh_token_handler,
                            context);
    oc_set_delayed_callback(context, refresh_token,
                            session_timeout[context->retry_count]);
  }

  return OC_EVENT_DONE;
}

static void
set_dev_profile_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  oc_rep_t *payload = NULL;
  st_print_log("[ST_CM] set dev profile handler(%d)\n", data->code);

  if (context->cloud_manager_status != CLOUD_MANAGER_SIGNED_IN)
    return;
  if (data->code != OC_STATUS_CHANGED)
    goto error;

  oc_remove_delayed_callback(context, set_dev_profile);
  context->retry_count = 0;
  context->cloud_manager_status = CLOUD_MANAGER_DEV_PUBLISHED;
  oc_set_delayed_callback(context, publish_resource,
                          message_timeout[context->retry_count]);
  return;

error:
  payload = get_res_payload(data);
  error_handler(data->user_data, payload, data->code, set_dev_profile);
  free_res_payload(payload);
}

static oc_event_callback_retval_t
set_dev_profile(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->cloud_manager_status == CLOUD_MANAGER_SIGNED_IN) {
    st_print_log("[ST_CM] try set dev profile(%d)\n", context->retry_count);
    context->retry_count++;
    if (!is_retry_over(context)) {
      if (st_check_cloud_connection(&context->cloud_ep))
        oc_set_device_profile(&context->cloud_ep, set_dev_profile_handler,
                              context);
      oc_set_delayed_callback(context, set_dev_profile,
                              message_timeout[context->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static void
publish_resource_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  oc_rep_t *payload = NULL;
  st_print_log("[ST_CM] publish resource handler(%d)\n", data->code);

  if (context->cloud_manager_status != CLOUD_MANAGER_DEV_PUBLISHED)
    return;
  if (data->code != OC_STATUS_CHANGED)
    goto error;

  oc_remove_delayed_callback(context, publish_resource);
  context->retry_count = 0;
  context->cloud_manager_status = CLOUD_MANAGER_RES_PUBLISHED;
  es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
  oc_set_delayed_callback(context, find_ping,
                          message_timeout[context->retry_count]);

  st_store_t *store_info = st_store_get_info();
  store_info->cloudinfo.status = CLOUD_MANAGER_RES_PUBLISHED;
  st_store_dump_async();
  return;

error:
  payload = get_res_payload(data);
  error_handler(data->user_data, payload, data->code, publish_resource);
  free_res_payload(payload);
}

static oc_event_callback_retval_t
publish_resource(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->cloud_manager_status == CLOUD_MANAGER_DEV_PUBLISHED) {
    st_print_log("[ST_CM] try publish resource(%d)\n", context->retry_count);
    context->retry_count++;
    if (!is_retry_over(context)) {
      if (st_check_cloud_connection(&context->cloud_ep))
        rd_publish_all(&context->cloud_ep, context->device_index,
                       publish_resource_handler, LOW_QOS, context);
      oc_set_delayed_callback(context, publish_resource,
                              message_timeout[context->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static void
find_ping_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[ST_CM] find ping handler(%d)\n", data->code);

  if (context->cloud_manager_status != CLOUD_MANAGER_SIGNED_IN &&
      context->cloud_manager_status != CLOUD_MANAGER_RES_PUBLISHED)
    return;

  oc_rep_t *payload = get_res_payload(data);

  if (data->code != OC_STATUS_OK)
    goto error;

  oc_remove_delayed_callback(context, find_ping);
  context->retry_count = 0;
  context->cloud_manager_status = CLOUD_MANAGER_FINISHED;

  int *interval = NULL;
  size_t size;

  oc_rep_get_int_array(payload, "inarray", &interval, &size);
  if (interval)
    g_ping_interval = interval[size - 1];
  oc_set_delayed_callback(context, callback_handler, 0);
  oc_set_delayed_callback(context, send_ping,
                          message_timeout[context->retry_count]);
  free_res_payload(payload);
  return;

error:
  error_handler(data->user_data, payload, data->code, find_ping);
  free_res_payload(payload);
}

static oc_event_callback_retval_t
find_ping(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->cloud_manager_status == CLOUD_MANAGER_SIGNED_IN ||
      context->cloud_manager_status == CLOUD_MANAGER_RES_PUBLISHED) {
    st_print_log("[ST_CM] try find ping(%d)\n", context->retry_count);
    context->retry_count++;
    if (!is_retry_over(context)) {
      if (st_check_cloud_connection(&context->cloud_ep))
        oc_find_ping_resource(&context->cloud_ep, find_ping_handler, context);
      oc_set_delayed_callback(context, find_ping,
                              message_timeout[context->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}

static void
send_ping_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  oc_rep_t *payload = NULL;
  st_print_log("[ST_CM] send ping handler(%d)\n", data->code);

  if (context->cloud_manager_status != CLOUD_MANAGER_FINISHED)
    return;
  if (data->code != OC_STATUS_NOT_MODIFIED)
    goto error;

  oc_remove_delayed_callback(context, send_ping);
  context->retry_count = 0;
  oc_set_delayed_callback(context, send_ping, g_ping_interval * ONE_MINUTE);
  return;

error:
  payload = get_res_payload(data);
  error_handler(data->user_data, payload, data->code, send_ping);
  free_res_payload(payload);
}

static oc_event_callback_retval_t
send_ping(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->cloud_manager_status == CLOUD_MANAGER_FINISHED) {
    st_print_log("[ST_CM] try send ping(%d)\n", context->retry_count);
    context->retry_count++;
    if (!is_retry_over(context)) {
      if (st_check_cloud_connection(&context->cloud_ep))
        oc_send_ping_request(&context->cloud_ep, g_ping_interval,
                             send_ping_handler, context);
      oc_set_delayed_callback(context, send_ping,
                              message_timeout[context->retry_count]);
    }
  }

  return OC_EVENT_DONE;
}
