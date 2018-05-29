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

#include "st_cloud_access.h"
#include "easysetup.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "rd_client.h"
#include "st_port.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#define UID_KEY "uid"
#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"

#define ONE_MINUTE (56)
#define MAX_CONTEXT_SIZE (2)
#define MAX_RETRY_COUNT (5)

static int session_timeout[5] = { 3, 50, 50, 50, 10 };
static int message_timeout[5] = { 1, 2, 4, 8, 10 };

typedef struct st_cloud_context
{
  struct st_cloud_context *next;
  st_cloud_access_cb_t callback;
  oc_endpoint_t cloud_ep;
  oc_string_t auth_provider;
  oc_string_t uid;
  oc_string_t access_token;
  oc_string_t refresh_token;
  int device_index;
  st_cloud_access_status_t cloud_access_status;
  uint8_t retry_count;
} st_cloud_context_t;

OC_LIST(st_cloud_context_list);
OC_MEMB(st_cloud_context_s, st_cloud_context_t, MAX_CONTEXT_SIZE);

static bool cloud_start_process(st_cloud_context_t *context);
static oc_event_callback_retval_t sign_up(void *data);
static oc_event_callback_retval_t sign_in(void *data);
static oc_event_callback_retval_t refresh_token(void *data);
static oc_event_callback_retval_t set_dev_profile(void *data);
static oc_event_callback_retval_t publish_resource(void *data);
static oc_event_callback_retval_t find_ping(void *data);
static oc_event_callback_retval_t send_ping(void *data);

static int ping_interval = 1;

static void
session_event_handler(const oc_endpoint_t *endpoint, oc_session_state_t state)
{
  st_print_log("[Cloud_Access] session state(%d)\n", state);
  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  while (context != NULL && context->device_index != endpoint->device) {
    context = context->next;
  }

  if (context && state == OC_SESSION_DISCONNECTED) {
    if (context->cloud_access_status == CLOUD_ACCESS_FINISH) {
      oc_remove_delayed_callback(context, send_ping);
      context->cloud_access_status = CLOUD_ACCESS_RE_CONNECTING;
    }

    cloud_start_process(context);
  }
}

int
st_cloud_access_start(st_store_t *cloud_info, int device_index,
                      st_cloud_access_cb_t cb)
{
  st_print_log("[Cloud_Access] st_cloud_access_start in\n");
  if (!cloud_info || !cb)
    return -1;

  st_cloud_context_t *context =
    (st_cloud_context_t *)oc_memb_alloc(&st_cloud_context_s);
  if (!context)
    return -1;

  context->callback = cb;
  if (cloud_info->cloudinfo.status & CLOUD_ACCESS_PUBLISHED)
    context->cloud_access_status = CLOUD_ACCESS_RE_CONNECTING;
  else if (cloud_info->cloudinfo.status & CLOUD_ACCESS_SIGNED_UP)
    context->cloud_access_status = CLOUD_ACCESS_SIGNED_UP;
  else
    context->cloud_access_status = CLOUD_ACCESS_INITIALIZE;
  context->device_index = device_index;

  if (oc_string_to_endpoint(&cloud_info->cloudinfo.ci_server,
                            &context->cloud_ep, NULL) != 0) {
    goto errors;
  }

  oc_new_string(&context->auth_provider,
                oc_string(cloud_info->cloudinfo.auth_provider),
                oc_string_len(cloud_info->cloudinfo.auth_provider));
  oc_new_string(&context->access_token,
                oc_string(cloud_info->cloudinfo.access_token),
                oc_string_len(cloud_info->cloudinfo.access_token));
  oc_new_string(&context->refresh_token,
                oc_string(cloud_info->cloudinfo.refresh_token),
                oc_string_len(cloud_info->cloudinfo.refresh_token));
  oc_new_string(&context->uid, oc_string(cloud_info->cloudinfo.uid),
                oc_string_len(cloud_info->cloudinfo.uid));

  if (!cloud_start_process(context)) {
    goto errors;
  }

  if (oc_list_length(st_cloud_context_list) == 0) {
    oc_add_session_event_callback(session_event_handler);
  }

  oc_list_add(st_cloud_context_list, context);
  st_print_log("[Cloud_Access] st_cloud_access_start success\n");
  return 0;

errors:
  es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
  oc_memb_free(&st_cloud_context_s, context);
  return -1;
}

void
st_cloud_access_stop(int device_index)
{
  st_print_log("[Cloud_Access] st_cloud_access_stop in\n");
  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  while (context != NULL && context->device_index != device_index) {
    context = context->next;
  }
  if (!context) {
    st_print_log("[Cloud_Access] can't find any context regarding device(%d)\n",
                 device_index);
    return;
  }

  oc_list_remove(st_cloud_context_list, context);

  if (oc_string_len(context->auth_provider) > 0) {
    oc_free_string(&context->auth_provider);
  }
  if (oc_string_len(context->uid) > 0) {
    oc_free_string(&context->uid);
  }
  if (oc_string_len(context->access_token) > 0) {
    oc_free_string(&context->access_token);
  }
  if (oc_string_len(context->refresh_token) > 0) {
    oc_free_string(&context->refresh_token);
  }
  oc_memb_free(&st_cloud_context_s, context);

  if (oc_list_length(st_cloud_context_list) == 0) {
    oc_remove_session_event_callback(session_event_handler);
  }
}

st_cloud_access_status_t
get_cloud_access_status(int device_index)
{
  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  while (context != NULL && context->device_index != device_index) {
    context = context->next;
  }
  if (!context) {
    st_print_log("[Cloud_Access] can't find any context regarding device(%d)\n",
                 device_index);
    return CLOUD_ACCESS_FAIL;
  }

  return context->cloud_access_status;
}

int
st_cloud_access_check_connection(const char *ci_server)
{
  st_print_log("[st_cloud_access_check_connection] ci_server %s\n", ci_server);
  if (!ci_server)
    return -1;

  oc_string_t dns_str;
  oc_new_string(&dns_str, ci_server, strlen(ci_server));

  oc_endpoint_t ep;
  int ret = oc_string_to_endpoint(&dns_str, &ep, NULL);
  oc_free_string(&dns_str);

  return ret;
}

static oc_event_callback_retval_t
callback_handler(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  context->callback(context->cloud_access_status);

  return OC_EVENT_DONE;
}

static bool
cloud_start_process(st_cloud_context_t *context)
{
  es_set_state(ES_STATE_REGISTERING_TO_CLOUD);
  st_print_log("[Cloud_Access] auth_provider : %s\n",
               oc_string(context->auth_provider));
  st_print_log("[Cloud_Access] uid : %s\n", oc_string(context->uid));
  st_print_log("[Cloud_Access] access_token : %s\n",
               oc_string(context->access_token));

  if (context->cloud_access_status == CLOUD_ACCESS_RE_CONNECTING ||
      context->cloud_access_status == CLOUD_ACCESS_SIGNED_UP) {
    oc_set_delayed_callback(context, sign_in, session_timeout[0]);
  } else {
    oc_set_delayed_callback(context, sign_up, session_timeout[0]);
  }
  _oc_signal_event_loop();

  return true;
}

static void
sign_up_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[Cloud_Access] sign up handler(%d)\n", data->code);

  if (data->code != OC_STATUS_CHANGED) {
    goto error;
  }

  oc_rep_t *rep = data->payload;
  char *value = NULL;
  int size;
  if (oc_rep_get_string(rep, UID_KEY, &value, &size)) {
    if (!oc_string(context->uid)) {
      oc_new_string(&context->uid, value, size);
    } else {
      if ((int)oc_string_len(context->uid) != size ||
          strncmp(oc_string(context->uid), value, size) != 0) {
        st_print_log("[Cloud_Access] different uid from cloud.\n");
        goto error;
      }
    }
  }
  if (oc_rep_get_string(rep, ACCESS_TOKEN_KEY, &value, &size)) {
    if (oc_string_len(context->access_token) > 0)
      oc_free_string(&context->access_token);
    oc_new_string(&context->access_token, value, size);
  }
  if (oc_rep_get_string(rep, REDIRECTURI_KEY, &value, &size)) {
    oc_string_t re_uri;
    oc_new_string(&re_uri, value, size);
    int ret = oc_string_to_endpoint(&re_uri, &context->cloud_ep, NULL);
    oc_free_string(&re_uri);

    if (ret != 0) {
      st_print_log("[Cloud_Access] invalid redirect server address.\n");
      goto error;
    }
  }

  if (oc_string_len(context->uid) == 0 ||
      oc_string_len(context->access_token) == 0) {
    goto error;
  }

  oc_remove_delayed_callback(context, sign_up);
  context->retry_count = 0;
  context->cloud_access_status = CLOUD_ACCESS_SIGNED_UP;
  es_set_state(ES_STATE_REGISTERED_TO_CLOUD);

  return;

error:
  if (context->retry_count < MAX_RETRY_COUNT - 1)
    return;
  oc_remove_delayed_callback(context, sign_up);
  context->cloud_access_status = CLOUD_ACCESS_FAIL;
  es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
  oc_set_delayed_callback(context, callback_handler, 0);
}

static oc_event_callback_retval_t
sign_up(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[Cloud_Access] try sign up(%d)\n", context->retry_count++);

  if (context->retry_count < MAX_RETRY_COUNT) {
    oc_sign_up(&context->cloud_ep, oc_string(context->auth_provider),
               oc_string(context->uid), oc_string(context->access_token),
               context->device_index, sign_up_handler, context);
    oc_set_delayed_callback(context, sign_up,
                            session_timeout[context->retry_count]);
  } else {
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}

static void
sign_in_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[Cloud_Access] sign in handler(%d)\n", data->code);

  if (data->code == OC_STATUS_CHANGED) {
    oc_remove_delayed_callback(context, sign_in);
    context->retry_count = 0;

    if (context->cloud_access_status == CLOUD_ACCESS_RE_CONNECTING) {
      es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, find_ping,
                              message_timeout[context->retry_count]);
    } else {
      es_set_state(ES_STATE_PUBLISHING_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, set_dev_profile,
                              message_timeout[context->retry_count]);
    }
    context->cloud_access_status = CLOUD_ACCESS_SIGNED_IN;
  } else {
    int code;
    if (oc_rep_get_int(data->payload, "code", &code)) {
      if (code == 4 && data->code == OC_STATUS_BAD_REQUEST) {
        context->retry_count = 0;
        oc_set_delayed_callback(context, refresh_token,
                                session_timeout[context->retry_count]);
      }
    }
    if (context->retry_count < MAX_RETRY_COUNT - 1)
      return;
    oc_remove_delayed_callback(context, sign_in);
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }
}

static oc_event_callback_retval_t
sign_in(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[Cloud_Access] try sign in(%d)\n", context->retry_count++);

  if (context->retry_count < MAX_RETRY_COUNT) {
    oc_sign_in(&context->cloud_ep, oc_string(context->uid),
               oc_string(context->access_token), 0, sign_in_handler, context);
    oc_set_delayed_callback(context, sign_in,
                            session_timeout[context->retry_count]);
  } else {
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}

static void
refresh_token_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[Cloud_Access] refresh token handler(%d)\n", data->code);

  if (data->code != OC_STATUS_CHANGED)
    goto error;

  char *value = NULL;
  int size;
  if (oc_rep_get_string(data->payload, ACCESS_TOKEN_KEY, &value, &size)) {
    if (oc_string_len(context->access_token) > 0)
      oc_free_string(&context->access_token);
    oc_new_string(&context->access_token, value, size);
  }
  if (oc_rep_get_string(data->payload, REFRESH_TOKEN_KEY, &value, &size)) {
    if (oc_string_len(context->refresh_token) > 0)
      oc_free_string(&context->refresh_token);
    oc_new_string(&context->refresh_token, value, size);
  }
  if (oc_string_len(context->access_token) == 0 ||
      oc_string_len(context->refresh_token) == 0)
    goto error;

  oc_remove_delayed_callback(context, refresh_token);
  context->retry_count = 0;
  oc_set_delayed_callback(context, sign_in,
                          session_timeout[context->retry_count]);

  return;

error:
  if (context->retry_count < MAX_RETRY_COUNT - 1)
    return;
  oc_remove_delayed_callback(context, refresh_token);
  context->cloud_access_status = CLOUD_ACCESS_FAIL;
  es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
  oc_set_delayed_callback(context, callback_handler, 0);
}

static oc_event_callback_retval_t
refresh_token(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[Cloud_Access] try refresh token(%d)\n",
               context->retry_count++);

  if (context->retry_count < MAX_RETRY_COUNT) {
    oc_refresh_access_token(&context->cloud_ep, oc_string(context->uid),
                            oc_string(context->refresh_token),
                            context->device_index, refresh_token_handler,
                            context);
    oc_set_delayed_callback(context, sign_in,
                            session_timeout[context->retry_count]);
  } else {
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}

static void
set_dev_profile_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[Cloud_Access] set dev profile handler(%d)\n", data->code);

  if (data->code == OC_STATUS_CHANGED) {
    oc_remove_delayed_callback(context, set_dev_profile);
    context->retry_count = 0;
    oc_set_delayed_callback(context, publish_resource,
                            message_timeout[context->retry_count]);
  } else {
    if (context->retry_count < MAX_RETRY_COUNT - 1)
      return;
    oc_remove_delayed_callback(context, sign_in);
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }
}

static oc_event_callback_retval_t
set_dev_profile(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[Cloud_Access] try set dev profile(%d)\n",
               context->retry_count++);

  if (context->retry_count < MAX_RETRY_COUNT) {
    oc_set_device_profile(&context->cloud_ep, set_dev_profile_handler, context);
    oc_set_delayed_callback(context, set_dev_profile,
                            message_timeout[context->retry_count]);
  } else {
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}

static void
publish_resource_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[Cloud_Access] publish resource handler(%d)\n", data->code);

  if (data->code == OC_STATUS_CHANGED) {
    oc_remove_delayed_callback(context, publish_resource);
    context->retry_count = 0;
    context->cloud_access_status = CLOUD_ACCESS_PUBLISHED;
    es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
    oc_set_delayed_callback(context, find_ping,
                            message_timeout[context->retry_count]);
  } else {
    if (context->retry_count < MAX_RETRY_COUNT - 1)
      return;
    oc_remove_delayed_callback(context, publish_resource);
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }
}

static oc_event_callback_retval_t
publish_resource(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[Cloud_Access] try publish resource(%d)\n",
               context->retry_count++);

  if (context->retry_count < MAX_RETRY_COUNT) {
    rd_publish_all(&context->cloud_ep, context->device_index,
                   publish_resource_handler, LOW_QOS, context);
    oc_set_delayed_callback(context, publish_resource,
                            message_timeout[context->retry_count]);
  } else {
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}

static void
find_ping_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[Cloud_Access] find ping handler(%d)\n", data->code);

  if (data->code == OC_STATUS_OK) {
    oc_remove_delayed_callback(context, find_ping);
    context->retry_count = 0;
    context->cloud_access_status = CLOUD_ACCESS_FINISH;

    int *interval = NULL, size;
    oc_rep_get_int_array(data->payload, "inarray", &interval, &size);
    if (interval)
      ping_interval = interval[size - 1];
    oc_set_delayed_callback(context, callback_handler, 0);
    oc_set_delayed_callback(context, send_ping,
                            message_timeout[context->retry_count]);
  } else {
    if (context->retry_count < MAX_RETRY_COUNT - 1)
      return;
    oc_remove_delayed_callback(context, find_ping);
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }
}

static oc_event_callback_retval_t
find_ping(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[Cloud_Access] try find ping(%d)\n", context->retry_count++);

  if (context->retry_count < MAX_RETRY_COUNT) {
    if (context->cloud_access_status == CLOUD_ACCESS_SIGNED_IN ||
        context->cloud_access_status == CLOUD_ACCESS_PUBLISHED) {
      oc_find_ping_resource(&context->cloud_ep, find_ping_handler, context);
      oc_set_delayed_callback(context, find_ping,
                              message_timeout[context->retry_count]);
    }
  } else {
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}

static void
send_ping_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
  st_print_log("[Cloud_Access] send ping handler(%d)\n", data->code);

  if (data->code == OC_STATUS_NOT_MODIFIED) {
    oc_remove_delayed_callback(context, send_ping);
    context->retry_count = 0;
    oc_set_delayed_callback(context, send_ping, ping_interval * ONE_MINUTE);
  } else {
    if (context->retry_count < MAX_RETRY_COUNT - 1)
      return;
    oc_remove_delayed_callback(context, send_ping);
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }
}

static oc_event_callback_retval_t
send_ping(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  st_print_log("[Cloud_Access] try send ping(%d)\n", context->retry_count++);

  if (context->retry_count < MAX_RETRY_COUNT) {
    if (context->cloud_access_status == CLOUD_ACCESS_FINISH) {
      oc_send_ping_request(&context->cloud_ep, ping_interval, send_ping_handler,
                           context);
      oc_set_delayed_callback(context, send_ping,
                              message_timeout[context->retry_count]);
    }
  } else {
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, callback_handler, 0);
  }

  return OC_EVENT_DONE;
}
