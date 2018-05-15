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
#include "cloud_access.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "rd_client.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#define CONNECTION_CHECK_SERVER "coaps+tcp://samsung.com:5683" // TODO

#define AUTH_PROVIDER_GITHUB "github"
#define AUTH_PROVIDER_STCLOUD "https://us-auth2.samsungosp.com" // TODO

#define UID_KEY "uid"
#define ACCESS_TOKEN_KEY "accesstoken"
#define REDIRECTURI_KEY "redirecturi"

#define MAX_CONTEXT_SIZE (2)
#define RETRY_INTERVAL (5)
#define LIMIT_RETRY_SIGNING (5)

typedef enum {
  PUBLISH_CORE = 1 << 0,
  PUBLISH_USER_RESOURCES = 1 << 1,
  PUBLISH_DEV_PROFILE = 1 << 2
} publish_state_t;

typedef struct st_cloud_context
{
  struct st_cloud_context *next;
  st_cloud_access_cb_t callback;
  st_cloud_access_status_t cloud_access_status;
  oc_endpoint_t cloud_ep;
  oc_string_t auth_provider;
  oc_string_t uid;
  oc_string_t access_token;
  oc_string_t auth_code;
  oc_link_t *publish_resources;
  uint8_t publish_state;
  int device_index;
  uint8_t retry_count;
} st_cloud_context_t;

OC_LIST(st_cloud_context_list);
OC_MEMB(st_cloud_context_s, st_cloud_context_t, MAX_CONTEXT_SIZE);

static bool sign_up_process(st_cloud_context_t *context);
static void sign_up_handler(oc_client_response_t *data);
static void sign_in_handler(oc_client_response_t *data);
static void session_event_handler(const oc_endpoint_t *endpoint,
                                  oc_session_state_t state);
static oc_event_callback_retval_t find_ping(void *data);

bool
st_cloud_access_start(es_coap_cloud_conf_data *cloud_info,
                      sc_coap_cloud_server_conf_properties *st_cloud_info,
                      oc_link_t *publish_resources, int device_index,
                      st_cloud_access_cb_t cb)
{
  printf("[Cloud_Access] st_cloud_access_start in\n");
  if (!cloud_info || !publish_resources || !cb)
    return false;

  st_cloud_context_t *context =
    (st_cloud_context_t *)oc_memb_alloc(&st_cloud_context_s);
  if (!context)
    return false;

  context->callback = cb;
  context->cloud_access_status = CLOUD_ACCESS_INITIALIZE;
  context->device_index = device_index;
  context->publish_resources = publish_resources;

  oc_string_t ep_str;
  oc_new_string(&ep_str, oc_string(cloud_info->ci_server), oc_string_len(cloud_info->ci_server));

  if (oc_string_to_endpoint(&ep_str, &context->cloud_ep, NULL) != 0) {
    oc_free_string(&ep_str);
    goto errors;
  }
  oc_free_string(&ep_str);

  oc_new_string(&context->auth_provider, oc_string(cloud_info->auth_provider),
                oc_string_len(cloud_info->auth_provider));
  if (oc_string(cloud_info->auth_code)) {
    oc_new_string(&context->auth_code, oc_string(cloud_info->auth_code),
                  oc_string_len(cloud_info->auth_code));
  }
  if (oc_string(cloud_info->access_token)) {
    oc_new_string(&context->access_token, oc_string(cloud_info->access_token),
                  oc_string_len(cloud_info->access_token));
  }
  if (st_cloud_info && oc_string(st_cloud_info->uid)) {
    oc_new_string(&context->uid, oc_string(st_cloud_info->uid),
                  oc_string_len(st_cloud_info->uid));
  }

  printf("[Cloud_Access] sign up to %s\n", oc_string(cloud_info->ci_server));
  if (!sign_up_process(context)) {
    goto errors;
  }

  if (oc_list_length(st_cloud_context_list) == 0) {
    oc_add_session_event_callback(session_event_handler);
  }

  oc_list_add(st_cloud_context_list, context);
  printf("[Cloud_Access] st_cloud_access_start success\n");
  return true;

errors:
  es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
  oc_memb_free(&st_cloud_context_s, context);
  return false;
}

void
st_cloud_access_stop(int device_index)
{
  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  while (context != NULL && context->device_index != device_index) {
    context = context->next;
  }
  if (!context) {
    printf("[Cloud_Access] can't find any context regarding device(%d)\n",
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
  if (oc_string_len(context->auth_code) > 0) {
    oc_free_string(&context->auth_code);
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
    printf("[Cloud_Access] can't find any context regarding device(%d)\n",
           device_index);
    return CLOUD_ACCESS_FAIL;
  }

  return context->cloud_access_status;
}

bool
st_cloud_access_check_connection(const char *ci_server)
{
  oc_string_t dns_str;
  oc_new_string(&dns_str, CONNECTION_CHECK_SERVER,
                strlen(CONNECTION_CHECK_SERVER));

  oc_endpoint_t ep;
  if (oc_string_to_endpoint(&dns_str, &ep, NULL) != 0) {
    oc_free_string(&dns_str);
    return false;
  }
  oc_free_string(&dns_str);

  if (ci_server) {
    oc_new_string(&dns_str, ci_server, strlen(ci_server));

    if (oc_string_to_endpoint(&dns_str, &ep, NULL) != 0) {
      oc_free_string(&dns_str);
      return false;
    }
    oc_free_string(&dns_str);
  }

  return true;
}

static oc_event_callback_retval_t
callback_handler(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  context->callback(context->cloud_access_status);
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
re_sign_up(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->retry_count < LIMIT_RETRY_SIGNING) {
    printf("[Cloud_Access] retry sign-up(%d)\n", context->retry_count);
    if (!sign_up_process(context)) {
      printf("[Cloud_Access] retry sign-up failed\n");
      goto error;
    }
    context->retry_count++;
    return OC_EVENT_CONTINUE;
  }
  printf("[Cloud_Access] retry sign-up count over\n");

error:
  // TODO : right error handling.
  context->cloud_access_status = CLOUD_ACCESS_FAIL;
  es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
  oc_set_delayed_callback(context, callback_handler, 0);
  return OC_EVENT_DONE;
}

static bool
sign_up_process(st_cloud_context_t *context)
{
  if (strncmp(oc_string(context->auth_provider), AUTH_PROVIDER_GITHUB,
              strlen(AUTH_PROVIDER_GITHUB)) == 0) {
    es_set_state(ES_STATE_REGISTERING_TO_CLOUD);

    if (!oc_sign_up_with_auth(
          &context->cloud_ep, oc_string(context->auth_provider),
          oc_string(context->auth_code), 0, sign_up_handler, context)) {
      goto retry;
    }
  } else if (strncmp(oc_string(context->auth_provider), AUTH_PROVIDER_STCLOUD,
                     strlen(AUTH_PROVIDER_STCLOUD)) == 0) {
    es_set_state(ES_STATE_REGISTERING_TO_CLOUD);
    printf("[Cloud_Access] auth_provider : %s\n",
           oc_string(context->auth_provider));
    printf("[Cloud_Access] uid : %s\n", oc_string(context->uid));
    printf("[Cloud_Access] access_token : %s\n",
           oc_string(context->access_token));
    if (!oc_sign_up(&context->cloud_ep, oc_string(context->auth_provider),
                    oc_string(context->uid), oc_string(context->access_token),
                    context->device_index, sign_up_handler, context)) {
      goto retry;
    }
  } else {
    return false;
  }
  return true;

retry:
  if (context->retry_count == 0) {
    oc_set_delayed_callback(context, re_sign_up, RETRY_INTERVAL);
    _oc_signal_event_loop();
  }
  return true;
}

static oc_event_callback_retval_t
re_sign_in(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->retry_count < LIMIT_RETRY_SIGNING) {
    printf("[Cloud_Access] sign in(%d) with\n", context->retry_count);
    printf("[Cloud_Access]  - uid: %s\n", oc_string(context->uid));
    printf("[Cloud_Access]  - accesstoken: %s\n",
           oc_string(context->access_token));
    oc_sign_in(&context->cloud_ep, oc_string(context->uid),
               oc_string(context->access_token), 0, sign_in_handler, context);
    context->retry_count++;
    return OC_EVENT_CONTINUE;
  }
  printf("[Cloud_Access] retry sign-in count over\n");

  // TODO : right error handling.
  context->cloud_access_status = CLOUD_ACCESS_FAIL;
  es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
  oc_set_delayed_callback(context, callback_handler, 0);
  return OC_EVENT_DONE;
}

static void
session_event_handler(const oc_endpoint_t *endpoint, oc_session_state_t state)
{
  OC_LOGipaddr(*endpoint);
  printf("st_cloud_context_list size : %d\n",
         oc_list_length(st_cloud_context_list));
  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  OC_LOGipaddr(context->cloud_ep);
  while (context != NULL && context->device_index != endpoint->device) {
    context = context->next;
  }

  if (context) {
    if (state == OC_SESSION_CONNECTED) {
      printf("[Cloud_Access] session connected.(%d)\n",
             context->cloud_access_status);
      if (context->cloud_access_status == CLOUD_ACCESS_DISCONNECTED) {
        context->cloud_access_status = CLOUD_ACCESS_RE_CONNECTING;
      }
    } else if (state == OC_SESSION_DISCONNECTED) {
      printf("[Cloud_Access] session disconnected.(%d)\n",
             context->cloud_access_status);
      if (context->cloud_access_status == CLOUD_ACCESS_INITIALIZE) {
        if (context->retry_count == 0) {
          oc_set_delayed_callback(context, re_sign_up, RETRY_INTERVAL);
        }
      } else {
        if (context->cloud_access_status == CLOUD_ACCESS_FINISH) {
          context->cloud_access_status = CLOUD_ACCESS_DISCONNECTED;
        }
        if (context->retry_count == 0) {
          oc_set_delayed_callback(context, re_sign_in, RETRY_INTERVAL);
        }
      }
    }
  }
}

static bool
is_resource_publish_finish(st_cloud_context_t *context)
{
  if (context->publish_state & PUBLISH_CORE &&
      context->publish_state & PUBLISH_USER_RESOURCES &&
      context->publish_state & PUBLISH_DEV_PROFILE) {
    return true;
  }
  return false;
}

static void
common_publish_handler(oc_client_response_t *data, publish_state_t state)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
    printf("[Cloud_Access] %s resources publish success.\n",
           state == PUBLISH_CORE ? "core" : state == PUBLISH_USER_RESOURCES
                                              ? "user"
                                              : "dev profile");
    context->publish_state |= state;
    if (is_resource_publish_finish(context)) {
      context->cloud_access_status = CLOUD_ACCESS_PUBLISHED;
      es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, find_ping, 0);
    }
  } else {
    printf("[Cloud_Access] %s resource publish failed(%d)!!\n",
           state == PUBLISH_CORE ? "core" : state == PUBLISH_USER_RESOURCES
                                              ? "user"
                                              : "dev profile",
           data->code);
    if (context->cloud_access_status != CLOUD_ACCESS_FAIL) {
      // TODO : re-publish?
      context->cloud_access_status = CLOUD_ACCESS_FAIL;
      es_set_state(ES_STATE_FAILED_TO_PUBLISH_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, callback_handler, 0);
    }
  }
}

static void
core_publish_handler(oc_client_response_t *data)
{
  common_publish_handler(data, PUBLISH_CORE);
}

static void
user_resources_publish_handler(oc_client_response_t *data)
{
  common_publish_handler(data, PUBLISH_USER_RESOURCES);
}

static void
dev_profile_publish_handler(oc_client_response_t *data)
{
  common_publish_handler(data, PUBLISH_DEV_PROFILE);
}

static void
sign_in_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
    if (context->retry_count > 0) {
      oc_remove_delayed_callback(context, re_sign_in);
      context->retry_count = 0;
    }

    if (context->cloud_access_status == CLOUD_ACCESS_RE_CONNECTING) {
      es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, find_ping, 0);
    } else if (context->cloud_access_status == CLOUD_ACCESS_SIGNED_UP) {
      printf("[Cloud_Access] sign in success.\n");
      es_set_state(ES_STATE_PUBLISHING_RESOURCES_TO_CLOUD);
      context->publish_state = 0;

      printf("[Cloud_Access] Core resource publish start.\n");
      rd_publish(&context->cloud_ep, NULL, context->device_index,
                 core_publish_handler, LOW_QOS, context);

      printf("[Cloud_Access] User resources publish start.\n");
      rd_publish(&context->cloud_ep, context->publish_resources,
                 context->device_index, user_resources_publish_handler, LOW_QOS,
                 context);

      printf("[Cloud_Access] Dev profile publish start.\n");
      rd_publish_dev_profile(&context->cloud_ep, dev_profile_publish_handler,
                             LOW_QOS, context);
    }
  } else {
    printf("[Cloud_Access] Sign in failed!!\n");
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    if (context->retry_count == 0) {
      oc_set_delayed_callback(context, re_sign_in, RETRY_INTERVAL);
    }
  }
}

static void
sign_up_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
    printf("[Cloud_Access] sign up success.\n");
    oc_rep_t *rep = data->payload;
    while (rep != NULL) {
      printf("[Cloud_Access]  - %s: ", oc_string(rep->name));
      switch (rep->type) {
      case OC_REP_BOOL:
        printf("%d\n", rep->value.boolean);
        break;
      case OC_REP_INT:
        printf("%d\n", rep->value.integer);
        break;
      case OC_REP_STRING:
        printf("%s\n", oc_string(rep->value.string));
        if (strncmp(UID_KEY, oc_string(rep->name), oc_string_len(rep->name)) ==
            0) {
          if (!oc_string(context->uid)) {
            oc_new_string(&context->uid, oc_string(rep->value.string),
                          oc_string_len(rep->value.string));
          } else {
            if (oc_string_len(context->uid) !=
                  oc_string_len(rep->value.string) ||
                strncmp(oc_string(context->uid), oc_string(rep->value.string),
                        oc_string_len(context->uid)) != 0) {
              printf("[Cloud_Access] different uid from cloud.\n");
              goto error;
            }
          }
        } else if (strncmp(ACCESS_TOKEN_KEY, oc_string(rep->name),
                           oc_string_len(rep->name)) == 0) {
          oc_new_string(&context->access_token, oc_string(rep->value.string),
                        oc_string_len(rep->value.string));
        } else if (strncmp(REDIRECTURI_KEY, oc_string(rep->name),
                           oc_string_len(rep->name)) == 0) {
          if (oc_string_to_endpoint(&rep->value.string, &context->cloud_ep,
                                    NULL) != 0) {
            printf("[Cloud_Access] invalid redirect server address.\n");
            goto error;
          }
        }
        break;
      default:
        printf("NULL\n");
        break;
      }
      rep = rep->next;
    }

    if (oc_string_len(context->uid) > 0 &&
        oc_string_len(context->access_token) > 0) {
      context->cloud_access_status = CLOUD_ACCESS_SIGNED_UP;
      if (context->retry_count > 0) {
        oc_remove_delayed_callback(context, re_sign_up);
        context->retry_count = 0;
      }
      es_set_state(ES_STATE_REGISTERED_TO_CLOUD);
    } else {
      goto error;
    }
  } else {
    printf("[Cloud_Access] Sign up failed!!\n");
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    if (context->retry_count == 0) {
      oc_set_delayed_callback(context, re_sign_up, RETRY_INTERVAL);
    }
  }

  return;

error:
  context->cloud_access_status = CLOUD_ACCESS_FAIL;
  es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
  oc_set_delayed_callback(context, callback_handler, 0);
}

static void
send_ping_handler(oc_client_response_t *data)
{
  if (data->code != OC_STATUS_NOT_MODIFIED) {
    st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
  }
}

static oc_event_callback_retval_t
send_ping(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  if (CLOUD_ACCESS_FAIL == context->cloud_access_status)
    return OC_EVENT_DONE;

  printf("[Cloud_Access] Send ping request.\n");
  if (oc_send_ping_request(&context->cloud_ep, 8, send_ping_handler, context))
    return OC_EVENT_CONTINUE;

  return OC_EVENT_DONE;
}

static void
find_ping_handler(oc_client_response_t *data)
{
  if (data->code == OC_STATUS_OK) {
    st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
    context->cloud_access_status = CLOUD_ACCESS_FINISH;
    oc_set_delayed_callback(context, callback_handler, 0);
    oc_set_delayed_callback(context, send_ping, 50);
  }
}

static oc_event_callback_retval_t
find_ping(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (CLOUD_ACCESS_PUBLISHED == context->cloud_access_status ||
      CLOUD_ACCESS_RE_CONNECTING == context->cloud_access_status) {
    printf("[Cloud_Access] Find ping resource.\n");
    oc_find_ping_resource(&context->cloud_ep, find_ping_handler, context);
  }
  return OC_EVENT_DONE;
}