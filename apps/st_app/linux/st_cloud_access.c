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
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "rd_client.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#define AUTH_PROVIDER_GITHUB "github"
#define AUTH_PROVIDER_STCLOUD "https://us-auth2.samsungosp.com" // TODO

#define UID_KEY "uid"
#define ACCESS_TOKEN_KEY "accesstoken"

#define MAX_CONTEXT_SIZE (2)
#define RETRY_INTERVAL (10)
#define LIMIT_RETRY_SIGNING (2)

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
  oc_string_t uid;
  oc_string_t access_token;
  oc_link_t *publish_resources;
  uint8_t publish_state;
  int device_index;
  uint8_t retry_count;
} st_cloud_context_t;

OC_LIST(st_cloud_context_list);
OC_MEMB(st_cloud_context_s, st_cloud_context_t, MAX_CONTEXT_SIZE);

static void sign_up_handler(oc_client_response_t *data);
static void session_event_handler(const oc_endpoint_t *endpoint,
                                  oc_session_state_t state);
static void find_ping_handler(oc_client_response_t *data);

bool
st_cloud_access_start(es_coap_cloud_conf_data *cloud_info,
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
  oc_new_string(&ep_str, cloud_info->ci_server, strlen(cloud_info->ci_server));

  if (oc_string_to_endpoint(&ep_str, &context->cloud_ep, NULL) != 0) {
    oc_free_string(&ep_str);
    goto errors;
  }
  oc_free_string(&ep_str);

  printf("[Cloud_Access] sign up to %s\n", cloud_info->ci_server);
  if (strncmp(cloud_info->auth_provider, AUTH_PROVIDER_GITHUB,
              strlen(AUTH_PROVIDER_GITHUB)) == 0) {
    es_set_state(ES_STATE_REGISTERING_TO_CLOUD);
    oc_sign_up_with_auth(&context->cloud_ep, cloud_info->auth_provider,
                         cloud_info->auth_code, 0, sign_up_handler, context);
  } else if (strncmp(cloud_info->auth_provider, AUTH_PROVIDER_STCLOUD,
                     strlen(AUTH_PROVIDER_STCLOUD)) == 0) {
    char device_id[100];
    oc_uuid_to_str(oc_core_get_device_id(device_index), device_id,
                   MAX_UUID_LENGTH);
    es_set_state(ES_STATE_REGISTERING_TO_CLOUD);
    oc_sign_up(&context->cloud_ep, cloud_info->auth_provider, device_id,
               cloud_info->access_token, device_index, sign_up_handler,
               context);
  } else {
    goto errors;
  }

  if (oc_list_length(st_cloud_context_list) == 0) {
    oc_add_session_event_callback(session_event_handler);
  }

  context->cloud_access_status = CLOUD_ACCESS_PROCRESSING;
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

static oc_event_callback_retval_t
callback_handler(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  if (CLOUD_ACCESS_FINISH == context->cloud_access_status) {
    printf("[Cloud_Access] Find ping resource.\n");
    oc_find_ping_resource(&context->cloud_ep, find_ping_handler, context);
  }
  context->callback(context->cloud_access_status);
  return OC_EVENT_DONE;
}

static void
re_sign_in_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
    printf("[Cloud_Access] sign in success.\n");
    context->cloud_access_status = CLOUD_ACCESS_FINISH;
    es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
    oc_set_delayed_callback(context, &callback_handler, 0);
  } else {
    printf("[Cloud Access] Sign in failed!!\n");
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, &callback_handler, 0);
  }
}

static oc_event_callback_retval_t
re_connect_cloud(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;

  if (context->retry_count < LIMIT_RETRY_SIGNING) {
    printf("[Cloud Access] retry sign-in(%d)\n", context->retry_count);
    oc_sign_in(&context->cloud_ep, oc_string(context->uid),
               oc_string(context->access_token), 0, re_sign_in_handler,
               context);
    context->retry_count++;
    return OC_EVENT_CONTINUE;
  } else {
    printf("[Cloud Access] retry sign-in count over\n");
    st_cloud_access_stop(context->device_index);
    // TODO : right error handling.
  }

  return OC_EVENT_DONE;
}

static void
session_event_handler(const oc_endpoint_t *endpoint, oc_session_state_t state)
{
  OC_LOGipaddr(*endpoint);
  st_cloud_context_t *context = oc_list_head(st_cloud_context_list);
  while (context != NULL &&
         oc_endpoint_compare(&context->cloud_ep, endpoint) != 0) {
    OC_LOGipaddr(context->cloud_ep);
    context = context->next;
  }
  if (!context) {
    return;
  }

  if (state == OC_SESSION_CONNECTED) {
    context->cloud_access_status = CLOUD_ACCESS_PROCRESSING;
  } else if (state == OC_SESSION_DISCONNECTED) {
    context->cloud_access_status = CLOUD_ACCESS_DISCONNECTED;
    context->retry_count = 0;
    oc_set_delayed_callback(context, &callback_handler, 0);
    oc_set_delayed_callback(context, &re_connect_cloud, RETRY_INTERVAL);
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
core_publish_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
    printf("[Cloud_Access] core resources publish success.\n");
    context->publish_state |= PUBLISH_CORE;
    if (is_resource_publish_finish(context)) {
      context->cloud_access_status = CLOUD_ACCESS_FINISH;
      es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, &callback_handler, 0);
    }
  } else {
    printf("[Cloud Access] core resource publish failed!!\n");
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_PUBLISH_RESOURCES_TO_CLOUD);
    oc_set_delayed_callback(context, &callback_handler, 0);
  }
}

static void
user_resources_publish_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
    printf("[Cloud_Access] user resources publish success.\n");
    context->publish_state |= PUBLISH_USER_RESOURCES;
    if (is_resource_publish_finish(context)) {
      context->cloud_access_status = CLOUD_ACCESS_FINISH;
      es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, &callback_handler, 0);
    }
  } else {
    printf("[Cloud Access] user resources publish failed!!\n");
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_PUBLISH_RESOURCES_TO_CLOUD);
    oc_set_delayed_callback(context, &callback_handler, 0);
  }
}

static void
dev_profile_publish_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
    printf("[Cloud_Access] dev profile publish success.\n");
    context->publish_state |= PUBLISH_DEV_PROFILE;
    if (is_resource_publish_finish(context)) {
      context->cloud_access_status = CLOUD_ACCESS_FINISH;
      es_set_state(ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD);
      oc_set_delayed_callback(context, &callback_handler, 0);
    }
  } else {
    printf("[Cloud Access] dev profile publish failed!!\n");
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_PUBLISH_RESOURCES_TO_CLOUD);
    oc_set_delayed_callback(context, &callback_handler, 0);
  }
}

static void
sign_in_handler(oc_client_response_t *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;

  if (data->code == OC_STATUS_CHANGED) {
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
  } else {
    printf("[Cloud Access] Sign in failed!!\n");
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, &callback_handler, 0);
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
          oc_new_string(&context->uid, oc_string(rep->value.string),
                        oc_string_len(rep->value.string));
        } else if (strncmp(ACCESS_TOKEN_KEY, oc_string(rep->name),
                           oc_string_len(rep->name)) == 0) {
          oc_new_string(&context->access_token, oc_string(rep->value.string),
                        oc_string_len(rep->value.string));
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
      es_set_state(ES_STATE_REGISTERED_TO_CLOUD);
      printf("[Cloud_Access] sign in with\n");
      printf("[Cloud_Access]  - uid: %s\n", oc_string(context->uid));
      printf("[Cloud_Access]  - accesstoken: %s\n",
             oc_string(context->access_token));
      oc_sign_in(&context->cloud_ep, oc_string(context->uid),
                 oc_string(context->access_token), 0, sign_in_handler, context);
    } else {
      context->cloud_access_status = CLOUD_ACCESS_FAIL;
      es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
      oc_set_delayed_callback(context, &callback_handler, 0);
    }
  } else {
    printf("[Cloud Access] Sign up failed!!\n");
    context->cloud_access_status = CLOUD_ACCESS_FAIL;
    es_set_state(ES_STATE_FAILED_TO_REGISTER_TO_CLOUD);
    oc_set_delayed_callback(context, &callback_handler, 0);
  }
}

static void
send_ping_handler(oc_client_response_t *data)
{
  if (data->code != OC_STATUS_NOT_MODIFIED) {
    st_cloud_context_t *context = (st_cloud_context_t *)data->user_data;
    context->cloud_access_status = CLOUD_ACCESS_PING_FAIL;
  }
}

static oc_event_callback_retval_t
send_ping(void *data)
{
  st_cloud_context_t *context = (st_cloud_context_t *)data;
  if (CLOUD_ACCESS_PING_FAIL == context->cloud_access_status)
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
    context->cloud_access_status = CLOUD_ACCESS_PING;
    oc_set_delayed_callback(context, &send_ping, 420);
  }
}
