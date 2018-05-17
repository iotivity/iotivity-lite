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

#include "cloud_access.h"
#include "oc_api.h"
#include "port/oc_clock.h"
#include "rd_client.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";

static const char *resource_rt = "core.light";
static const char *device_rt = "oic.d.phone";
static const char *device_name = "Galaxy";

static const char *manufacturer = "Samsung";

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

pthread_mutex_t app_mutex;
oc_resource_t *res1;
oc_resource_t *res2;
oc_link_t *link1;
oc_link_t *link2;

#define MAX_URI_LENGTH (30)
static char a_light[MAX_URI_LENGTH];

static oc_string_t uid;
static oc_string_t access_token;

#define OC_IPV6_ADDRSTRLEN (46)
static oc_endpoint_t set_ep;

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  return ret;
}

static void
get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;

  printf("get_handler:\n");

  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, false);
    oc_rep_set_int(root, power, 0);
    oc_rep_set_text_string(root, name, "Light");
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
parse_payload(oc_client_response_t *data)
{
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    printf("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      printf("%d\n", rep->value.boolean);
      break;
    case OC_REP_INT:
      printf("%d\n", rep->value.integer);
      break;
    case OC_REP_STRING:
      printf("%s\n", oc_string(rep->value.string));
      if (strncmp("uid", oc_string(rep->name), oc_string_len(rep->name)) == 0) {
        if (oc_string_len(uid))
          oc_free_string(&uid);
        oc_new_string(&uid, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
      } else if (strncmp("accesstoken", oc_string(rep->name),
                         oc_string_len(rep->name)) == 0) {
        if (oc_string_len(access_token))
          oc_free_string(&access_token);
        oc_new_string(&access_token, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
      }
      break;
    default:
      printf("NULL\n");
      break;
    }
    rep = rep->next;
  }
}

static void
post_response(oc_client_response_t *data)
{
  if (data->code == OC_STATUS_CHANGED)
    printf("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    printf("POST response: CREATED\n");
  else
    printf("POST response code %d\n", data->code);

  parse_payload(data);
}

static void
delete_response(oc_client_response_t *data)
{
  if (data->code == OC_STATUS_DELETED)
    printf("DELETE response: DELETED\n");
  else if (data->code == OC_STATUS_BAD_REQUEST)
    printf("DELETE response: BAD REQUEST\n");
  else
    printf("DELETE response code %d\n", data->code);
}

static oc_discovery_flags_t
discovery_handler(const char *anchor, const char *uri, oc_string_array_t types,
                  oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
                  oc_resource_properties_t bm, void *user_data)
{
  oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;

  (void)anchor;
  (void)user_data;
  (void)interfaces;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, resource_rt, 10) == 0) {
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      printf("Resource %s hosted at endpoints:\n", a_light);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }
      ret = OC_STOP_DISCOVERY;
      goto exit;
    }
  }

exit:
  oc_free_server_endpoints(endpoint);
  return ret;
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
register_resources(void)
{
  res1 = oc_new_resource(NULL, "/light/1", 1, 0);
  oc_resource_bind_resource_type(res1, resource_rt);
  oc_resource_bind_resource_interface(res1, OC_IF_RW);
  oc_resource_set_default_interface(res1, OC_IF_RW);
  oc_resource_set_discoverable(res1, true);
  oc_resource_set_request_handler(res1, OC_GET, get_handler, NULL);
  oc_add_resource(res1);

  res2 = oc_new_resource(NULL, "/light/2", 1, 0);
  oc_resource_bind_resource_type(res2, resource_rt);
  oc_resource_bind_resource_interface(res2, OC_IF_RW);
  oc_resource_set_default_interface(res2, OC_IF_RW);
  oc_resource_set_discoverable(res2, true);
  oc_resource_set_request_handler(res2, OC_GET, get_handler, NULL);
  oc_add_resource(res2);
}

int
cloud_main(int argc, char* argv[])
{
  int init;
  char addr[10];

  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cv, NULL);

  printf("set cloud address(ex. coap+tcp://127.0.0.1:5683): ");
  if (sscanf(argv[1], "%s", addr)) {
    printf("address: %s\n", addr);
  }

  oc_string_t address_str;
  oc_new_string(&address_str, addr, strlen(addr));

  oc_string_to_endpoint(&address_str, &set_ep, NULL);
  oc_free_string(&address_str);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

#ifdef OC_SECURITY
  oc_storage_config("./cloud_linux_creds");
#endif /* OC_SECURITY */

  if (pthread_mutex_init(&mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    return -1;
  }

  if (pthread_mutex_init(&app_mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    return -1;
  }

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

    pthread_mutex_lock(&app_mutex);

    char auth_code[21];
    char* a_code = NULL;
    printf("set auth code(ex. j1o2j3a4e5h6o7n8g9): ");
    if (sscanf(argv[2], "%20s", a_code)) {
      printf("auth_code: %s\n", a_code);
    }

    oc_sign_up_with_auth(&set_ep, "github", auth_code, 0, post_response,
                         NULL);

    oc_sign_in(&set_ep, oc_string(uid), oc_string(access_token), 0,
               post_response, NULL);

  if (!link1) {
    link1 = oc_new_link(res1);
    link2 = oc_new_link(res2);
    oc_list_add((oc_list_t)link1, link2);
  }
  rd_publish(&set_ep, link1, 0, post_response, LOW_QOS, NULL);

  oc_do_ip_discovery_at_endpoint(resource_rt, &discovery_handler, &set_ep,
                                 NULL);
  rd_delete(&set_ep, NULL, 0, delete_response, LOW_QOS, NULL);

  oc_sign_out(&set_ep, oc_string(access_token), 0, post_response, NULL);

  pthread_mutex_unlock(&app_mutex);

  if (oc_string_len(uid))
    oc_free_string(&uid);
  if (oc_string_len(access_token))
    oc_free_string(&access_token);
  oc_delete_link(link1);
  oc_delete_link(link2);

  oc_main_shutdown();

  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_mutex);
  return 0;
}
