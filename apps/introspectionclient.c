/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "oc_api.h"
#include "port/oc_clock.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

int quit = 0;

static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  printf("\tPlatform initialized.\n");
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  printf("\tDevice initialized.\n");
  return ret;
}

#define MAX_URI_LENGTH (128)

static char wk_introspection_uri[MAX_URI_LENGTH];
static char introspection_data_uri[MAX_URI_LENGTH];
static oc_endpoint_t wk_introspection_server;
static oc_endpoint_t introspection_data_server;

void
print_rep(oc_rep_t *rep, bool pretty_print)
{
  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, pretty_print);
  printf("%s\n", json);
  free(json);
}

static void
get_introspection_data(oc_client_response_t *data)
{
  printf("\nInside the get_introspection_data handler:\n");
  if (data->code == OC_STATUS_OK) {
    oc_rep_t *rep = data->payload;
    print_rep(rep, true);
  } else {
    switch (data->code) {
    case OC_STATUS_UNAUTHORIZED:
      printf("\tERROR Unauthorized access check permissions.\n");
      break;
    case OC_STATUS_INTERNAL_SERVER_ERROR:
      printf("\tERROR Internal Server Error\n"
             "\t\tcheck the max app data size of the server.\n");
      break;
    default:
      printf("\tERROR status: %d\n", data->code);
    }
  }
}

static void
get_wk_introspection(oc_client_response_t *data)
{
  printf("\nInside the get_wk_introspection handler:\n");
  oc_rep_t *rep = data->payload;

  while (rep != NULL) {
    print_rep(rep, true);
    switch (rep->type) {
    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *rep_array = rep->value.object_array;
      while (rep_array != NULL) {
        oc_rep_t *rep_item = rep_array->value.object;
        while (rep_item != NULL) {
          char *url_str = oc_string(rep_item->name);
          size_t url_str_len = oc_string_len(rep_item->name);
          if (strncmp("url", url_str, url_str_len) == 0) {
            oc_string_t path;

            // convert the url to an endpoint.
            oc_string_to_endpoint(&rep_item->value.string,
                                  &introspection_data_server, &path);
            strncpy(introspection_data_uri, oc_string(path), MAX_URI_LENGTH);
            introspection_data_uri[MAX_URI_LENGTH - 1] = '\0';

            printf("Calling GET on %s\n", introspection_data_uri);
            oc_do_get(introspection_data_uri, &introspection_data_server, NULL,
                      &get_introspection_data, LOW_QOS, NULL);
          }
          rep_item = rep_item->next;
        }
        rep_array = rep_array->next;
      }
      break;
    }
    default:
      break;
    }
    rep = rep->next;
  }
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)iface_mask;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 20 && strncmp(t, "oic.wk.introspection", 20) == 0) {
      printf("Found oic.wk.introspection resource.\n");
      oc_endpoint_copy(&wk_introspection_server, endpoint);
      strncpy(wk_introspection_uri, uri, uri_len);
      wk_introspection_uri[uri_len] = '\0';

      printf("Resource %s hosted at endpoints:\n", wk_introspection_uri);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        printf("\t");
        PRINTipaddr(*ep);
        printf("\n");
        ep = ep->next;
      }

      printf("Calling GET on oic.wk.introspection %s\n", wk_introspection_uri);
      oc_do_get(wk_introspection_uri, &wk_introspection_server, NULL,
                &get_wk_introspection, LOW_QOS, NULL);
      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  printf(
    "Making ip discovery request for OCF 'oic.wk.introspection' resource.\n");
  oc_do_ip_discovery("oic.wk.introspection", &discovery, NULL);
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

int
main(void)
{
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .requests_entry = issue_requests };

  oc_clock_time_t next_event;

  // set at 18K may need to be increased if server contains a large IDD.
  oc_set_max_app_data_size(18432);
#ifdef OC_STORAGE
  oc_storage_config("./introspectionclient_creds");
#endif /* OC_STORAGE */
  printf("Initilizing the introspection client...\n");
  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
  oc_main_shutdown();
  return 0;
}
