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

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel Corporation", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.wk.d", "Generic Client", "ocf.1.0.0",
                       "ocf.res.1.3.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char light_1[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;
static bool light_state = false;

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(light_1, light_server);
  return OC_EVENT_DONE;
}

static void
post_light(oc_client_response_t *data)
{
  PRINT("POST_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);
}

static void
observe_light(oc_client_response_t *data)
{
  PRINT("OBSERVE_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      PRINT("%d\n", rep->value.boolean);
      light_state = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (oc_init_post(light_1, light_server, NULL, &post_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !light_state);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST\n");
  } else
    PRINT("Could not init POST\n");
}

static oc_discovery_flags_t
discovery(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)di;
  (void)interfaces;
  (void)user_data;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 11 && strncmp(t, "oic.r.light", 11) == 0) {
      strncpy(light_1, uri, uri_len);
      light_1[uri_len] = '\0';
      light_server = endpoint;

      PRINT("Resource %s hosted at endpoints:\n", light_1);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }

      oc_do_observe(light_1, light_server, NULL, &observe_light, LOW_QOS, NULL);
      oc_set_delayed_callback(NULL, &stop_observe, 10);
      return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery("oic.r.light", &discovery, NULL);
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
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

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .requests_entry = issue_requests };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./client_creds");
#endif /* OC_SECURITY */

  oc_set_con_res_announced(false);
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
