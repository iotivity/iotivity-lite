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
static struct _fridge_state
{
  int filter;
  bool rapid_freeze;
  bool defrost;
  bool rapid_cool;
} fridge_state;
static double thermostat = 0.0;

static int
app_init(void)
{
  int ret = oc_init_platform("FridgeRemote", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.remote", "My remote", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char fridge_1[MAX_URI_LENGTH];
static char temp_1[MAX_URI_LENGTH];
static oc_endpoint_t *fridge_server, *temp_server;
static bool stop_get_post = false;

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

static oc_event_callback_retval_t
stop_client(void *data)
{
  (void)data;
  PRINT("Stopping client...\n");
  handle_signal(0);
  return OC_EVENT_DONE;
}

static void get_platform(oc_client_response_t *data);
static void get_device(oc_client_response_t *data);

static oc_event_callback_retval_t
get_p_and_d(void *data)
{
  (void)data;
  oc_do_get("oic/p", fridge_server, NULL, &get_platform, LOW_QOS, NULL);
  oc_do_get("oic/d", fridge_server, "if=oic.if.baseline", &get_device, LOW_QOS,
            NULL);
  oc_do_get("oic/d", temp_server, "if=oic.if.baseline", &get_device, LOW_QOS,
            NULL);

  stop_get_post = true;

  oc_set_delayed_callback(NULL, &stop_client, 3);

  return OC_EVENT_DONE;
}

static void get_temp(oc_client_response_t *data);

static void
post_temp(oc_client_response_t *data)
{
  PRINT("POST_fridge:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);

  if (!stop_get_post) {
    oc_do_get(temp_1, temp_server, NULL, &get_temp, LOW_QOS, NULL);
  }
}

static void
get_temp(oc_client_response_t *data)
{
  PRINT("GET_temp:\n");
  oc_rep_t *rep = data->payload;

  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_DOUBLE:
      if (oc_string_len(rep->name) == 11 &&
          memcmp(oc_string(rep->name), "temperature", 11) == 0) {
        thermostat = rep->value.double_p;
        PRINT("value: %lf\n", thermostat);
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (!stop_get_post &&
      oc_init_post(temp_1, temp_server, NULL, &post_temp, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_double(root, temperature, thermostat + 1.0);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST\n");
  } else
    PRINT("Could not init POST\n");
}

static void get_fridge(oc_client_response_t *data);

static void
post_fridge(oc_client_response_t *data)
{
  PRINT("POST_fridge:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);

  if (!stop_get_post) {
    oc_do_get(fridge_1, fridge_server, NULL, &get_fridge, LOW_QOS, NULL);
  }
}

static void
get_fridge(oc_client_response_t *data)
{
  PRINT("GET_fridge:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      if (oc_string_len(rep->name) == 6 &&
          memcmp(oc_string(rep->name), "filter", 6) == 0) {
        fridge_state.filter = (int)rep->value.integer;
        PRINT("value: %d\n", fridge_state.filter);
      }
      break;
    case OC_REP_BOOL:
      if (oc_string_len(rep->name) == 11 &&
          memcmp(oc_string(rep->name), "rapidFreeze", 11) == 0) {
        fridge_state.rapid_freeze = rep->value.boolean;
      } else if (oc_string_len(rep->name) == 9 &&
                 memcmp(oc_string(rep->name), "rapidCool", 9) == 0) {
        fridge_state.rapid_cool = rep->value.boolean;
      } else if (oc_string_len(rep->name) == 7 &&
                 memcmp(oc_string(rep->name), "defrost", 7) == 0) {
        fridge_state.defrost = rep->value.boolean;
      }
      PRINT("value: %d\n", rep->value.boolean);
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (!stop_get_post && oc_init_post(fridge_1, fridge_server, NULL,
                                     &post_fridge, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_int(root, filter, fridge_state.filter + 5);
    oc_rep_set_boolean(root, rapidFreeze, !fridge_state.rapid_freeze);
    oc_rep_set_boolean(root, defrost, !fridge_state.defrost);
    oc_rep_set_boolean(root, rapidCool, !fridge_state.rapid_cool);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST\n");
  } else
    PRINT("Could not init POST\n");
}

static void
get_platform(oc_client_response_t *data)
{
  PRINT("GET_platform:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if ((oc_string_len(rep->name) == 2 &&
           memcmp(oc_string(rep->name), "pi", 2) == 0) ||
          (oc_string_len(rep->name) == 4 &&
           memcmp(oc_string(rep->name), "mnmn", 4) == 0)) {
        PRINT("key: %s, value: %s\n", oc_string(rep->name),
              oc_string(rep->value.string));
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }
}

static void
get_device(oc_client_response_t *data)
{
  PRINT("GET_device:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if ((oc_string_len(rep->name) == 3 &&
           memcmp(oc_string(rep->name), "pid", 3) == 0) ||
          (oc_string_len(rep->name) == 3 &&
           memcmp(oc_string(rep->name), "dmv", 3) == 0) ||
          (oc_string_len(rep->name) == 3 &&
           memcmp(oc_string(rep->name), "icv", 3) == 0) ||
          (oc_string_len(rep->name) == 2 &&
           memcmp(oc_string(rep->name), "di", 2) == 0)) {
        PRINT("key: %s, value: %s\n", oc_string(rep->name),
              oc_string(rep->value.string));
      }
      break;
    case OC_REP_STRING_ARRAY:
      if (oc_string_len(rep->name) == 2 &&
          (memcmp(oc_string(rep->name), "rt", 2) == 0 ||
           memcmp(oc_string(rep->name), "if", 2) == 0)) {
        int i;
        PRINT("key: %s, value: ", oc_string(rep->name));
        for (i = 0;
             i < (int)oc_string_array_get_allocated_size(rep->value.array);
             i++) {
          PRINT(" %s ", oc_string_array_get_item(rep->value.array, i));
        }
        PRINT("\n");
      }
      break;
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
  (void)iface_mask;
  (void)user_data;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 19 && strncmp(t, "oic.r.refrigeration", 19) == 0) {
      strncpy(fridge_1, uri, uri_len);
      fridge_1[uri_len] = '\0';
      oc_endpoint_list_copy(&fridge_server, endpoint);

      PRINT("Resource %s hosted in device %s at endpoints:\n", fridge_1,
            anchor);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }
      PRINT("\n\n");
      oc_do_get(fridge_1, fridge_server, NULL, &get_fridge, LOW_QOS, NULL);
      return OC_CONTINUE_DISCOVERY;
    } else if (strlen(t) == 17 && strncmp(t, "oic.r.temperature", 17) == 0) {
      strncpy(temp_1, uri, uri_len);
      temp_1[uri_len] = '\0';
      oc_endpoint_list_copy(&temp_server, endpoint);

      PRINT("Resource %s hosted in device %s at endpoints:\n", temp_1, anchor);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }
      PRINT("\n\n");
      oc_do_get(temp_1, temp_server, NULL, &get_temp, LOW_QOS, NULL);
      return OC_CONTINUE_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery(NULL, &discovery, NULL);
  oc_set_delayed_callback(NULL, &get_p_and_d, 10);
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

#ifdef OC_STORAGE
  oc_storage_config("./multi_device_client_creds");
#endif /* OC_STORAGE */

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
