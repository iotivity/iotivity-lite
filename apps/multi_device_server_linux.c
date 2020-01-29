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
static double thermostat;

static int
app_init(void)
{
  int ret = oc_init_platform("Refrigerator", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.refrigeration", "My fridge",
                       "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.thermostat", "My thermostat",
                       "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
get_fridge(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  (void)user_data;
  PRINT("GET_fridge:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, rapidFreeze, fridge_state.rapid_freeze);
    oc_rep_set_boolean(root, defrost, fridge_state.defrost);
    oc_rep_set_boolean(root, rapidCool, fridge_state.rapid_cool);
    oc_rep_set_int(root, filter, fridge_state.filter);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_fridge(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  (void)user_data;
  (void)iface_mask;
  PRINT("POST_fridge:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      if (oc_string_len(rep->name) == 6 &&
          memcmp(oc_string(rep->name), "filter", 6) == 0) {
        fridge_state.filter = (int)rep->value.integer;
        PRINT("value: %d\n", fridge_state.filter);
      } else {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
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
      } else {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
      PRINT("value: %d\n", rep->value.boolean);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
get_temp(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)user_data;
  (void)request;
  PRINT("GET_temp:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
  case OC_IF_S:
    oc_rep_set_double(root, temperature, thermostat);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
post_temp(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)user_data;
  (void)iface_mask;
  PRINT("POST_temp:\n");
  if (iface_mask == OC_IF_S) {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_DOUBLE:
      if (oc_string_len(rep->name) == 11 &&
          memcmp(oc_string(rep->name), "temperature", 11) == 0) {
        thermostat = rep->value.double_p;
        PRINT("value: %lf\n", thermostat);
      } else {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("myfridge", "/fridge/1", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.refrigeration");
  oc_resource_bind_resource_interface(res, OC_IF_A);
  oc_resource_set_default_interface(res, OC_IF_A);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_fridge, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_fridge, NULL);
  oc_add_resource(res);

  oc_resource_t *res1 = oc_new_resource("tempsetter", "/temp/1", 1, 1);
  oc_resource_bind_resource_type(res1, "oic.r.temperature");
  oc_resource_bind_resource_interface(res1, OC_IF_A | OC_IF_S);
  oc_resource_set_default_interface(res1, OC_IF_A);
  oc_resource_set_discoverable(res1, true);
  oc_resource_set_periodic_observable(res1, 1);
  oc_resource_set_request_handler(res1, OC_GET, get_temp, NULL);
  oc_resource_set_request_handler(res1, OC_POST, post_temp, NULL);
  oc_add_resource(res1);
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
                                       .register_resources =
                                         register_resources };

  oc_clock_time_t next_event;

#ifdef OC_STORAGE
  oc_storage_config("./multi_device_server_creds");
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
