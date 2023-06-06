/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_api.h"
#include "oc_log.h"
#include "port/oc_clock.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static bool quit = false;
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
  OC_PRINTF("GET_fridge:\n");
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
  OC_PRINTF("POST_fridge:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_PRINTF("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      if (oc_string_len(rep->name) == 6 &&
          memcmp(oc_string(rep->name), "filter", 6) == 0) {
        fridge_state.filter = (int)rep->value.integer;
        OC_PRINTF("value: %d\n", fridge_state.filter);
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
      OC_PRINTF("value: %d\n", rep->value.boolean);
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
  OC_PRINTF("GET_temp:\n");
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
post_temp(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)user_data;
  (void)iface_mask;
  OC_PRINTF("POST_temp:\n");
  if (iface_mask == OC_IF_S) {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_PRINTF("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_DOUBLE:
      if (oc_string_len(rep->name) == 11 &&
          memcmp(oc_string(rep->name), "temperature", 11) == 0) {
        thermostat = rep->value.double_p;
        OC_PRINTF("value: %lf\n", thermostat);
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
  pthread_cond_signal(&cv);
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = true;
  signal_event_loop();
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    pthread_mutex_destroy(&mutex);
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_destroy(&attr);
  return true;
}

static void
deinit(void)
{
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
}

static void
run_loop(void)
{
  while (!quit) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    pthread_mutex_lock(&mutex);
    if (next_event_mt == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      struct timespec next_event = { 1, 0 };
      oc_clock_time_t next_event_cv;
      if (oc_clock_monotonic_time_to_posix(next_event_mt, CLOCK_MONOTONIC,
                                           &next_event_cv)) {
        next_event = oc_clock_time_to_timespec(next_event_cv);
      }
      pthread_cond_timedwait(&cv, &mutex, &next_event);
    }
    pthread_mutex_unlock(&mutex);
  }
}

int
main(void)
{
  if (!init()) {
    return -1;
  }

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
  };

#ifdef OC_STORAGE
  oc_storage_config("./multi_device_server_creds");
#endif /* OC_STORAGE */

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }
  run_loop();
  oc_main_shutdown();
  deinit();
  return 0;
}
