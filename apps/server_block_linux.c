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
static int large_array[100];

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.array", "Large array generator",
                       "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static oc_separate_response_t array_response;

static oc_event_callback_retval_t
handle_array_response(void *data)
{
  (void)data;
  if (array_response.active) {
    oc_set_separate_response_buffer(&array_response);
    PRINT("GET_array:\n");
    int i;
    for (i = 0; i < 100; i++) {
      large_array[i] = oc_random_value();
      PRINT("(%d %d) ", i, large_array[i]);
    }
    PRINT("\n");
    oc_rep_start_root_object();
    oc_rep_set_int_array(root, array, large_array, 100);
    oc_rep_end_root_object();
    oc_send_separate_response(&array_response, OC_STATUS_OK);
  }
  return OC_EVENT_DONE;
}

static void
get_array(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  oc_indicate_separate_response(request, &array_response);
  oc_set_delayed_callback(NULL, &handle_array_response, 5);
}

static void
post_array(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  PRINT("POST_array:\n");
  int i;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT_ARRAY: {
      int64_t *arr = oc_int_array(rep->value.array);
      for (i = 0; i < (int)oc_int_array_size(rep->value.array); i++) {
        PRINT("(%d %lld) ", i, arr[i]);
      }
      PRINT("\n");
    } break;
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
  oc_resource_t *res = oc_new_resource("arrayofvalues", "/array/1", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.array");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 5);
  oc_resource_set_request_handler(res, OC_GET, get_array, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_array, NULL);
  oc_add_resource(res);
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
  oc_storage_config("./server_block_linux_creds");
#endif /* OC_STORAGE */

  oc_set_mtu_size(200);
  oc_set_max_app_data_size(2048);

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
