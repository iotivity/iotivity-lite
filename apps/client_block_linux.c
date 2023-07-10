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
#include "port/oc_random.h"
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static bool quit = false;

static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  ret |=
    oc_add_device("/oic/d", "oic.d.large.array.reader", "Large array reader",
                  "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char array_1[MAX_URI_LENGTH];
static oc_endpoint_t *array_server;
static int large_array[100];

static void
post_array(oc_client_response_t *data)
{
  OC_PRINTF("POST_array:\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("POST response OK\n");
  else
    OC_PRINTF("POST response code %d\n", data->code);
}

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  OC_PRINTF("Stopping OBSERVE\n");
  oc_stop_observe(array_1, array_server);

  if (oc_init_post(array_1, array_server, NULL, &post_array, LOW_QOS, NULL)) {
    for (int i = 0; i < 100; i++) {
      large_array[i] = (int)oc_random_value();
      OC_PRINTF("(%d %d) ", i, large_array[i]);
    }
    OC_PRINTF("\n");
    oc_rep_start_root_object();
    oc_rep_set_int_array(root, array, large_array, 100);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      OC_PRINTF("Sent POST request\n");
    } else {
      OC_PRINTF("Could not send POST\n");
    }
  } else {
    OC_PRINTF("Could not init POST\n");
  }

  return OC_EVENT_DONE;
}

static void
get_array(oc_client_response_t *data)
{
  int i;
  OC_PRINTF("GET_array:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    OC_PRINTF("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT_ARRAY: {
      int64_t *arr = oc_int_array(rep->value.array);
      for (i = 0; i < (int)oc_int_array_size(rep->value.array); i++) {
        OC_PRINTF("(%d %" PRId64 ") ", i, arr[i]);
      }
      OC_PRINTF("\n");
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)iface_mask;
  (void)user_data;
  (void)bm;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 11 && strncmp(t, "oic.r.array", 11) == 0) {
      oc_endpoint_list_copy(&array_server, endpoint);

      strncpy(array_1, uri, uri_len);
      array_1[uri_len] = '\0';

      OC_PRINTF("Resource %s hosted at endpoints:\n", array_1);
      const oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        ep = ep->next;
      }

      oc_do_observe(array_1, array_server, NULL, &get_array, HIGH_QOS, NULL);
      oc_set_delayed_callback(NULL, &stop_observe, 25);
      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery("oic.r.array", &discovery, NULL);
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
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
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
    .requests_entry = issue_requests,
  };

#ifdef OC_STORAGE
  oc_storage_config("./client_block_linux_creds");
#endif /* OC_STORAGE */

  oc_set_mtu_size(300);
  oc_set_max_app_data_size(2048);

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
