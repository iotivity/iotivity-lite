/****************************************************************************
 *
 * Copyright 2021 ETRI All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
 * Created on: Aug 2, 2022,
 *        Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "oc_push.h"
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";
static const char *device_rt = "oic.d.push";
static const char *device_name = "push-targetserver";
static const char *manufacturer = "ETRI";

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

pthread_mutex_t app_mutex;
int quit = 0;

void
push_arrived(oc_pushd_resource_rep_t *push_payload)
{
  printf("new push arrives (path: %s, rt: ",
         oc_string(push_payload->resource->uri));
  for (size_t i = 0;
       i < oc_string_array_get_allocated_size(push_payload->resource->types);
       i++) {
    printf("%s ", oc_string_array_get_item(push_payload->resource->types, i));
  }
  printf(")\n");

  oc_print_pushd_resource(push_payload->rep);
}

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);

  /* set push callback function which will be called when new PUSH arrives */
  oc_set_on_push_arrived(push_arrived);

  return ret;
}

static void
signal_event_loop(void)
{
  pthread_cond_signal(&cv);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event;

  while (quit != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_mutex);
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

  pthread_exit(0);
}

void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  printf("=====================================\n");
  printf("0. Quit\n");
  printf("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

int
main(void)
{
  int init = 0;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop =
                                          signal_event_loop };

#ifdef OC_STORAGE
  oc_storage_config("./push_targetserver_multithread_linux_creds");
#endif /* OC_STORAGE */

  if (pthread_mutex_init(&mutex, NULL)) {
    printf("pthread_mutex_init failed!\n");
    return -1;
  }

  if (pthread_mutex_init(&app_mutex, NULL)) {
    printf("pthread_mutex_init failed!\n");
    pthread_mutex_destroy(&mutex);
    return -1;
  }

  init = oc_main_init(&handler);
  if (init < 0) {
    printf("oc_main_init failed!(%d)\n", init);
    goto exit;
  }

  size_t device_num = oc_core_get_num_devices();
  size_t i;
  for (i = 0; i < device_num; i++) {
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(i);
    printf("=== device(%zd) endpoint info. ===\n", i);
    while (ep) {
      oc_string_t ep_str;
      if (oc_endpoint_to_string(ep, &ep_str) == 0) {
        printf("%s\n", oc_string(ep_str));
        oc_free_string(&ep_str);
      }
      ep = ep->next;
    }
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    printf("Failed to create main thread\n");
    init = -1;
    goto exit;
  }

  int key;
  while (quit != 1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%d", &key)) {
      printf("scanf failed!!!!\n");
      quit = 1;
      handle_signal(0);
      break;
    }

    pthread_mutex_lock(&app_mutex);
    switch (key) {
    case 0:
      quit = 1;
      handle_signal(0);
      break;
    default:
      printf("unsupported command.\n");
      break;
    }
    pthread_mutex_unlock(&app_mutex);
  }

  pthread_join(thread, NULL);
  printf("pthread_join finish!\n");

exit:
  oc_main_shutdown();

  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_mutex);
  return 0;
}
