/****************************************************************************
 *
 * Copyright (c) 2020 Intel Corporation
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

static bool light_state = false;

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Room1 lights", "ocf.2.2.5",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
retrieve_light_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                      void *user_data)
{
  (void)user_data;
  OC_PRINTF("RETRIEVE light switch:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, value, light_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  OC_PRINTF("Light state %d\n", light_state);
}

static void
update_light_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                    void *user_data)
{
  (void)user_data;
  (void)iface_mask;
  OC_PRINTF("UPDATE light switch:\n");
  if (request->origin) {
    if (request->origin->flags & MULTICAST) {
      OC_PRINTF("\t\t--multicast\n\t\t--");
    }
    OC_PRINTipaddr(*(request->origin));
    OC_PRINTF("\n");
  }
  oc_status_t code = OC_STATUS_CHANGED;
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_PRINTF("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      OC_PRINTF("value: %d\n", state);
      break;
    default:
      code = OC_STATUS_BAD_REQUEST;
      break;
    }
    if (code == OC_STATUS_BAD_REQUEST) {
      break;
    }
    rep = rep->next;
  }

  if (code != OC_STATUS_BAD_REQUEST) {
    light_state = state;
  }

  if (request->origin && request->origin->flags & MULTICAST) {
    /* Do not respond to a multicast update */
    oc_ignore_request(request);
    /* Notify observers of a successful update */
    if (code == OC_STATUS_CHANGED) {
      oc_notify_observers(request->resource);
    }
  } else {
    oc_send_response(request, code);
  }
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("rooflights1", "/lights", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
  oc_resource_set_request_handler(res, OC_GET, retrieve_light_switch, NULL);
  oc_resource_set_request_handler(res, OC_POST, update_light_switch, NULL);
#ifdef OC_OSCORE
  oc_resource_set_secure_mcast(res, true);
#endif /* OC_OSCORE */
  oc_add_resource(res);
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
  oc_clock_time_t next_event_mt;
  while (!quit) {
    next_event_mt = oc_main_poll_v1();
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
  oc_storage_config("./secure_mcast_server1_creds");
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
