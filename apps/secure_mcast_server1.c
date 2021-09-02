/*
// Copyright (c) 2020 Intel Corporation
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
static bool light_state = false;

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Room1 lights", "ocf.2.2.2",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
retrieve_light_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                      void *user_data)
{
  (void)user_data;
  PRINT("RETRIEVE light switch:\n");
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
  PRINT("Light state %d\n", light_state);
}

static void
update_light_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                    void *user_data)
{
  (void)user_data;
  (void)iface_mask;
  PRINT("UPDATE light switch:\n");
  if (request->origin) {
    if (request->origin->flags & MULTICAST) {
      PRINT("\t\t--multicast\n\t\t--");
    }
    PRINTipaddr(*(request->origin));
    PRINT("\n");
  }
  oc_status_t code = OC_STATUS_CHANGED;
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      PRINT("value: %d\n", state);
      break;
    default:
      code = OC_STATUS_BAD_REQUEST;
      return;
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

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

  oc_clock_time_t next_event;

#ifdef OC_STORAGE
  oc_storage_config("./secure_mcast_server1_creds");
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
