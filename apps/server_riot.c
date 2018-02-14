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

static bool light_state = false;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Kishen's light", "1.0", "1.0",
                       NULL, NULL);
  return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  PRINT("GET_light:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, light_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  PRINT("Light state %d\n", light_state);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  PRINT("POST_light:\n");
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
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  light_state = state;
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  post_light(request, interface, user_data);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("lightbulb", "/light/1", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.light");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_add_resource(res);
}

#include "pthread_cond.h"
#include "thread.h"

static int quit;
static mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;

static void
signal_event_loop(void)
{
  mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  mutex_unlock(&mutex);
}

static char _oc_main_stack[THREAD_STACKSIZE_MAIN];

void *
oc_main_thread(void *arg)
{
  (void)arg;

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

  if (oc_main_init(&handler) < 0) {
    PRINT("server_riot: failed to initialize stack\n");
    return NULL;
  }

  oc_clock_time_t next_event;
  while (!quit) {
    next_event = oc_main_poll();
    mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    mutex_unlock(&mutex);
  }

  oc_main_shutdown();

  return NULL;
}

int
main(void)
{
  thread_create(_oc_main_stack, sizeof(_oc_main_stack), 2, 0, oc_main_thread,
                NULL, "OCF event thread");

  fgetc(stdin);

  quit = 1;
  signal_event_loop();

  return 0;
}
