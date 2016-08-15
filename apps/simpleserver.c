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

static bool state = false;
int power;
oc_string_t name;

void
app_init(void)
{
  oc_init_platform("Intel", NULL, NULL);

  oc_add_device("/oic/d", "oic.d.light", "Lamp", "1.0", "1.0",
		NULL, NULL);

  oc_new_string(&name, "John's Light");
}

#ifdef OC_SECURITY
void
fetch_credentials(void)
{
  oc_storage_config("./creds");
}
#endif

static void
get_light(oc_request_t *request, oc_interface_mask_t interface)
{
  ++power;

  PRINT("GET_light:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_DEFAULT:
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, state);
    oc_rep_set_int(root, power, power);
    oc_rep_set_text_string(root, name, oc_string(name));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OK);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface)
{
  PRINT("PUT_light:\n");
  oc_rep_t *rep = request->request_payload;
  while(rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch(rep->type) {
    case BOOL:
      state = rep->value_boolean;
      PRINT("value: %d\n", state);
      break;
    case INT:
      power = rep->value_int;
      PRINT("value: %d\n", power);
      break;
    case STRING:
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value_string));
      break;
    default:
      oc_send_response(request, BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, CHANGED);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface)
{
  put_light(request, interface);
}

void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("/a/light", 2, 0);
  oc_resource_bind_resource_type(res, "core.light");
  oc_resource_bind_resource_type(res, "core.brightlight");
  oc_resource_bind_resource_interface(res, OC_IF_RW);

#ifdef OC_SECURITY
  oc_resource_make_secure(res);
#endif

  oc_resource_set_discoverable(res);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light);
  oc_resource_set_request_handler(res, OC_PUT, put_light);
  oc_resource_set_request_handler(res, OC_POST, post_light);
  oc_add_resource(res);
}

#if defined(CONFIG_MICROKERNEL) || defined(CONFIG_NANOKERNEL) /* Zephyr */

#include <zephyr.h>
#include <sections.h>
#include "port/oc_signal_main_loop.h"
#include <string.h>

static struct nano_sem block;

void
oc_signal_main_loop(void)
{
  nano_sem_give(&block);
}

void
main(void)
{
  oc_handler_t handler = {.init = app_init,
#ifdef OC_SECURITY
			  .get_credentials = fetch_credentials,
#endif /* OC_SECURITY */
			  .register_resources = register_resources
  };

  nano_sem_init(&block);

  if (oc_main_init(&handler) < 0)
    return;

  oc_clock_time_t next_event;

  while (true) {
    next_event = oc_main_poll();
    if (next_event == 0)
      next_event = TICKS_UNLIMITED;
    else
      next_event -= oc_clock_time();
    nano_task_sem_take(&block, next_event);
  }

  oc_main_shutdown();
}

#elif defined(__linux__) /* Linux */
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include "port/oc_signal_main_loop.h"
#include "port/oc_clock.h"

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

int quit = 0;

void
oc_signal_main_loop(void)
{
  pthread_cond_signal(&cv);
}

void
handle_signal(int signal)
{
  oc_signal_main_loop();
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

  oc_handler_t handler = {.init = app_init,
#ifdef OC_SECURITY
			  .get_credentials = fetch_credentials,
#endif /* OC_SECURITY */
			  .register_resources = register_resources
  };

  oc_clock_time_t next_event;

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  while(quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    }
    else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  oc_main_shutdown();
  return 0;
}
#endif /* __linux__ */
