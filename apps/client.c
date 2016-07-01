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

void
app_init(void)
{
  oc_new_platform("Apple");
  oc_add_platform();
  oc_new_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "1.0", "1.0");
  oc_set_custom_device_property(purpose, "operate lamp");
  oc_add_device();
}

#ifdef OC_SECURITY
void
fetch_credentials(void)
{
  oc_storage_config("./creds");
}
#endif

static char light_1[30];
static oc_server_handle_t light_server;
static bool light_state = false;

oc_event_callback_retval_t
stop_observe(void* data)
{
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(light_1, &light_server);
  return DONE;
}

void
put_light(oc_client_response_t *data)
{
  PRINT("PUT_light:\n");
  if (data->code == OK)
    PRINT("PUT response OK\n");
  else
    PRINT("PUT response code %d\n", data->code);
}

void
observe_light(oc_client_response_t *data)
{
  PRINT("OBSERVE_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case BOOL:
      PRINT("%d\n", rep->value_boolean);
      light_state = rep->value_boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (oc_init_put(light_1, &light_server, NULL, &put_light, LOW_QOS)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !light_state);
    oc_rep_end_root_object();
    if (oc_do_put())
      PRINT("Sent PUT request\n");
    else
      PRINT("Could not send PUT\n");
  }
  else
    PRINT("Could not init PUT\n");
}

oc_discovery_flags_t
discovery(const char *di,
	  const char *uri,
	  oc_string_array_t types,
	  oc_interface_mask_t interfaces,
	  oc_server_handle_t* server)
{
  int i;
  for (i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 11 && strncmp(t, "oic.r.light", 11) == 0) {
      memcpy(&light_server, server, sizeof(oc_server_handle_t));
      strcpy(light_1, uri);

      oc_do_observe(light_1, &light_server, NULL, &observe_light, LOW_QOS);
      oc_set_delayed_callback(NULL, &stop_observe, 30);
      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

void
issue_requests()
{
  oc_do_ip_discovery("oic.r.light", &discovery);
}

#if defined(CONFIG_MICROKERNEL) || defined(CONFIG_NANOKERNEL) /* Zephyr */

#include <zephyr.h>
#include <sections.h>
#include "port/oc_signal_main_loop.h"
#include <string.h>

static struct nano_timer idle_time;

void
oc_signal_main_loop()
{
  nano_task_timer_stop(&idle_time);
}

void
main()
{
  oc_handler_t handler = {.init = app_init,
#ifdef OC_SECURITY
			  .get_credentials = fetch_credentials,
#endif /* OC_SECURITY */
			  .requests_entry = issue_requests
  };

  uint32_t dummy;
  nano_timer_init(&idle_time, &dummy);

  int init = oc_main_init(&handler);

  oc_clock_time_t next_event;

  while (init) {
    next_event = oc_main_poll();
    nano_task_timer_start(&idle_time, next_event - oc_clock_time());

    nano_task_timer_test(&idle_time, TICKS_UNLIMITED);
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
oc_signal_main_loop()
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
main()
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  oc_handler_t handler = {.init = app_init,
#ifdef OC_SECURITY
			  .get_credentials = fetch_credentials,
#endif /* OC_SECURITY */
			  .requests_entry = issue_requests
  };

  oc_clock_time_t next_event;

  int init = oc_main_init(&handler);

  if (init != 1)
    goto exit;

  while (quit != 1) {
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

exit:
  return 0;
}
#endif /* __linux__ */
