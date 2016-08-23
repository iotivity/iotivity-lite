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

static oc_separate_response_t temp_response;
static int temperature;

oc_define_interrupt_handler(temp_sensor)
{
  if(temp_response.active) {
    oc_set_separate_response_buffer(&temp_response);

    oc_rep_start_root_object();
    oc_rep_set_int(root, temp, temperature);
    oc_rep_end_root_object();

    oc_send_separate_response(&temp_response, OK);
  }
}

static void
app_init(void)
{
  oc_activate_interrupt_handler(temp_sensor);
  oc_init_platform("GE", NULL, NULL);

  oc_add_device("/oic/d", "oic.d.tempsensor", "Home temperature monitor",
		"1.0", "1.0", NULL, NULL);
}

#ifdef OC_SECURITY
static void
fetch_credentials(void)
{
  oc_storage_config("./creds");
}
#endif

static void
get_temp(oc_request_t *request, oc_interface_mask_t interface)
{
  oc_indicate_separate_response(request, &temp_response);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("/temp/1", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.tempsensor");
  oc_resource_bind_resource_interface(res, OC_IF_R);
  oc_resource_set_default_interface(res, OC_IF_R);

#ifdef OC_SECURITY
  oc_resource_make_secure(res);
#endif

  oc_resource_set_discoverable(res);
  oc_resource_set_observable(res);
  oc_resource_set_request_handler(res, OC_GET, get_temp);
  oc_add_resource(res);
}

#include <zephyr.h>
#include <sections.h>
#include "port/oc_signal_main_loop.h"
#include <string.h>

static char fiber_stack[512];

static void
fake_sensor_fiber(void)
{
  struct nano_timer timer;
  nano_timer_init(&timer, NULL);
  temperature = 3;

  while(1) {
    temperature++;
    oc_signal_interrupt_handler(temp_sensor);

    nano_fiber_timer_start(&timer, 2 * sys_clock_ticks_per_sec);
    nano_fiber_timer_test(&timer, TICKS_UNLIMITED);
  }
}

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

  task_fiber_start(&fiber_stack[0], 512,
		   (nano_fiber_entry_t)fake_sensor_fiber, 0, 0, 7, 0);

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
