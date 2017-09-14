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
  if (temp_response.active) {
    oc_set_separate_response_buffer(&temp_response);

    oc_rep_start_root_object();
    oc_rep_set_int(root, temp, temperature);
    oc_rep_end_root_object();

    oc_send_separate_response(&temp_response, OC_STATUS_OK);
  }
}

static int
app_init(void)
{
  oc_activate_interrupt_handler(temp_sensor);
  int ret = oc_init_platform("GE", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.tempsensor", "Home temperature monitor",
                       "1.0", "1.0", NULL, NULL);
  return ret;
}

static void
get_temp(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  oc_indicate_separate_response(request, &temp_response);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("tempsensor", "/temp/1", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.tempsensor");
  oc_resource_bind_resource_interface(res, OC_IF_R);
  oc_resource_set_default_interface(res, OC_IF_R);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
  oc_resource_set_request_handler(res, OC_GET, get_temp, NULL);
  oc_add_resource(res);
}

#include <string.h>
#include <zephyr.h>

static char thread_stack[512];
static struct k_sem signal_interrupt;

static void
signal_interrupt_thread(struct k_timer *timer)
{
  k_sem_give(&signal_interrupt);
}

static void
fake_sensor_interrupts(void)
{
  struct k_timer timer;
  k_timer_init(&timer, signal_interrupt_thread, NULL);
  k_sem_init(&signal_interrupt, 0, 1);
  k_timer_start(&timer, 0, 1000); /* Fire off an interrupt every 1s */

  temperature = 3;

  while (1) {
    temperature++;
    oc_signal_interrupt_handler(temp_sensor);

    k_sem_take(&signal_interrupt, K_FOREVER);
  }
}

static struct k_sem block;

static void
signal_event_loop(void)
{
  k_sem_give(&block);
}

void
main(void)
{
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

  k_sem_init(&block, 0, 1);

  if (oc_main_init(&handler) < 0)
    return;

  k_thread_spawn(&thread_stack[0], sizeof(thread_stack),
                 (k_thread_entry_t)fake_sensor_interrupts, 0, 0, 0,
                 K_PRIO_COOP(7), 0, K_NO_WAIT);

  oc_clock_time_t next_event;

  while (true) {
    next_event = oc_main_poll();
    if (next_event == 0)
      next_event = K_FOREVER;
    else
      next_event -= oc_clock_time();
    k_sem_take(&block, next_event);
  }

  oc_main_shutdown();
}
