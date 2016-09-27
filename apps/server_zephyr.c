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
#include "port/oc_signal_main_loop.h"

#include <sections.h>
#include <string.h>
#include <zephyr.h>

static struct nano_sem block;
static bool light_state = false;

static void
set_device_custom_property(void *data)
{
  oc_set_custom_device_property(purpose, "desk lamp");
}

static void
app_init(void)
{
  oc_init_platform("Intel", NULL, NULL);

  oc_add_device("/oic/d", "oic.d.light", "Kishen's light", "1.0", "1.0",
                set_device_custom_property, NULL);
}

#ifdef OC_SECURITY
static void
fetch_credentials(void)
{
  oc_storage_config("./creds");
}
#endif

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
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
put_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  PRINT("PUT_light:\n");
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case BOOL:
      state = rep->value_boolean;
      PRINT("value: %d\n", state);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_OK);
  light_state = state;
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("/light/1", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.light");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);

#ifdef OC_SECURITY
  oc_resource_make_secure(res);
#endif

  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_add_resource(res);
}

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
                          .register_resources = register_resources };

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
