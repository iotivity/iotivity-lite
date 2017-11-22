/*
// Copyright 2018 Oleksandr Grytsov
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

#include <unistd.h>

#include <openthread/cli.h>
#include <openthread/diag.h>
#include <openthread/openthread.h>
#include <examples/platforms/platform.h>

#ifdef OC_RETARGET
#include <openthread/platform/uart.h>
#endif

#include "oc_api.h"
#include "oc_assert.h"
#include "oc_instance.h"

otInstance *ot_instance;

static bool light_state = false;

static void
set_device_custom_property(void *data)
{
  (void)data;
  oc_set_custom_device_property(purpose, "desk lamp");
}

static int
app_init(void)
{
  int ret = oc_init_platform("Openthread", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Openthread light", "ocf.1.0.0",
                       "ocf.res.1.0.0", set_device_custom_property, NULL);
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
  (void)user_data;
  (void)interface;
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

static void
ot_state_changed(uint32_t flags, void *context)
{
  (void)context;

  if (flags & OT_CHANGED_THREAD_ROLE) {
      PRINT("Role: %d\n", otThreadGetDeviceRole(ot_instance));
  }
}

static void
signal_event_loop(void)
{
  ocInstanceSignal();
}

static
int start_thread(void)
{
  if (!otThreadGetAutoStart(ot_instance)) {
    if (otIp6SetEnabled(ot_instance, true) != OT_ERROR_NONE) {
      OC_ERR("Can't enable ip6\n");
      return -1;
    }
    if (otLinkSetPanId(ot_instance, 0xface) != OT_ERROR_NONE) {
      OC_ERR("Can't set panid\n");
      return -1;
    }
    if (otThreadSetEnabled(ot_instance, true) != OT_ERROR_NONE) {
      OC_ERR("Can't enable thread\n");
      return -1;
    }

    if(otThreadSetAutoStart(ot_instance, true) != OT_ERROR_NONE) {
      OC_ERR("Can't set thread autostart\n");
      return -1;
    }
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  // init openthread

  PlatformInit(argc, argv);

  ot_instance = otInstanceInitSingle();

  oc_assert(ot_instance);

#ifdef OC_RETARGET
  oc_assert(otPlatUartEnable() == OT_ERROR_NONE);
#endif

  oc_assert(start_thread() == 0);

  otSetStateChangedCallback(ot_instance, ot_state_changed, NULL);

  // init iotivity

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                        register_resources };

  ocInstanceInit(&handler);

  PRINT("Server\n");

  while (1) {
    // handle openthread
    otTaskletsProcess(ot_instance);
    PlatformProcessDrivers(ot_instance);
  }

  oc_main_shutdown();

  return 0;
}
