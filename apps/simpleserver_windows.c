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
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include <signal.h>
#include <windows.h>

int quit = 0;

static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

static bool state = false;
int power;
oc_string_t name;
bool g_binaryswitch_value = false;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  oc_new_string(&name, "John's Light", 12);
  oc_resource_tag_locn(oc_core_get_resource_by_index(OCF_D, 0), OCF_LOCN_UNKNOWN);
  return ret;
}

static void
get_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces,
                 void *user_data)
{
  (void)user_data; /* not used */
  PRINT("get_binaryswitch: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_A:
    /* property "value" */
    oc_rep_set_boolean(root, value, g_binaryswitch_value);
    PRINT("   value : %d\n", g_binaryswitch_value); /* not handled value */
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}


static void
post_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces,
                  void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("post_binaryswitch:\n");
  oc_rep_t *rep = request->request_payload;
  /* loop over the request document to check if all inputs are ok */
  while (rep != NULL) {
    PRINT("key: (check) %s \n", oc_string(rep->name));
    if (memcmp(oc_string(rep->name), "value", 5) == 0) {
      /* property "value" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        PRINT("   property 'value' is not of type bool %d \n", rep->type);
      }
    }

    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    /* loop over all the properties in the input document */
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
      PRINT("key: (assign) %s \n", oc_string(rep->name));
      /* no error: assign the variables */
      if (memcmp(oc_string(rep->name), "value", 5) == 0) {
        /* assign "value" */
        g_binaryswitch_value = rep->value.boolean;
      }
      rep = rep->next;
    }
    /* set the response */
    PRINT("Set response \n");
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, value, g_binaryswitch_value);
    oc_rep_end_root_object();

    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    /* TODO: add error response, if any */
    //oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_diagnostic_message(request, "Test Diagnostic Response", 24,
                               OC_STATUS_BAD_REQUEST);
  }
}

static void
get_light(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)user_data;
  ++power;

  PRINT("GET_light:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, state);
    oc_rep_set_int(root, power, power);
    oc_rep_set_text_string(root, name, oc_string(name));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  PRINT("POST_light:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      PRINT("value: %d\n", state);
      break;
    case OC_REP_INT:
      power = (int)rep->value.integer;
      PRINT("value: %d\n", power);
      break;
    case OC_REP_STRING:
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  post_light(request, iface_mask, user_data);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource(NULL, "/a/light", 2, 0);
  oc_resource_bind_resource_type(res, "x.com.core.light");
  oc_resource_bind_resource_type(res, "x.com.core.brightlight");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_add_resource(res);

  oc_resource_t *res_binaryswitch = oc_new_resource("Binary Switch", "/binaryswitch", 1, 0);
  oc_resource_bind_resource_type(res_binaryswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(res_binaryswitch, OC_IF_A);
  oc_resource_set_default_interface(res_binaryswitch, OC_IF_A);
  oc_resource_set_discoverable(res_binaryswitch, true);
  oc_resource_set_periodic_observable(res_binaryswitch, 1);
  oc_resource_set_request_handler(res_binaryswitch, OC_GET, get_binaryswitch,
                                  NULL);
  oc_resource_set_request_handler(res_binaryswitch, OC_POST, post_binaryswitch,
                                  NULL);
  oc_add_resource(res_binaryswitch);
}

static void
signal_event_loop(void)
{
  WakeConditionVariable(&cv);
}

void
handle_signal(int signal)
{
  signal_event_loop();
  quit = 1;
}

int
main(void)
{
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);

  int init;

  /* set the latency to 240 seconds*/
  /* if no latency is needed then remove the next line */
  oc_core_set_latency(240);

  signal(SIGINT, handle_signal);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources,
                                        .requests_entry = 0 };

  oc_clock_time_t next_event;

#ifdef OC_STORAGE
  oc_storage_config("./simpleserver_creds/");
#endif /* OC_STORAGE */

  oc_set_con_res_announced(true);
  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  while (quit != 1) {
    next_event = oc_main_poll();
    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }

  oc_main_shutdown();
  return 0;
}
