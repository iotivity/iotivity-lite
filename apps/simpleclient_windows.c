/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
#include <signal.h>
#include <windows.h>

static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

static bool quit = false;

static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;

static bool state = false;
static int power = 0;
static oc_string_t name;

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  OC_PRINTF("Stopping OBSERVE\n");
  oc_stop_observe(a_light, light_server);
  return OC_EVENT_DONE;
}

static void
observe_light(oc_client_response_t *data)
{
  OC_PRINTF("OBSERVE_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    OC_PRINTF("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_PRINTF("%d\n", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      OC_PRINTF("%d\n", (int)rep->value.integer);
      power = (int)rep->value.integer;
      break;
    case OC_REP_STRING:
      OC_PRINTF("%s\n", oc_string(rep->value.string));
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      break;
    }
    rep = rep->next;
  }
}

static void
post2_light(oc_client_response_t *data)
{
  OC_PRINTF("POST2_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    OC_PRINTF("POST response: CREATED\n");
  else
    OC_PRINTF("POST response code %d\n", data->code);

  oc_do_observe(a_light, light_server, NULL, &observe_light, LOW_QOS, NULL);
  oc_set_delayed_callback(NULL, &stop_observe, 30);
  OC_PRINTF("Sent OBSERVE request\n");
}

static void
post_light(oc_client_response_t *data)
{
  OC_PRINTF("POST_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    OC_PRINTF("POST response: CREATED\n");
  else
    OC_PRINTF("POST response code %d\n", data->code);

  if (oc_init_post(a_light, light_server, NULL, &post2_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, true);
    oc_rep_set_int(root, power, 55);
    oc_rep_end_root_object();
    if (oc_do_post())
      OC_PRINTF("Sent POST request\n");
    else
      OC_PRINTF("Could not send POST request\n");
  } else
    OC_PRINTF("Could not init POST request\n");
}

static void
put_light(oc_client_response_t *data)
{
  OC_PRINTF("PUT_light:\n");

  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("PUT response: CHANGED\n");
  else
    OC_PRINTF("PUT response code %d\n", data->code);

  if (oc_init_post(a_light, light_server, NULL, &post_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, false);
    oc_rep_set_int(root, power, 105);
    oc_rep_end_root_object();
    if (oc_do_post())
      OC_PRINTF("Sent POST request\n");
    else
      OC_PRINTF("Could not send POST request\n");
  } else
    OC_PRINTF("Could not init POST request\n");
}

static void
get_light(oc_client_response_t *data)
{
  OC_PRINTF("GET_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    OC_PRINTF("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_PRINTF("%d\n", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      OC_PRINTF("%d\n", (int)rep->value.integer);
      power = (int)rep->value.integer;
      break;
    case OC_REP_STRING:
      OC_PRINTF("%s\n", oc_string(rep->value.string));
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (oc_init_put(a_light, light_server, NULL, &put_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, true);
    oc_rep_set_int(root, power, 15);
    oc_rep_end_root_object();

    if (oc_do_put())
      OC_PRINTF("Sent PUT request\n");
    else
      OC_PRINTF("Could not send PUT request\n");
  } else
    OC_PRINTF("Could not init PUT request\n");
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)iface_mask;
  (void)bm;
  int i;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  OC_PRINTF("\n\nDISCOVERYCB %s %s %d\n\n", anchor, uri,
            (int)oc_string_array_get_allocated_size(types));
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    OC_PRINTF("\n\nDISCOVERED RES %s\n\n\n", t);
    if (strlen(t) == 10 && strncmp(t, "core.light", 10) == 0) {
      oc_endpoint_list_copy(&light_server, endpoint);
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      OC_PRINTF("Resource %s hosted at endpoints:\n", a_light);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        ep = ep->next;
      }

      oc_do_get(a_light, light_server, NULL, &get_light, LOW_QOS, NULL);

      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery("core.light", &discovery, NULL);
}

static void
signal_event_loop(void)
{
  WakeConditionVariable(&cv);
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = true;
  signal_event_loop();
}

static void
init(void)
{
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  signal(SIGINT, handle_signal);
}

static void
run_loop(void)
{
  oc_clock_time_t next_event_mt;
  while (!quit) {
    next_event_mt = oc_main_poll_v1();
    if (next_event_mt == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now_mt = oc_clock_time_monotonic();
      if (now_mt < next_event_mt) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }
}

int
main(void)
{
  init();

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = 0,
    .requests_entry = issue_requests,
  };

#ifdef OC_STORAGE
  oc_storage_config("./simpleclient_creds/");
#endif /* OC_STORAGE */

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    return ret;
  }
  run_loop();
  oc_main_shutdown();
  return 0;
}
