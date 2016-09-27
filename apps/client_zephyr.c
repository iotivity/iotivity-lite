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

#include <sections.h>
#include <string.h>
#include <zephyr.h>

#define MAX_URI_LENGTH (30)
static char light_1[MAX_URI_LENGTH];
static oc_server_handle_t light_server;
static bool light_state = false;
static struct nano_sem block;

static void
set_device_custom_property(void *data)
{
  oc_set_custom_device_property(purpose, "operate lamp");
}

static void
app_init(void)
{
  oc_init_platform("Apple", NULL, NULL);
  oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "1.0", "1.0",
                set_device_custom_property, NULL);
}

static oc_event_callback_retval_t
stop_observe(void *data)
{
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(light_1, &light_server);
  return DONE;
}

static void
put_light(oc_client_response_t *data)
{
  PRINT("PUT_light:\n");
  if (data->code == OC_STATUS_OK)
    PRINT("PUT response OK\n");
  else
    PRINT("PUT response code %d\n", data->code);
}

static void
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

  if (oc_init_put(light_1, &light_server, NULL, &put_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !light_state);
    oc_rep_end_root_object();
    if (oc_do_put())
      PRINT("Sent PUT request\n");
    else
      PRINT("Could not send PUT\n");
  } else
    PRINT("Could not init PUT\n");
}

static oc_discovery_flags_t
discovery(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t interfaces, oc_server_handle_t *server,
          void *user_data)
{
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  for (i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 11 && strncmp(t, "oic.r.light", 11) == 0) {
      memcpy(&light_server, server, sizeof(oc_server_handle_t));

      strncpy(light_1, uri, uri_len);
      light_1[uri_len] = '\0';

      oc_do_observe(light_1, &light_server, NULL, &observe_light, LOW_QOS,
                    NULL);
      oc_set_delayed_callback(NULL, &stop_observe, 30);
      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery("oic.r.light", &discovery, NULL);
}

void
signal_event_loop(void)
{
  nano_sem_give(&block);
}

void
main(void)
{
  static oc_handler_t handler = {.init = app_init,
                                 .signal_event_loop = signal_event_loop,
                                 .requests_entry = issue_requests };

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
