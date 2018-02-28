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

#include <string.h>
#include <zephyr.h>

#define MAX_URI_LENGTH (30)
static char light_1[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;
static bool light_state = false;
static struct k_sem block;
static bool got_discovery_response = false;

static void
set_device_custom_property(void *data)
{
  (void)data;
  oc_set_custom_device_property(purpose, "operate lamp");
}

static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "1.0", "1.0",
                       set_device_custom_property, NULL);
  return ret;
}

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(light_1, light_server);
  return OC_EVENT_DONE;
}

static void
post_light(oc_client_response_t *data)
{
  PRINT("POST_light:\n");
  if (data->code == OC_STATUS_OK)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);
}

static void
observe_light(oc_client_response_t *data)
{
  PRINT("OBSERVE_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      PRINT("%d\n", rep->value.boolean);
      light_state = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (oc_init_post(light_1, light_server, NULL, &post_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !light_state);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST\n");
  } else
    PRINT("Could not init POST\n");
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)interfaces;
  (void)user_data;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 11 && strncmp(t, "oic.r.light", 11) == 0) {
      light_server = endpoint;

      strncpy(light_1, uri, uri_len);
      light_1[uri_len] = '\0';

      oc_do_observe(light_1, light_server, NULL, &observe_light, LOW_QOS, NULL);
      oc_set_delayed_callback(NULL, &stop_observe, 30);

      got_discovery_response = true;
      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static oc_event_callback_retval_t
do_discovery(void *data)
{
  (void)data;
  if (got_discovery_response) {
    return OC_EVENT_DONE;
  }
  oc_do_ip_discovery("oic.r.light", &discovery, NULL);
  return OC_EVENT_CONTINUE;
}

static void
issue_requests(void)
{
  oc_set_delayed_callback(NULL, &do_discovery, 10);
}

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
                                       .requests_entry = issue_requests };

  k_sem_init(&block, 0, 1);

  if (oc_main_init(&handler) < 0)
    return;

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
