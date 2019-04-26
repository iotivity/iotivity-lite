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
#include "port/oc_clock.h"
#include <signal.h>
#include <windows.h>

int quit = 0;

static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

#define OC_PRETTY_PRINT_TAB_CHARACTER "  "
void oc_rep_print_tab(int tab_depth) {
    for (int i = 0; i < tab_depth; i++) {
        PRINT("%s", OC_PRETTY_PRINT_TAB_CHARACTER);
    }
}

void oc_rep_print_format(oc_rep_t *rep, int tab_depth, bool pretty_print) {
    while (rep != NULL) {
        if (pretty_print) oc_rep_print_tab(tab_depth + 1);
        PRINT("\"%s\" : ", oc_string(rep->name));
        switch (rep->type) {
        case OC_REP_NIL:
            PRINT("null");
            break;
        case OC_REP_INT:
            PRINT("%lld", rep->value.integer);
            break;
        case OC_REP_DOUBLE:
            PRINT("%f", rep->value.double_p);
            break;
        case OC_REP_BOOL:
            PRINT("%s", (rep->value.boolean) ? "true" : "false");
            break;
        case OC_REP_STRING:
            PRINT("%s", oc_string(rep->value.string));
            break;
        case OC_REP_OBJECT:
            (pretty_print) ? PRINT("{\n") : PRINT("{");
            oc_rep_print_format(rep->value.object, tab_depth + 1, pretty_print);
            if (pretty_print) oc_rep_print_tab(tab_depth + 1);
            PRINT("}");
            break;
        case OC_REP_INT_ARRAY:
            PRINT("[");
            int64_t *int_array;
            size_t int_array_size = 0;
            oc_rep_get_bool_array(rep, oc_string(rep->name), &int_array, &int_array_size);
            for (size_t i = 0; i < int_array_size; i++) {
                if (pretty_print) oc_rep_print_tab(tab_depth + 2);
                PRINT("%lld", int_array[i]);
                if (i < int_array_size - 1) {
                    PRINT(", ");
                }
            }
            PRINT("]");
            break;
        case OC_REP_BOOL_ARRAY:
            PRINT("[");
            bool *bool_array;
            size_t bool_array_size = 0;
            oc_rep_get_bool_array(rep, oc_string(rep->name), &bool_array, &bool_array_size);
            for (size_t i = 0; i < bool_array_size; i++) {
                if (pretty_print) oc_rep_print_tab(tab_depth + 2);
                PRINT("\"%s\"", (bool_array[i]) ? "true" : "false");
                if (i < bool_array_size - 1) {
                    PRINT(", ");
                }
            }
            PRINT("]");
            break;
        case OC_REP_STRING_ARRAY:
            (pretty_print) ? PRINT("[\n") : PRINT("[");
            oc_string_array_t str_array;
            size_t str_array_size = 0;
            oc_rep_get_string_array(rep, oc_string(rep->name), &str_array, &str_array_size);
            for (size_t i = 0; i < str_array_size; i++) {
                if (pretty_print) oc_rep_print_tab(tab_depth + 2);
                PRINT("\"%s\"", oc_string_array_get_item(str_array, i));
                if (i < str_array_size - 1) {
                    (pretty_print) ? PRINT(",\n") : PRINT(", ");
                }  else {
                    if (pretty_print) PRINT("\n");
                }
            }
            if (pretty_print) oc_rep_print_tab(tab_depth + 1);
            PRINT("]");
            break;
        case OC_REP_OBJECT_ARRAY:
            oc_rep_t *rep_array = rep->value.object_array;
            PRINT("[");
            if (pretty_print)  PRINT("\n");
            do {
                oc_rep_t *rep_item = rep_array->value.object;
                if (pretty_print) oc_rep_print_tab(tab_depth + 2);
                (pretty_print) ? PRINT("{\n") : PRINT("{");
                oc_rep_print_format(rep_item, tab_depth + 2, pretty_print);
                rep_array = rep_array->next;
                if (rep_array) {
                    if (pretty_print) oc_rep_print_tab(tab_depth + 2);
                    (pretty_print) ? PRINT("},\n") : PRINT("},");
                }
            } while (rep_array);
            if (pretty_print) oc_rep_print_tab(tab_depth + 2);
            PRINT("}]");
            break;
        default:
            PRINT("UNHANDLED TYPE 0x%.2X", rep->type);
            break;
        }
        rep = rep->next;
        if (rep != NULL) PRINT(",");
        (pretty_print) ? PRINT("\n") : PRINT(" ");
    }
}

void oc_rep_print(oc_rep_t *rep, bool pretty_print) {
    PRINT("{");
    if (pretty_print) PRINT("\n");
    if (pretty_print) {
        oc_rep_print_format(rep, 0, pretty_print);
    } else {
        oc_rep_print_format(rep, 0, pretty_print);
    }
    PRINT("}");
    if (pretty_print) PRINT("\n");
}



static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (128)
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;

static char wk_introspection_uri[MAX_URI_LENGTH];
static char introspection_data_uri[MAX_URI_LENGTH];
static oc_endpoint_t *wk_introspection_server;
typedef struct uri_info_s {
    oc_string_t url;
    oc_string_t protocol;
} uri_info_t;

static uri_info_t uri_info;

static bool state;
static int power;
static oc_string_t name;

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(a_light, light_server);
  return OC_EVENT_DONE;
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
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      PRINT("%lld\n", rep->value.integer);
      power = (int)rep->value.integer;
      break;
    case OC_REP_STRING:
      PRINT("%s\n", oc_string(rep->value.string));
      if (oc_string_len(name))
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
  PRINT("POST2_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    PRINT("POST response: CREATED\n");
  else
    PRINT("POST response code %d\n", data->code);

  oc_do_observe(a_light, light_server, NULL, &observe_light, LOW_QOS, NULL);
  oc_set_delayed_callback(NULL, &stop_observe, 2);
  PRINT("Sent OBSERVE request\n");
}

static void
post_light(oc_client_response_t *data)
{
  PRINT("POST_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    PRINT("POST response: CREATED\n");
  else
    PRINT("POST response code %d\n", data->code);

  if (oc_init_post(a_light, light_server, NULL, &post2_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, true);
    oc_rep_set_int(root, power, 55);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST request\n");
  } else
    PRINT("Could not init POST request\n");
}

static void
put_light(oc_client_response_t *data)
{
  PRINT("PUT_light:\n");

  if (data->code == OC_STATUS_CHANGED)
    PRINT("PUT response: CHANGED\n");
  else
    PRINT("PUT response code %d\n", data->code);

  if (oc_init_post(a_light, light_server, NULL, &post_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, false);
    oc_rep_set_int(root, power, 105);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST request\n");
  } else
    PRINT("Could not init POST request\n");
}

static void
get_light(oc_client_response_t *data)
{
  PRINT("GET_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      PRINT("%d\n", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      PRINT("%lld\n", rep->value.integer);
      power = (int)rep->value.integer;
      break;
    case OC_REP_STRING:
      PRINT("%s\n", oc_string(rep->value.string));
      if (oc_string_len(name))
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
      PRINT("Sent PUT request\n");
    else
      PRINT("Could not send PUT request\n");
  } else
    PRINT("Could not init PUT request\n");
}

static void get_wk_introspection(oc_client_response_t *data);

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
  PRINT("\n\nDISCOVERYCB %s %s %zd\n", anchor, uri,
        oc_string_array_get_allocated_size(types));
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    PRINT("DISCOVERED RES %s\n\n\n", t);
    if (strlen(t) == 10 && strncmp(t, "core.light", 10) == 0) {
      light_server = endpoint;
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      PRINT("Resource %s hosted at endpoints:\n", a_light);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }

      oc_do_get(a_light, light_server, NULL, &get_light, LOW_QOS, NULL);

      return OC_STOP_DISCOVERY;
    }
    if (strlen(t) == 20 && strncmp(t, "oic.wk.introspection", 20) == 0) {
        wk_introspection_server = endpoint;
        strncpy(wk_introspection_uri, uri, uri_len);
        wk_introspection_uri[uri_len] = '\0';

        PRINT("Resource %s hosted at endpoints:\n", wk_introspection_uri);
        oc_endpoint_t *ep = endpoint;
        while (ep != NULL) {
            PRINTipaddr(*ep);
            PRINT("\n");
            ep = ep->next;
        }

        oc_do_get(wk_introspection_uri, wk_introspection_server, NULL, &get_wk_introspection, LOW_QOS, NULL);
        return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}

static void
get_introspection_data(oc_client_response_t *data) {
    PRINT("\n\nGET_introspection_data:\n");
    oc_rep_t *rep = data->payload;
    oc_rep_print(rep, false);
}

static void
get_wk_introspection(oc_client_response_t *data)
{
    PRINT("\n\nGET_wk_introspection:\n");
    oc_rep_t *rep = data->payload;
    oc_rep_print(rep, false);

    while (rep != NULL) {
        switch (rep->type) {
        case OC_REP_OBJECT_ARRAY:
            oc_rep_t *rep_array = rep->value.object_array;
            do {
                oc_rep_t *rep_item = rep_array->value.object;
                while (rep_item != NULL) {
                    if (strncmp("url", oc_string(rep_item->name), oc_string_len(rep_item->name)) == 0) {
                        //strncpy(introspection_data_uri, oc_string(rep_item->value.string), MAX_URI_LENGTH);
                        strncpy(introspection_data_uri, "/oc/introspection", MAX_URI_LENGTH);
                        introspection_data_uri[MAX_URI_LENGTH - 1] = '\0';
                    }
                    rep_item = rep_item->next;
                }
                rep_array = rep_array->next;
            } while (rep_array);
            break;
        default:
            break;
        }
        rep = rep->next;
    }
    oc_do_get(introspection_data_uri, wk_introspection_server, NULL, &get_introspection_data, LOW_QOS, NULL);
    //oc_do_ip_discovery("core.light", &discovery, NULL);
}

static void
issue_requests(void)
{
  oc_do_ip_discovery("oic.wk.introspection", &discovery, NULL);
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

  signal(SIGINT, handle_signal);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = 0,
                                       .requests_entry = issue_requests };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./simpleclient_creds/");
#endif /* OC_SECURITY */

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
          SleepConditionVariableCS(&cv, &cs,
              (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }

  oc_main_shutdown();
  return 0;
}
