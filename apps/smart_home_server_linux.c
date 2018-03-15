/*
// Copyright (c) 2017 Intel Corporation
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

#include <pthread.h>
#include <signal.h>
#include <stdio.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

static double temp_C = 5.0, min_C = 0.0, max_C = 100.0, min_K = 273.15,
              max_K = 373.15, min_F = 32, max_F = 212;
typedef enum { C = 100, F, K } units_t;
static bool switch_state, pswitch_state;

static int
app_init(void)
{
  int err = oc_init_platform("Intel", NULL, NULL);

  err |= oc_add_device("/oic/d", "oic.d.switch", "Temp_sensor", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return err;
}

static void
get_temp(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  PRINT("GET_temp:\n");
  bool invalid_query = false;
  double temp = temp_C;
  units_t temp_units = C;
  char *units;
  int units_len = oc_get_query_value(request, "units", &units);
  if (units_len != -1) {
    if (units[0] == 'K') {
      temp = temp_C + 273.15;
      temp_units = K;
    } else if (units[0] == 'F') {
      temp = (temp_C / 100) * 180 + 32;
      temp_units = F;
    } else if (units[0] != 'C')
      invalid_query = true;
  }

  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    oc_rep_set_text_string(root, id, "home_thermostat");
  /* fall through */
  case OC_IF_A:
  case OC_IF_S:
    oc_rep_set_double(root, temperature, temp);
    switch (temp_units) {
    case C:
      oc_rep_set_text_string(root, units, "C");
      break;
    case F:
      oc_rep_set_text_string(root, units, "F");
      break;
    case K:
      oc_rep_set_text_string(root, units, "K");
      break;
    }
    break;
  default:
    break;
  }

  if (!invalid_query) {
    oc_rep_set_array(root, range);
    switch (temp_units) {
    case C:
      oc_rep_add_double(range, min_C);
      oc_rep_add_double(range, max_C);
      break;
    case K:
      oc_rep_add_double(range, min_K);
      oc_rep_add_double(range, max_K);
      break;
    case F:
      oc_rep_add_double(range, min_F);
      oc_rep_add_double(range, max_F);
      break;
    }
    oc_rep_close_array(root, range);
  }

  oc_rep_end_root_object();

  if (invalid_query)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_OK);
}

static void
post_temp(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  PRINT("POST_temp:\n");
  bool out_of_range = false;
  double temp = -1;

  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_DOUBLE:
      temp = rep->value.double_p;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (temp < min_C || temp > max_C)
    out_of_range = true;

  temp_C = temp;

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, id, "home_thermostat");
  oc_rep_set_double(root, temperature, temp_C);
  oc_rep_set_text_string(root, units, "C");
  oc_rep_set_array(root, range);
  oc_rep_add_double(range, min_C);
  oc_rep_add_double(range, max_C);
  oc_rep_close_array(root, range);
  oc_rep_end_root_object();

  if (out_of_range)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
get_pswitch(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;
  PRINT("GET_pswitch:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    oc_rep_set_text_string(root, id, "purifier_switch");
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, pswitch_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);
}

static void
post_pswitch(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  (void)interface;
  (void)user_data;
  PRINT("POST_pswitch:\n");
  bool state = false, bad_request = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      break;
    default:
      if (oc_string_len(rep->name) > 2) {
        if (strncmp(oc_string(rep->name), "x.", 2) == 0) {
          break;
        }
      }
      bad_request = true;
      break;
    }
    rep = rep->next;
  }

  if (!bad_request) {
    pswitch_state = state;
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, pswitch_state);
  oc_rep_end_root_object();

  if (!bad_request) {
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
get_switch(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)user_data;
  PRINT("GET_switch:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    oc_rep_set_text_string(root, id, "thermostat_switch");
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, switch_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);
}

static void
post_switch(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)interface;
  (void)user_data;
  PRINT("POST_switch:\n");
  bool state = false, bad_request = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      break;
    default:
      if (oc_string_len(rep->name) > 2) {
        if (strncmp(oc_string(rep->name), "x.", 2) == 0) {
          break;
        }
      }
      bad_request = true;
      break;
    }
    rep = rep->next;
  }

  if (!bad_request) {
    switch_state = state;
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, switch_state);
  oc_rep_end_root_object();

  if (!bad_request) {
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
register_resources(void)
{
  oc_resource_t *temp = oc_new_resource("tempsensor", "/temp", 1, 0);
  oc_resource_bind_resource_type(temp, "oic.r.temperature");
  oc_resource_bind_resource_interface(temp, OC_IF_A);
  oc_resource_bind_resource_interface(temp, OC_IF_S);
  oc_resource_set_default_interface(temp, OC_IF_A);
  oc_resource_set_discoverable(temp, true);
  oc_resource_set_periodic_observable(temp, 1);
  oc_resource_set_request_handler(temp, OC_GET, get_temp, NULL);
  oc_resource_set_request_handler(temp, OC_POST, post_temp, NULL);
  oc_add_resource(temp);

  oc_resource_t *bswitch = oc_new_resource("smartbutton", "/switch", 1, 0);
  oc_resource_bind_resource_type(bswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(bswitch, OC_IF_A);
  oc_resource_set_default_interface(bswitch, OC_IF_A);
  oc_resource_set_discoverable(bswitch, true);
  oc_resource_set_request_handler(bswitch, OC_GET, get_switch, NULL);
  oc_resource_set_request_handler(bswitch, OC_POST, post_switch, NULL);
  oc_add_resource(bswitch);

  oc_resource_t *pbswitch =
    oc_new_resource("purifierswitch", "/purifier_switch", 1, 0);
  oc_resource_bind_resource_type(pbswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(pbswitch, OC_IF_A);
  oc_resource_set_default_interface(pbswitch, OC_IF_A);
  oc_resource_set_discoverable(pbswitch, true);
  oc_resource_set_request_handler(pbswitch, OC_GET, get_pswitch, NULL);
  oc_resource_set_request_handler(pbswitch, OC_POST, post_pswitch, NULL);
  oc_add_resource(pbswitch);

#ifdef OC_COLLECTIONS
  oc_resource_t *col = oc_new_collection("dashboard", "/platform", 1, 0);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);
  oc_link_t *l1 = oc_new_link(temp);
  oc_collection_add_link(col, l1);

  oc_link_t *l2 = oc_new_link(bswitch);
  oc_collection_add_link(col, l2);

  oc_link_t *l3 = oc_new_link(pbswitch);
  oc_collection_add_link(col, l3);
  oc_add_collection(col);
#endif /* OC_COLLECTIONS */
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

int
main(void)
{
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

  oc_clock_time_t next_event;

  oc_set_mtu_size(2048);
  oc_set_max_app_data_size(8192);

#ifdef OC_SECURITY
  oc_storage_config("./smart_home_server_linux_creds");
#endif /* OC_SECURITY */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  oc_main_shutdown();

  return 0;
}
