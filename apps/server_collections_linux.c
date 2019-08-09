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

#include <pthread.h>
#include <signal.h>
#include <stdio.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;
static bool light_state = false;
static int counter;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Kishen's light", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
get_count(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)user_data;
  PRINT("GET_count:\n");
  counter++;
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R:
    oc_rep_set_int(root, count, counter);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_count(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)interface;
  (void)user_data;
  PRINT("POST_count:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      counter = (int)rep->value.integer;
      PRINT("value: %d\n", counter);
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  oc_rep_start_root_object();
  oc_rep_set_int(root, count, counter);
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
get_light(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)user_data;
  PRINT("GET_light:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, light_state);
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
      light_state = rep->value.boolean;
      PRINT("value: %d\n", light_state);
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, state, light_state);
  oc_rep_end_root_object();

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

#ifdef OC_COLLECTIONS_IF_CREATE
/* Resource creation and request handlers for oic.r.energy.consumption instances
 */
typedef struct oc_ec_t
{
  struct oc_ec_t *next;
  oc_resource_t *resource;
  double power;
  double energy;
} oc_ec_t;
OC_MEMB(ec_s, oc_ec_t, 1);
OC_LIST(ecs);

bool
set_ec_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
  (void)resource;
  oc_ec_t *ec = (oc_ec_t *)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_DOUBLE:
      if (oc_string_len(rep->name) == 5 &&
          memcmp(oc_string(rep->name), "power", 5) == 0) {
        ec->power = rep->value.double_p;
      } else if (oc_string_len(rep->name) == 6 &&
                 memcmp(oc_string(rep->name), "energy", 6) == 0) {
        ec->energy = rep->value.double_p;
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
get_ec_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                  void *data)
{
  oc_ec_t *ec = (oc_ec_t *)data;
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(resource);
  /* fall through */
  case OC_IF_S:
    oc_rep_set_double(root, power, ec->power);
    oc_rep_set_double(root, energy, ec->energy);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

void
get_ec(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  get_ec_properties(request->resource, iface_mask, user_data);
  oc_send_response(request, OC_STATUS_OK);
}

oc_resource_t *
get_ec_instance(const char *href, oc_string_array_t *types,
                oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
                size_t device)
{
  oc_ec_t *ec = (oc_ec_t *)oc_memb_alloc(&ec_s);
  if (ec) {
    ec->resource = oc_new_resource(
      NULL, href, oc_string_array_get_allocated_size(*types), device);
    if (ec->resource) {
      size_t i;
      for (i = 0; i < oc_string_array_get_allocated_size(*types); i++) {
        const char *rt = oc_string_array_get_item(*types, i);
        oc_resource_bind_resource_type(ec->resource, rt);
      }
      oc_resource_bind_resource_interface(ec->resource, iface_mask);
      ec->resource->properties = bm;
      oc_resource_set_default_interface(ec->resource, OC_IF_A);
      oc_resource_set_request_handler(ec->resource, OC_GET, get_ec, ec);
      oc_resource_set_properties_cbs(ec->resource, get_ec_properties, ec,
                                     set_ec_properties, ec);
      oc_add_resource(ec->resource);

      oc_list_add(ecs, ec);
      return ec->resource;
    } else {
      oc_memb_free(&ec_s, ec);
    }
  }
  return NULL;
}

void
free_ec_instance(oc_resource_t *resource)
{
  oc_ec_t *ec = (oc_ec_t *)oc_list_head(ecs);
  while (ec) {
    if (ec->resource == resource) {
      oc_delete_resource(resource);
      oc_list_remove(ecs, ec);
      oc_memb_free(&ec_s, ec);
      return;
    }
    ec = ec->next;
  }
}
#endif /* OC_COLLECTIONS_IF_CREATE */

static void
register_resources(void)
{
  oc_resource_t *res1 = oc_new_resource("lightbulb", "/light/1", 1, 0);
  oc_resource_bind_resource_type(res1, "oic.r.light");
  oc_resource_bind_resource_interface(res1, OC_IF_RW);
  oc_resource_set_default_interface(res1, OC_IF_RW);
  oc_resource_set_discoverable(res1, true);
  oc_resource_set_periodic_observable(res1, 1);
  oc_resource_set_request_handler(res1, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res1, OC_POST, post_light, NULL);
  oc_resource_set_request_handler(res1, OC_PUT, put_light, NULL);
  oc_add_resource(res1);

  oc_resource_t *res2 = oc_new_resource("counter", "/count/1", 1, 0);
  oc_resource_bind_resource_type(res2, "oic.r.counter");
  oc_resource_bind_resource_interface(res2, OC_IF_R);
  oc_resource_set_default_interface(res2, OC_IF_R);
  oc_resource_set_discoverable(res2, true);
  oc_resource_set_periodic_observable(res2, 1);
  oc_resource_set_request_handler(res2, OC_GET, get_count, NULL);
  oc_resource_set_request_handler(res2, OC_POST, post_count, NULL);
  oc_add_resource(res2);

#if defined(OC_COLLECTIONS)
  oc_resource_t *col = oc_new_collection("roomlights", "/lights", 1, 0);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);

  oc_link_t *l1 = oc_new_link(res1);
  oc_collection_add_link(col, l1);

  oc_link_t *l2 = oc_new_link(res2);
  oc_collection_add_link(col, l2);

  oc_collection_add_supported_rt(col, "oic.r.counter");
  oc_collection_add_supported_rt(col, "oic.r.light");
  oc_collection_add_supported_rt(col, "oic.r.energy.consumption");

#ifdef OC_COLLECTIONS_IF_CREATE
  oc_collections_add_rt_factory("oic.r.energy.consumption", get_ec_instance,
                                free_ec_instance);
#endif /* OC_COLLECTIONS_IF_CREATE */

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

#ifdef OC_STORAGE
  oc_storage_config("./server_collections_linux_creds");
#endif /* OC_STORAGE */

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
