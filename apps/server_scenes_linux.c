/*
// Copyright (c) 2016 Intel Corporation
// Copyright (c) 2017 Lynx Technology
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

/**
@brief Server-side example for scene handling.
@file
*/

#include "oc_api.h"
#include "port/oc_clock.h"

#if defined(OC_COLLECTIONS) && defined(OC_SCENES)
#include <stdlib.h>
#include "include/oc_scene.h"
#include "include/oc_collection.h"
#endif

#include <pthread.h>
#include <signal.h>
#include <stdio.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;
static bool light_state = false;
static int brightness;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Kishen's light", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);

  return ret;
}

static void
get_brightness(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  PRINT("GET_brightness:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_R:
    oc_rep_set_int(root, brightness, brightness);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_brightness(oc_request_t *request, oc_interface_mask_t interface,
                void *user_data)
{
  (void)interface;
  (void)user_data;
  PRINT("POST_brightness:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      brightness = rep->value.integer;
      PRINT("value: %d\n", brightness);
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  oc_rep_start_root_object();
  oc_rep_set_int(root, brightness, brightness);
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_CHANGED);
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
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)interface;
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
put_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  post_light(request, interface, user_data);
}

#if defined(OC_COLLECTIONS) && defined(OC_SCENES)
static void
post_scene(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)interface;
  (void)user_data;

  oc_collection_t *scene_col = (oc_collection_t *)request->resource;
  const char *scene_value = oc_string(scene_col->last_scene);
  PRINT("POST_scene: %s\n", scene_value);

  oc_link_t *link = oc_list_head(scene_col->links);
  while (link != NULL) {
    oc_scene_member_t *member = (oc_scene_member_t *)link->resource;
    oc_scene_mapping_t *mapping =
      (oc_scene_mapping_t *)oc_list_head(member->scene_mapping);
    while (mapping != NULL) {
      if (strcmp(scene_value, oc_string(mapping->scene)) == 0) {
        /* simplified, actually we would require posting the update to the
         * resource */
        PRINT("\ttriggering %s: %s=%s\n", oc_string(member->resource->uri),
              oc_string(mapping->property), oc_string(mapping->value));
        if (strcmp(oc_string(mapping->property), "state") == 0) {
          light_state = (atoi(oc_string(mapping->value)) ? true : false);
        } else if (strcmp(oc_string(mapping->property), "brightness") == 0) {
          brightness = atoi(oc_string(mapping->value));
        }
        /* continue, there may be multiple properties per resource */
      }
      mapping = mapping->next;
    }
    link = link->next;
  }

  /* This is an internal callback. Do NOT add or send a response here. */
}
#endif /* OC_COLLECTIONS && OC_SCENES */

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

  oc_resource_t *res2 = oc_new_resource("brightness", "/brightness/1", 1, 0);
  oc_resource_bind_resource_type(res2, "oic.r.light.brightness");
  oc_resource_bind_resource_interface(res2, OC_IF_A);
  oc_resource_set_default_interface(res2, OC_IF_A);
  oc_resource_set_discoverable(res2, true);
  oc_resource_set_periodic_observable(res2, 1);
  oc_resource_set_request_handler(res2, OC_GET, get_brightness, NULL);
  oc_resource_set_request_handler(res2, OC_POST, post_brightness, NULL);
  oc_add_resource(res2);

#if defined(OC_COLLECTIONS) && defined(OC_SCENES)
  oc_resource_t *scene_col = oc_new_scene_collection("/scene_col/my_livingroom", 0);
  oc_resource_set_discoverable(scene_col, true);
  /* post_scene is invoked when a scene is set. This is a work-around
     until the stack can apply the device values itself. */
  oc_resource_set_request_handler(scene_col, OC_POST, post_scene, NULL);
  oc_add_scene_collection(scene_col);

  oc_resource_t *scene_light = oc_new_scene_member("/scene_member/light", res1);
  oc_resource_set_discoverable(scene_light, true);
  oc_add_scene_mapping(scene_light, "on", "state", "1");
  oc_add_scene_mapping(scene_light, "dim", "state", "1");
  oc_add_scene_mapping(scene_light, "off", "state", "0");
  oc_add_scene_member(scene_col, scene_light);

  oc_resource_t *scene_brightness = oc_new_scene_member("/scene_member/brightness", res2);
  oc_resource_set_discoverable(scene_brightness, true);
  oc_add_scene_mapping(scene_brightness, "on", "brightness", "100");
  oc_add_scene_mapping(scene_brightness, "dim", "brightness", "50");
  /* no use to have off scene for brightness, because the light is then off anyway */
  oc_add_scene_member(scene_col, scene_brightness);
#endif /* OC_COLLECTIONS && OC_SCENES */
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

#ifdef OC_SECURITY
  oc_storage_config("./server_scenes_linux_creds");
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
