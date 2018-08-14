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
  @brief Client-side example for scene handling.
  @file
*/

#include "oc_api.h"
#include "port/oc_clock.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

#define MAX_URI_LENGTH (30)
static char scene_uri[MAX_URI_LENGTH];
static oc_endpoint_t *scene_server;
static int current_scene = -1;
static oc_string_array_t scenes;

#define SPACES(n) (2*(n)), ""

static void
dump_rep(oc_rep_t *rep, int n)
{
  PRINT("%*s{\n", SPACES(n));
  n += 2;
  while (rep != NULL) {
    if (oc_string_len(rep->name) > 0)
      PRINT("%*skey: %s value: ", SPACES(n), oc_string(rep->name));
    switch (rep->type) {
      case OC_REP_STRING:
        PRINT("%s\n", oc_string(rep->value.string));
        break;
      case OC_REP_STRING_ARRAY: {
        PRINT("[ ");
        size_t i;
        for (i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array);
             i++) {
          PRINT(" %s ", oc_string_array_get_item(rep->value.array, i));
        }
        PRINT(" ]\n");

        if (oc_string_len(rep->name) > 0 &&
            strcmp(oc_string(rep->name), "sceneValues") == 0 &&
            oc_string_array_get_allocated_size(scenes) == 0) {
          oc_new_string_array(&scenes, oc_string_array_get_allocated_size(rep->value.array));
          for (i = 0;
               i < oc_string_array_get_allocated_size(rep->value.array);
               i++) {
            oc_string_array_add_item(scenes, oc_string_array_get_item(rep->value.array, i));
          }
        }
      } break;
      case OC_REP_BOOL:
        PRINT("%d\n", rep->value.boolean);
        break;
      case OC_REP_INT:
        PRINT("%d\n", rep->value.integer);
        break;
      case OC_REP_OBJECT:
      case OC_REP_OBJECT_ARRAY:
        PRINT("\n");
        dump_rep(rep->value.object, n + 2);
        break;
      default:
        break;
    }
    rep = rep->next;
  }
  n -= 2;
  PRINT("%*s}\n", SPACES(n));
}

static void
post_scene_response(oc_client_response_t *data)
{
  PRINT("\nPOST_scene_response:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);
  dump_rep(data->payload, 0);
}

static void handle_signal(int signal);

static oc_event_callback_retval_t
trigger_scene(void *data)
{
  (void)data;
  if (++current_scene < (int)oc_string_array_get_allocated_size(scenes))
  {
    const char *scene = oc_string_array_get_item(scenes, current_scene);
    PRINT("--> Triggering scene %s\n", scene);
    if (oc_init_post(scene_uri, scene_server, "if=oic.if.a", &post_scene_response,
                     LOW_QOS, NULL)) {
      oc_rep_start_root_object();
      oc_rep_set_text_string(root, lastScene, scene);
      oc_rep_end_root_object();

      if (oc_do_post())
        PRINT("Sent POST request\n\n");
      else
        PRINT("Could not send POST\n\n");
    }
    else
      PRINT("Could not init POST\n\n");

    return OC_EVENT_CONTINUE;
  }
  oc_free_string_array(&scenes);
  PRINT("So long, and thanks for all the fish!\n");
  handle_signal(0);
  return OC_EVENT_DONE;
}

static void
get_scene_collection_oic_if_baseline(oc_client_response_t *data)
{
  PRINT("\nGET_scene_collection_oic_if_baseline:\n");
  dump_rep(data->payload, 0);
  oc_set_delayed_callback(NULL, &trigger_scene, 3);
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
  size_t i;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  for (i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    PRINT("\ntype: %s\n", t);
    if (strlen(t) == 22 && strncmp(t, "oic.wk.scenecollection", 22) == 0) {
      scene_server = endpoint;

      strncpy(scene_uri, uri, uri_len);
      scene_uri[uri_len] = '\0';

      PRINT("\nSending GET %s?if=oic.if.baseline\n\n", scene_uri);

      oc_do_get(scene_uri, scene_server, "if=oic.if.baseline", &get_scene_collection_oic_if_baseline,
                LOW_QOS, NULL);

      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery("oic.wk.scenecollection", &discovery, NULL);
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

static int
app_init(void)
{
  int ret = oc_init_platform("Linux", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.client", "Scene Client", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
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
                                       .requests_entry = issue_requests };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./client_scenes_linux_creds");
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
