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

static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char lights[MAX_URI_LENGTH];
static oc_endpoint_t *lights_server;
static bool do_once = true;
static void get_lights_oic_if_b(oc_client_response_t *data);

#ifdef OC_COLLECTIONS_IF_CREATE
static oc_discovery_flags_t
dishand(const char *anchor, const char *uri, oc_string_array_t types,
        oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
        oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)interfaces;
  (void)user_data;
  (void)bm;
  (void)endpoint;

  PRINT("\n\nURI %s\n\n", uri);

  (void)types;
  (void)interfaces;

  return OC_CONTINUE_DISCOVERY;
}

static void
post_lights_oic_if_create(oc_client_response_t *data)
{
  (void)data;
  PRINT("\n\nPOST_lights:oic_if_create\n\n");

  oc_rep_t *rep = data->payload;

  while (rep) {
    PRINT("\n\nKey: %s\t\t", oc_string(rep->name));

    switch (rep->type) {
    case OC_REP_STRING:
      PRINT("%s\n\n", oc_string(rep->value.string));
      break;
    case OC_REP_STRING_ARRAY: {
      size_t i;
      for (i = 0; i < oc_string_array_get_allocated_size(rep->value.array);
           i++) {

        PRINT(" %s ", oc_string_array_get_item(rep->value.array, i));
      }
      PRINT("\n");
    } break;
    case OC_REP_INT:
      PRINT(" %d\n", rep->value.integer);
      break;
    case OC_REP_OBJECT: {
      oc_rep_t *policy = rep->value.object;
      ;

      while (policy) {
        PRINT("\t\t%s\t\t", oc_string(policy->name));
        switch (policy->type) {
        case OC_REP_INT:
          PRINT(" %d ", policy->value.integer);
          break;
        default:
          break;
        }
        policy = policy->next;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  oc_do_ip_discovery_at_endpoint(NULL, dishand, lights_server, NULL);
}
#endif /* OC_COLLECTIONS_IF_CREATE */

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(lights, lights_server);

#ifdef OC_COLLECTIONS_IF_CREATE
  PRINT("\nSending POST %s?if=oic.if.create \n", lights);

  if (oc_init_post(lights, lights_server, "if=oic.if.create",
                   &post_lights_oic_if_create, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_array(root, rt);
    oc_rep_add_text_string(rt, "oic.r.energy.consumption");
    oc_rep_close_array(root, rt);
    oc_rep_set_array(root, if);
    oc_rep_add_text_string(if, "oic.if.s");
    oc_rep_add_text_string(if, "oic.if.baseline");
    oc_rep_close_array(root, if);
    oc_rep_set_object(root, p);
    oc_rep_set_uint(p, bm, 3);
    oc_rep_close_object(root, p);
    oc_rep_set_object(root, rep);
    oc_rep_set_array(rep, rt);
    oc_rep_add_text_string(rt, "oic.r.energy.consumption");
    oc_rep_close_array(rep, rt);
    oc_rep_set_array(rep, if);
    oc_rep_add_text_string(if, "oic.if.s");
    oc_rep_add_text_string(if, "oic.if.baseline");
    oc_rep_close_array(rep, if);
    oc_rep_set_double(rep, power, 25.0);
    oc_rep_set_double(rep, energy, 30.0);
    oc_rep_close_object(root, rep);
    oc_rep_end_root_object();

    if (oc_do_post())
      PRINT("Sent POST request\n\n");
    else
      PRINT("Could not send POST\n\n");
  } else
    PRINT("Could not init POST\n\n");
#endif /* OC_COLLECTIONS_IF_CREATE */
  return OC_EVENT_DONE;
}

static void
post_lights_oic_if_b(oc_client_response_t *data)
{
  PRINT("\nPOST_lights_oic_if_b:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);

  oc_rep_t *ll = data->payload;

  while (ll != NULL) {
    PRINT("\tLink:\n");
    oc_rep_t *link = ll->value.object;
    while (link != NULL) {
      switch (link->type) {
      case OC_REP_STRING:
        PRINT("\t\tkey: %s value: %s\n", oc_string(link->name),
              oc_string(link->value.string));
        break;
      case OC_REP_OBJECT: {
        PRINT("\t\tkey: %s value: { ", oc_string(link->name));
        oc_rep_t *rep = link->value.object;
        while (rep != NULL) {
          switch (rep->type) {
          case OC_REP_BOOL:
            PRINT(" %s : %d ", oc_string(rep->name), rep->value.boolean);
            break;
          case OC_REP_INT:
            PRINT(" %s : %lld ", oc_string(rep->name), rep->value.integer);
            break;
          default:
            break;
          }
          rep = rep->next;
        }
        PRINT(" }\n\n");
      } break;
      default:
        break;
      }
      link = link->next;
    }
    ll = ll->next;
  }

  PRINT("\nSending OBSERVE %s?if=oic.if.b\n\n", lights);

  oc_do_observe(lights, lights_server, "if=oic.if.b", &get_lights_oic_if_b,
                LOW_QOS, NULL);
  oc_set_delayed_callback(NULL, &stop_observe, 5);
}

static void
get_lights_oic_if_b(oc_client_response_t *data)
{
  PRINT("\nGET_lights_oic_if_b:\n");
  oc_rep_t *ll = data->payload;

  while (ll != NULL) {
    PRINT("\tLink:\n");
    oc_rep_t *link = ll->value.object;
    while (link != NULL) {
      switch (link->type) {
      case OC_REP_STRING:
        PRINT("\t\tkey: %s value: %s\n", oc_string(link->name),
              oc_string(link->value.string));
        break;
      case OC_REP_OBJECT: {
        PRINT("\t\tkey: %s value: { ", oc_string(link->name));
        oc_rep_t *rep = link->value.object;
        while (rep != NULL) {
          switch (rep->type) {
          case OC_REP_BOOL:
            PRINT(" %s : %d ", oc_string(rep->name), rep->value.boolean);
            break;
          case OC_REP_INT:
            PRINT(" %s : %lld ", oc_string(rep->name), rep->value.integer);
            break;
          default:
            break;
          }
          rep = rep->next;
        }
        PRINT(" }\n\n");
      } break;
      default:
        break;
      }
      link = link->next;
    }
    ll = ll->next;
  }

  if (!do_once)
    return;

  PRINT("\nSending POST %s?if=oic.if.b [{href: /light/1, rep: "
        "{state: true}}, {href: /count/1, rep: {count: 100}}]\n",
        lights);

  if (oc_init_post(lights, lights_server, "if=oic.if.b", &post_lights_oic_if_b,
                   LOW_QOS, NULL)) {
    oc_rep_start_links_array();
    oc_rep_object_array_start_item(links);
    oc_rep_set_text_string(links, href, "/light/1");
    oc_rep_set_object(links, rep);
    oc_rep_set_boolean(rep, state, true);
    oc_rep_close_object(links, rep);
    oc_rep_object_array_end_item(links);
    oc_rep_object_array_start_item(links);
    oc_rep_set_text_string(links, href, "/count/1");
    oc_rep_set_object(links, rep);
    oc_rep_set_int(rep, count, 100);
    oc_rep_close_object(links, rep);
    oc_rep_object_array_end_item(links);
    oc_rep_end_links_array();

    if (oc_do_post())
      PRINT("Sent POST request\n\n");
    else
      PRINT("Could not send POST\n\n");
  } else
    PRINT("Could not init POST\n\n");

  do_once = false;
}

static void
get_lights_oic_if_ll(oc_client_response_t *data)
{
  PRINT("\nGET_lights_oic_if_ll:\n");
  oc_rep_t *ll = data->payload;

  while (ll != NULL) {
    PRINT("\tLink:\n");
    oc_rep_t *link = ll->value.object;
    while (link != NULL) {
      PRINT("\t\tkey: %s value: ", oc_string(link->name));
      switch (link->type) {
      case OC_REP_STRING:
        PRINT("%s\n", oc_string(link->value.string));
        break;
      case OC_REP_STRING_ARRAY: {
        PRINT("[ ");
        int i;
        for (i = 0;
             i < (int)oc_string_array_get_allocated_size(link->value.array);
             i++) {
          PRINT(" %s ", oc_string_array_get_item(link->value.array, i));
        }
        PRINT(" ]\n");
      } break;
      case OC_REP_OBJECT: {
        PRINT("{ ");
        oc_rep_t *rep = link->value.object;
        while (rep != NULL) {
          PRINT(" %s : ", oc_string(rep->name));
          switch (rep->type) {
          case OC_REP_BOOL:
            PRINT("%d ", rep->value.boolean);
            break;
          case OC_REP_INT:
            PRINT("%lld ", rep->value.integer);
            break;
          case OC_REP_STRING:
            PRINT("%s ", oc_string(rep->value.string));
            break;
          default:
            break;
          }
          rep = rep->next;
        }
        PRINT(" }\n\n");
      } break;
      default:
        break;
      }
      link = link->next;
    }
    ll = ll->next;
  }

  PRINT("\nSending GET %s?if=oic.if.b\n\n", lights);

  oc_do_get(lights, lights_server, "if=oic.if.b", &get_lights_oic_if_b, LOW_QOS,
            NULL);
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)iface_mask;
  (void)user_data;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, "oic.wk.col", 10) == 0) {
      oc_endpoint_list_copy(&lights_server, endpoint);

      strncpy(lights, uri, uri_len);
      lights[uri_len] = '\0';

      PRINT("Resource %s hosted at endpoints:\n", lights);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }

      PRINT("\nSending GET %s?if=oic.if.ll\n\n", lights);

      oc_do_get(lights, lights_server, "if=oic.if.ll", &get_lights_oic_if_ll,
                LOW_QOS, NULL);

      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery("oic.wk.col", &discovery, NULL);
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

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .requests_entry = issue_requests };

  oc_clock_time_t next_event;

#ifdef OC_STORAGE
  oc_storage_config("./client_collections_linux_creds");
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
