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

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <inttypes.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;
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
static char lights[MAX_URI_LENGTH];
static oc_endpoint_t *lights_server;
static bool do_once = true;
static void get_lights_oic_if_b(oc_client_response_t *data);

#ifdef OC_COLLECTIONS_IF_CREATE
static oc_discovery_flags_t
dishand(const char *anchor, const char *uri, oc_string_array_t types,
        oc_interface_mask_t interfaces, const oc_endpoint_t *endpoint,
        oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)types;
  (void)interfaces;
  (void)user_data;
  (void)bm;
  (void)endpoint;

  OC_PRINTF("\n\nURI %s\n\n", uri);
  return OC_CONTINUE_DISCOVERY;
}

static void
post_lights_oic_if_create(oc_client_response_t *data)
{
  (void)data;
  OC_PRINTF("\n\nPOST_lights:oic_if_create\n\n");

  oc_rep_t *rep = data->payload;

  while (rep) {
    OC_PRINTF("\n\nKey: %s\t\t", oc_string(rep->name));

    switch (rep->type) {
    case OC_REP_STRING:
      OC_PRINTF("%s\n\n", oc_string(rep->value.string));
      break;
    case OC_REP_STRING_ARRAY:
      for (size_t i = 0;
           i < oc_string_array_get_allocated_size(rep->value.array); i++) {

        OC_PRINTF(" %s ", oc_string_array_get_item(rep->value.array, i));
      }
      OC_PRINTF("\n");
      break;
    case OC_REP_INT:
      OC_PRINTF(" %" PRId64 "\n", rep->value.integer);
      break;
    case OC_REP_OBJECT: {
      const oc_rep_t *policy = rep->value.object;
      while (policy) {
        OC_PRINTF("\t\t%s\t\t", oc_string(policy->name));
        switch (policy->type) {
        case OC_REP_INT:
          OC_PRINTF(" %" PRId64 " ", policy->value.integer);
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
  OC_PRINTF("Stopping OBSERVE\n");
  oc_stop_observe(lights, lights_server);

#ifdef OC_COLLECTIONS_IF_CREATE
  OC_PRINTF("\nSending POST %s?if=oic.if.create \n", lights);

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
      OC_PRINTF("Sent POST request\n\n");
    else
      OC_PRINTF("Could not send POST\n\n");
  } else
    OC_PRINTF("Could not init POST\n\n");
#endif /* OC_COLLECTIONS_IF_CREATE */
  return OC_EVENT_DONE;
}

static void
post_lights_oic_if_b(oc_client_response_t *data)
{
  OC_PRINTF("\nPOST_lights_oic_if_b:\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("POST response OK\n");
  else
    OC_PRINTF("POST response code %d\n", data->code);

  oc_rep_t *ll = data->payload;

  while (ll != NULL) {
    OC_PRINTF("\tLink:\n");
    oc_rep_t *link = ll->value.object;
    while (link != NULL) {
      switch (link->type) {
      case OC_REP_STRING:
        OC_PRINTF("\t\tkey: %s value: %s\n", oc_string(link->name),
                  oc_string(link->value.string));
        break;
      case OC_REP_OBJECT: {
        OC_PRINTF("\t\tkey: %s value: { ", oc_string(link->name));
        oc_rep_t *rep = link->value.object;
        while (rep != NULL) {
          switch (rep->type) {
          case OC_REP_BOOL:
            OC_PRINTF(" %s : %d ", oc_string(rep->name), rep->value.boolean);
            break;
          case OC_REP_INT:
            OC_PRINTF(" %s : %" PRId64 " ", oc_string(rep->name),
                      rep->value.integer);
            break;
          default:
            break;
          }
          rep = rep->next;
        }
        OC_PRINTF(" }\n\n");
      } break;
      default:
        break;
      }
      link = link->next;
    }
    ll = ll->next;
  }

  OC_PRINTF("\nSending OBSERVE %s?if=oic.if.b\n\n", lights);

  oc_do_observe(lights, lights_server, "if=oic.if.b", &get_lights_oic_if_b,
                LOW_QOS, NULL);
  oc_set_delayed_callback(NULL, &stop_observe, 5);
}

static void
get_lights_oic_if_b(oc_client_response_t *data)
{
  OC_PRINTF("\nGET_lights_oic_if_b:\n");
  oc_rep_t *ll = data->payload;

  while (ll != NULL) {
    OC_PRINTF("\tLink:\n");
    oc_rep_t *link = ll->value.object;
    while (link != NULL) {
      switch (link->type) {
      case OC_REP_STRING:
        OC_PRINTF("\t\tkey: %s value: %s\n", oc_string(link->name),
                  oc_string(link->value.string));
        break;
      case OC_REP_OBJECT: {
        OC_PRINTF("\t\tkey: %s value: { ", oc_string(link->name));
        oc_rep_t *rep = link->value.object;
        while (rep != NULL) {
          switch (rep->type) {
          case OC_REP_BOOL:
            OC_PRINTF(" %s : %d ", oc_string(rep->name), rep->value.boolean);
            break;
          case OC_REP_INT:
            OC_PRINTF(" %s : %" PRId64 " ", oc_string(rep->name),
                      rep->value.integer);
            break;
          default:
            break;
          }
          rep = rep->next;
        }
        OC_PRINTF(" }\n\n");
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

  OC_PRINTF("\nSending POST %s?if=oic.if.b [{href: /light/1, rep: "
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
      OC_PRINTF("Sent POST request\n\n");
    else
      OC_PRINTF("Could not send POST\n\n");
  } else
    OC_PRINTF("Could not init POST\n\n");

  do_once = false;
}

static void
get_lights_oic_if_ll(oc_client_response_t *data)
{
  OC_PRINTF("\nGET_lights_oic_if_ll:\n");
  oc_rep_t *ll = data->payload;

  while (ll != NULL) {
    OC_PRINTF("\tLink:\n");
    oc_rep_t *link = ll->value.object;
    while (link != NULL) {
      OC_PRINTF("\t\tkey: %s value: ", oc_string(link->name));
      switch (link->type) {
      case OC_REP_STRING:
        OC_PRINTF("%s\n", oc_string(link->value.string));
        break;
      case OC_REP_STRING_ARRAY: {
        OC_PRINTF("[ ");
        int i;
        for (i = 0;
             i < (int)oc_string_array_get_allocated_size(link->value.array);
             i++) {
          OC_PRINTF(" %s ", oc_string_array_get_item(link->value.array, i));
        }
        OC_PRINTF(" ]\n");
      } break;
      case OC_REP_OBJECT: {
        OC_PRINTF("{ ");
        oc_rep_t *rep = link->value.object;
        while (rep != NULL) {
          OC_PRINTF(" %s : ", oc_string(rep->name));
          switch (rep->type) {
          case OC_REP_BOOL:
            OC_PRINTF("%d ", rep->value.boolean);
            break;
          case OC_REP_INT:
            OC_PRINTF("%" PRId64 " ", rep->value.integer);
            break;
          case OC_REP_STRING:
            OC_PRINTF("%s ", oc_string(rep->value.string));
            break;
          default:
            break;
          }
          rep = rep->next;
        }
        OC_PRINTF(" }\n\n");
      } break;
      default:
        break;
      }
      link = link->next;
    }
    ll = ll->next;
  }

  OC_PRINTF("\nSending GET %s?if=oic.if.b\n\n", lights);

  oc_do_get(lights, lights_server, "if=oic.if.b", &get_lights_oic_if_b, LOW_QOS,
            NULL);
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)iface_mask;
  (void)user_data;
  (void)bm;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, "oic.wk.col", 10) == 0) {
      oc_endpoint_list_copy(&lights_server, endpoint);

      strncpy(lights, uri, uri_len);
      lights[uri_len] = '\0';

      OC_PRINTF("Resource %s hosted at endpoints:\n", lights);
      const oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        ep = ep->next;
      }

      OC_PRINTF("\nSending GET %s?if=oic.if.ll\n\n", lights);

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
  pthread_cond_signal(&cv);
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = true;
  signal_event_loop();
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  pthread_condattr_destroy(&attr);
  return true;
}

static void
deinit(void)
{
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
}

static void
run_loop(void)
{
  while (!quit) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    pthread_mutex_lock(&mutex);
    if (next_event_mt == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      struct timespec next_event = { 1, 0 };
      oc_clock_time_t next_event_cv;
      if (oc_clock_monotonic_time_to_posix(next_event_mt, CLOCK_MONOTONIC,
                                           &next_event_cv)) {
        next_event = oc_clock_time_to_timespec(next_event_cv);
      }
      pthread_cond_timedwait(&cv, &mutex, &next_event);
    }
    pthread_mutex_unlock(&mutex);
  }
}

int
main(void)
{
  if (!init()) {
    return -1;
  }

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .requests_entry = issue_requests,
  };

#ifdef OC_STORAGE
  oc_storage_config("./client_collections_linux_creds");
#endif /* OC_STORAGE */

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }
  run_loop();
  oc_main_shutdown();
  deinit();
  return 0;
}
