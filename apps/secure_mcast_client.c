/*
// Copyright (c) 2020 Intel Corporation
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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

char mcast_uri[64];
typedef struct light_switch_t
{
  struct light_switch_t *next;
  oc_endpoint_t *endpoint;
} light_switch_t;

OC_LIST(light_switches);
OC_MEMB(light_switches_m, light_switch_t, 100);

static void
free_light_switch(light_switch_t *res)
{
  oc_free_server_endpoints(res->endpoint);
  oc_memb_free(&light_switches_m, res);
}

static void
free_all_light_switches(void)
{
  light_switch_t *l = (light_switch_t *)oc_list_pop(light_switches);
  while (l != NULL) {
    free_light_switch(l);
    l = (light_switch_t *)oc_list_pop(light_switches);
  }
}

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.wk.d", "Secure multicast client",
                       "ocf.2.2.1", "ocf.res.1.3.0,ocf.sh.1.3.0", NULL, NULL);
  return ret;
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) != 1) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
    }                                                                          \
  } while (0)

static void
display_menu(void)
{
  PRINT("\n\n################################################\nSecure "
        "multicast Client for light switches"
        "\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Discover light switches\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[2] RETRIEVE switch\n");
  PRINT("[3] Unicast UPDATE switch\n");
  PRINT("[4] Start OBSERVE switch\n");
  PRINT("[5] Stop OBSERVE switch\n");
  PRINT("[6] Multicast UPDATE switches\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[99] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

static void
show_discovered_light_switches(light_switch_t **res)
{
  PRINT("\nDiscovered light switches:\n");
  light_switch_t *l = (light_switch_t *)oc_list_head(light_switches);
  int i = 0;
  PRINT("\n\n");
  while (l != NULL) {
    if (res != NULL) {
      res[i] = l;
    }
    PRINT("[%d]: %s", i, mcast_uri);
    oc_endpoint_t *ep = l->endpoint;
    while (ep != NULL) {
      PRINT("\n\t\t");
      PRINTipaddr(*ep);
      ep = ep->next;
    }
    PRINT("\n\n");
    i++;
    l = l->next;
  }
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

static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    pthread_mutex_lock(&app_sync_lock);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_sync_lock);

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
  return NULL;
}

static void
update_handler(oc_client_response_t *data)
{
  PRINT("UPDATE light switch:\n");
  if (data->code == OC_STATUS_CHANGED) {
    PRINT("UPDATE response CHANGED\n");
  } else {
    PRINT("UPDATE response code %d\n", data->code);
  }

  char buf[4096];
  oc_rep_to_json(data->payload, buf, 4096, true);
  oc_client_cb_t *cb = (oc_client_cb_t *)data->client_cb;
  PRINT("uri: %s\n", oc_string(cb->uri));
  PRINT("query: %s\n", oc_string(cb->query));
  PRINT("payload: %s\n", buf);
  display_menu();
}

static void
retrieve_handler(oc_client_response_t *data)
{
  PRINT("RETRIEVE light switch:\n");
  char buf[4096];
  oc_rep_to_json(data->payload, buf, 4096, true);
  oc_client_cb_t *cb = (oc_client_cb_t *)data->client_cb;
  if (data->endpoint) {
    PRINT("server endpoint: ");
    PRINTipaddr(*(data->endpoint));
  }
  PRINT("\nuri: %s\n", oc_string(cb->uri));
  PRINT("query: %s\n", oc_string(cb->query));
  PRINT("payload: %s\n", buf);
  display_menu();
}

static void
retrieve_light_switch(bool observe)
{
  pthread_mutex_lock(&app_sync_lock);
  if (oc_list_length(light_switches) > 0) {
    light_switch_t *res[100];
    show_discovered_light_switches(res);
    PRINT("\n\nSelect light switch: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(light_switches)) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      oc_endpoint_t *ep = res[c]->endpoint;
      if (observe) {
        if (!oc_do_observe(mcast_uri, ep, NULL, retrieve_handler, HIGH_QOS,
                           NULL)) {
          PRINT("\nERROR: Could not issue Observe request\n");
        }
      } else {
        if (!oc_do_get(mcast_uri, ep, NULL, retrieve_handler, HIGH_QOS, NULL)) {
          PRINT("\nERROR Could not issue RETRIEVE request\n");
        }
      }
    }
  } else {
    PRINT("\nERROR: No known light switches... Please retry discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
stop_observe_light_switch(void)
{
  pthread_mutex_lock(&app_sync_lock);
  if (oc_list_length(light_switches) > 0) {
    light_switch_t *res[100];
    show_discovered_light_switches(res);
    PRINT("\n\nSelect light switch: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(light_switches)) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      oc_endpoint_t *ep = res[c]->endpoint;
      oc_stop_observe(mcast_uri, ep);
    }
  } else {
    PRINT("\nERROR: No known light switches... Please retry discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
update_light_switch(bool multicast)
{
#ifndef OC_OSCORE
  multicast = false;
#endif /* OC_OSCORE */
  pthread_mutex_lock(&app_sync_lock);
  if (oc_list_length(light_switches) > 0) {
    light_switch_t *res[100];
    int c = 0;
    oc_endpoint_t *ep = NULL;
    if (!multicast) {
      show_discovered_light_switches(res);
      PRINT("\n\nSelect light switch: ");
      SCANF("%d", &c);
      if (c < 0 || c > oc_list_length(light_switches)) {
        PRINT("\nERROR: Invalid selection.. Try again..\n");
        pthread_mutex_unlock(&app_sync_lock);
        return;
      }
      ep = res[c]->endpoint;
    }
    int s;
    PRINT("Select siwtch value:\n[0]: true\n[1]: false\n\nSelect: ");
    SCANF("%d", &s);
    if (s < 0 || s > 1) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      if ((!multicast &&
           oc_init_post(mcast_uri, ep, NULL, &update_handler, HIGH_QOS, NULL))
#ifdef OC_OSCORE
          || (multicast && oc_init_multicast_update(mcast_uri, NULL))
#endif /* OC_OSCORE */
      ) {
        oc_rep_start_root_object();
        if (s == 0) {
          oc_rep_set_boolean(root, value, true);
        } else {
          oc_rep_set_boolean(root, value, false);
        }
        oc_rep_end_root_object();
        if ((!multicast && !oc_do_post())
#ifdef OC_OSCORE
            || (multicast && !oc_do_multicast_update())
#endif /* OC_OSCORE */
        ) {
          PRINT("\nERROR: Could not issue UPDATE request\n");
        }
      } else {
        PRINT("\nERROR: Could not initialize UPDATE request\n");
      }
    }
  } else {
    PRINT("\nERROR: No known light switches... Please retry discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static oc_discovery_flags_t
discovery(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)di;
  (void)iface_mask;
  (void)user_data;
  (void)uri;
  (void)types;
  (void)bm;

  oc_endpoint_t *ep = endpoint;
  oc_string_t ep_str;
  bool supports_mcast = false;
  while (ep) {
    memset(&ep_str, 0, sizeof(oc_string_t));
    if (oc_endpoint_to_string(ep, &ep_str) >= 0) {
      if ((oc_string_len(ep_str) == 23 &&
           memcmp(oc_string(ep_str), "coap://224.0.1.187:5683", 23) == 0) ||
          (oc_string_len(ep_str) == 23 &&
           memcmp(oc_string(ep_str), "coap://[ff02::158]:5683", 23) == 0)) {
        supports_mcast = true;
      }
      oc_free_string(&ep_str);
      if (supports_mcast) {
        break;
      }
    }
    ep = ep->next;
  }

  if (supports_mcast) {
    light_switch_t *l = (light_switch_t *)oc_memb_alloc(&light_switches_m);
    if (l) {
      PRINT("\n##Discovered light switch##\n");
      oc_endpoint_list_copy(&l->endpoint, endpoint);
      if (oc_list_length(light_switches) == 0) {
        int uri_len = (strlen(uri) >= 64) ? 63 : strlen(uri);
        memcpy(mcast_uri, uri, uri_len);
        mcast_uri[uri_len] = '\0';
      }
      oc_list_add(light_switches, l);
    }
  }

  return OC_CONTINUE_DISCOVERY;
}

static void
discover_light_switches(void)
{
  pthread_mutex_lock(&app_sync_lock);
  free_all_light_switches();
  PRINT("\nDiscovering light switches...");
  if (!oc_do_ip_discovery("oic.r.switch.binary", &discovery, NULL)) {
    PRINT("\nERROR: Could not issue discovery request\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

int
main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int init;

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .requests_entry = NULL };

#ifdef OC_STORAGE
  oc_storage_config("./secure_mcast_client_creds");
#endif /* OC_STORAGE */

  oc_set_max_app_data_size(32768);
  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }

  int c;
  while (quit != 1) {
    display_menu();
    SCANF("%d", &c);
    switch (c) {
    case 0:
      continue;
      break;
    case 1:
      discover_light_switches();
      break;
    case 2:
      retrieve_light_switch(false);
      break;
    case 3:
      update_light_switch(false);
      break;
    case 4:
      retrieve_light_switch(true);
      break;
    case 5:
      stop_observe_light_switch();
      break;
    case 6:
      update_light_switch(true);
      break;
    case 99:
      handle_signal(0);
      break;
    default:
      break;
    }
  }

  pthread_join(event_thread, NULL);
  free_all_light_switches();
  return 0;
}
