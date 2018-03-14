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
#include <unistd.h>

static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

typedef enum { UNKNOWN = 0, LOCKED, UNLOCKED } lock_state;

typedef struct oc_smartlock_t
{
  struct oc_smartlock_t *next;
  oc_endpoint_t *endpoint;
  char uri[64];
  lock_state state;
} oc_smartlock_t;

OC_LIST(smartlocks);
OC_MEMB(smartlocks_m, oc_smartlock_t, 100);

static void
free_smart_lock(oc_smartlock_t *lock)
{
  oc_free_server_endpoints(lock->endpoint);
  oc_memb_free(&smartlocks_m, lock);
}

static void
free_all_known_locks(void)
{
  oc_smartlock_t *l = (oc_smartlock_t *)oc_list_pop(smartlocks);
  while (l != NULL) {
    free_smart_lock(l);
    l = (oc_smartlock_t *)oc_list_pop(smartlocks);
  }
}

static int
app_init(void)
{
  int ret = oc_init_platform("Intel Corporation", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.wk.d", "SmartLock", "ocf.1.0.0",
                       "ocf.res.1.3.0", NULL, NULL);
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
  PRINT("\n\n################################################\nSmart Lock "
        "Controller"
        "\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Discover smart locks\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[2] GET lock state\n");
  PRINT("[3] POST lock state\n");
  PRINT("[4] Start OBSERVE lock state\n");
  PRINT("[5] Stop OBSERVE lock state\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[6] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

static oc_event_callback_retval_t
show_discovered_locks(void *data)
{
  (void)data;
  PRINT("\nDiscovered locks with rt oic.r.lock.status:\n");
  oc_smartlock_t **locks = (oc_smartlock_t **)data;
  oc_smartlock_t *l = (oc_smartlock_t *)oc_list_head(smartlocks);
  int i = 0;
  PRINT("\n\n");
  while (l != NULL) {
    if (locks != NULL) {
      locks[i] = l;
    }
    PRINT("[%d]: %s", i, l->uri);
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
  return OC_EVENT_DONE;
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
POST_handler(oc_client_response_t *data)
{
  PRINT("POST_lock_state:\n");
  if (data->code == OC_STATUS_CHANGED) {
    PRINT("POST response OK\n");
  } else {
    PRINT("POST response code %d\n", data->code);
  }

  oc_smartlock_t *lock = (oc_smartlock_t *)data->user_data;
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (oc_string_len(rep->name) == 9 &&
          memcmp(oc_string(rep->name), "lockState", 9) == 0) {
        PRINT("\n\n%s : %s\n\n", oc_string(rep->name),
              oc_string(rep->value.string));
        if (oc_string_len(rep->value.string) == 6 &&
            memcmp(oc_string(rep->value.string), "Locked", 6) == 0) {
          lock->state = LOCKED;
        } else {
          lock->state = UNLOCKED;
        }
      }
    default:
      break;
    }
    rep = rep->next;
  }

  display_menu();
}

static void
GET_handler(oc_client_response_t *data)
{
  PRINT("GET_lock_state:\n");
  oc_smartlock_t *lock = (oc_smartlock_t *)data->user_data;
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (oc_string_len(rep->name) == 9 &&
          memcmp(oc_string(rep->name), "lockState", 9) == 0) {
        PRINT("\n\n%s : %s\n\n", oc_string(rep->name),
              oc_string(rep->value.string));
        if (oc_string_len(rep->value.string) == 6 &&
            memcmp(oc_string(rep->value.string), "Locked", 6) == 0) {
          lock->state = LOCKED;
        } else {
          lock->state = UNLOCKED;
        }
      }
    default:
      break;
    }
    rep = rep->next;
  }

  display_menu();
}

static void
get_lock_state(bool observe)
{
  pthread_mutex_lock(&app_sync_lock);
  if (oc_list_length(smartlocks) > 0) {
    oc_smartlock_t *locks[100];
    show_discovered_locks(locks);
    PRINT("\n\nSelect lock: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(smartlocks)) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      if (observe) {
        oc_do_observe(locks[c]->uri, locks[c]->endpoint, NULL, GET_handler,
                      HIGH_QOS, locks[c]);
      } else {
        oc_do_get(locks[c]->uri, locks[c]->endpoint, NULL, GET_handler,
                  HIGH_QOS, locks[c]);
      }
    }
  } else {
    PRINT("\nERROR: No known locks... Please try discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
stop_observe_lock_state(void)
{
  pthread_mutex_lock(&app_sync_lock);
  if (oc_list_length(smartlocks) > 0) {
    oc_smartlock_t *locks[100];
    show_discovered_locks(locks);
    PRINT("\n\nSelect lock: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(smartlocks)) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      oc_stop_observe(locks[c]->uri, locks[c]->endpoint);
    }
  } else {
    PRINT("\nERROR: No known locks... Please try discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
post_lock_state(void)
{
  pthread_mutex_lock(&app_sync_lock);
  if (oc_list_length(smartlocks) > 0) {
    oc_smartlock_t *locks[100];
    show_discovered_locks(locks);
    PRINT("\n\nSelect lock: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(smartlocks)) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      int s;
      PRINT("Lock states:\n[0]: Locked\n[1]: Unlocked\n\nSelect lock state: ");
      SCANF("%d", &s);
      if (s < 0 || s > 1) {
        PRINT("\nERROR: Invalid selection.. Try again..\n");
      } else {
        if (oc_init_post(locks[c]->uri, locks[c]->endpoint, NULL, &POST_handler,
                         HIGH_QOS, locks[c])) {
          oc_rep_start_root_object();
          if (s == 0) {
            oc_rep_set_text_string(root, lockState, "Locked");
          } else {
            oc_rep_set_text_string(root, lockState, "Unlocked");
          }
          oc_rep_end_root_object();
          if (!oc_do_post()) {
            PRINT("\nERROR: Could not issue POST request\n");
          }
        } else {
          PRINT("\nERROR: Could not initialize POST request\n");
        }
      }
    }
  } else {
    PRINT("\nERROR: No known locks... Please try discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static oc_discovery_flags_t
discovery(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)di;
  (void)interfaces;
  (void)user_data;
  (void)uri;
  (void)types;
  (void)bm;

  oc_smartlock_t *l = (oc_smartlock_t *)oc_memb_alloc(&smartlocks_m);
  if (l) {
    l->endpoint = endpoint;
    int uri_len = (strlen(uri) >= 64) ? 63 : strlen(uri);
    memcpy(l->uri, uri, uri_len);
    l->uri[uri_len] = '\0';
    oc_list_add(smartlocks, l);

    PRINT("\nDiscovering...\n");

    display_menu();

    return OC_CONTINUE_DISCOVERY;
  }
  oc_free_server_endpoints(endpoint);
  return OC_STOP_DISCOVERY;
}

static oc_discovery_flags_t
null_discovery(const char *di, const char *uri, oc_string_array_t types,
               oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
               oc_resource_properties_t bm, void *user_data)
{
  (void)di;
  (void)interfaces;
  (void)user_data;
  (void)uri;
  (void)types;
  (void)endpoint;
  (void)bm;
  oc_free_server_endpoints(endpoint);

  return OC_STOP_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_ip_discovery(NULL, &null_discovery, NULL);
}

static void
discover_smart_locks(void)
{
  pthread_mutex_lock(&app_sync_lock);
  free_all_known_locks();
  oc_do_ip_discovery("oic.r.lock.status", &discovery, NULL);
  oc_set_delayed_callback(NULL, show_discovered_locks, 5);
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

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .requests_entry = issue_requests };

#ifdef OC_SECURITY
  oc_storage_config("./smart_lock_creds");
#endif /* OC_SECURITY */

  oc_set_con_res_announced(false);
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
      discover_smart_locks();
      break;
    case 2:
      get_lock_state(false);
      break;
    case 3:
      post_lock_state();
      break;
    case 4:
      get_lock_state(true);
      break;
    case 5:
      stop_observe_lock_state();
      break;
    case 6:
      handle_signal(0);
      break;
    default:
      break;
    }
  }

  pthread_join(event_thread, NULL);
  return 0;
}
