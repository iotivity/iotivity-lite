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

#define PRINTport(endpoint)                                                   \
  do {                                                                         \
    if ((endpoint).flags & IPV4) {                                             \
      PRINT("%d",             \
             (endpoint).addr.ipv4.port);     \
    } else {                                                                   \
      PRINT(                                                                   \
        "%d",                                                             \
         (endpoint).addr.ipv6.port);        \
    }                                                                          \
} while(0)

#define PRINTIPaddr(endpoint)                                                  \
  do {                                                                         \
    if ((endpoint).flags & IPV4) {                                             \
      PRINT("%d.%d.%d.%d", ((endpoint).addr.ipv4.address)[0],             \
            ((endpoint).addr.ipv4.address)[1],                                 \
            ((endpoint).addr.ipv4.address)[2],                                 \
            ((endpoint).addr.ipv4.address)[3]);     \
    } else {                                                                   \
      PRINT(                                                                   \
        "%02x%02x::%02x%02x:%02x%02x:%02x%02x:%"    \
        "02x%"                                                                 \
        "02x",                                                                 \
        ((endpoint).addr.ipv6.address)[0], ((endpoint).addr.ipv6.address)[1],  \
        ((endpoint).addr.ipv6.address)[8], ((endpoint).addr.ipv6.address)[9],  \
        ((endpoint).addr.ipv6.address)[10],                                    \
        ((endpoint).addr.ipv6.address)[11],                                    \
        ((endpoint).addr.ipv6.address)[12],                                    \
        ((endpoint).addr.ipv6.address)[13],                                    \
        ((endpoint).addr.ipv6.address)[14],                                    \
        ((endpoint).addr.ipv6.address)[15]);                                   \
    }                                                                          \
} while(0)
pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

int quit = 0;

static int
app_init(void)
{
  int ret = oc_init_platform("TAFAgent", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;
static oc_string_t name;
static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}
static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)interfaces;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 8 && strncmp(t, "oic.wk.d", 8) == 0) {
      light_server = endpoint;
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      PRINT("Resource %s hosted at endpoints:\n", a_light);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTIPaddr(*ep);
        PRINT("\n");
        PRINTport(*ep);
        PRINT("\n");
        ep = ep->next;
      }

  signal_event_loop();
  quit = 1;
      return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{

  oc_do_ip_discovery("oic.wk.d", &discovery, NULL);

}


void
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
                                       .requests_entry = issue_requests };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./discover_device_creds");
#endif               /* OC_SECURITY */

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
  oc_free_server_endpoints(light_server);
  oc_free_string(&name);
  oc_main_shutdown();
  return 0;
}
