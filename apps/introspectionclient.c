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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __linux__
#include <pthread.h>
static pthread_mutex_t mutex;
static pthread_cond_t cv;
#endif /* __linux__ */

#ifdef _WIN32
#include <windows.h>
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;
#endif /* _WIN32 */

static bool quit = false;

static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  OC_PRINTF("\tPlatform initialized.\n");
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  OC_PRINTF("\tDevice initialized.\n");
  return ret;
}

#define MAX_URI_LENGTH (128)

static char wk_introspection_uri[MAX_URI_LENGTH];
static char introspection_data_uri[MAX_URI_LENGTH];
static oc_endpoint_t wk_introspection_server;
static oc_endpoint_t introspection_data_server;

static void
print_rep(oc_rep_t *rep, bool pretty_print)
{
  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, pretty_print);
  OC_PRINTF("%s\n", json);
  free(json);
}

static void
get_introspection_data(oc_client_response_t *data)
{
  OC_PRINTF("\nInside the get_introspection_data handler:\n");
  if (data->code == OC_STATUS_OK) {
    oc_rep_t *rep = data->payload;
    print_rep(rep, true);
  } else {
    switch (data->code) {
    case OC_STATUS_UNAUTHORIZED:
      OC_PRINTF("\tERROR Unauthorized access check permissions.\n");
      break;
    case OC_STATUS_INTERNAL_SERVER_ERROR:
      OC_PRINTF("\tERROR Internal Server Error\n"
                "\t\tcheck the max app data size of the server.\n");
      break;
    default:
      OC_PRINTF("\tERROR status: %d\n", data->code);
    }
  }
}

static void
get_wk_introspection(oc_client_response_t *data)
{
  OC_PRINTF("\nInside the get_wk_introspection handler:\n");
  oc_rep_t *rep = data->payload;

  while (rep != NULL) {
    print_rep(rep, true);
    switch (rep->type) {
    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *rep_array = rep->value.object_array;
      while (rep_array != NULL) {
        oc_rep_t *rep_item = rep_array->value.object;
        while (rep_item != NULL) {
          char *url_str = oc_string(rep_item->name);
          size_t url_str_len = oc_string_len(rep_item->name);
          if (strncmp("url", url_str, url_str_len) == 0) {
            oc_string_t path;

            // convert the url to an endpoint.
            oc_string_to_endpoint(&rep_item->value.string,
                                  &introspection_data_server, &path);
            strncpy(introspection_data_uri, oc_string(path), MAX_URI_LENGTH);
            introspection_data_uri[MAX_URI_LENGTH - 1] = '\0';

            OC_PRINTF("Calling GET on %s\n", introspection_data_uri);
            oc_do_get(introspection_data_uri, &introspection_data_server, NULL,
                      &get_introspection_data, LOW_QOS, NULL);
          }
          rep_item = rep_item->next;
        }
        rep_array = rep_array->next;
      }
      break;
    }
    default:
      break;
    }
    rep = rep->next;
  }
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)iface_mask;
  (void)bm;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); ++i) {
    const char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 20 && strncmp(t, "oic.wk.introspection", 20) == 0) {
      OC_PRINTF("Found oic.wk.introspection resource.\n");
      oc_endpoint_copy(&wk_introspection_server, endpoint);
      strncpy(wk_introspection_uri, uri, uri_len);
      wk_introspection_uri[uri_len] = '\0';

      OC_PRINTF("Resource %s hosted at endpoints:\n", wk_introspection_uri);
      const oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        OC_PRINTF("\t");
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        ep = ep->next;
      }

      OC_PRINTF("Calling GET on oic.wk.introspection %s\n",
                wk_introspection_uri);
      oc_do_get(wk_introspection_uri, &wk_introspection_server, NULL,
                &get_wk_introspection, LOW_QOS, NULL);
      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  OC_PRINTF(
    "Making ip discovery request for OCF 'oic.wk.introspection' resource.\n");
  oc_do_ip_discovery("oic.wk.introspection", &discovery, NULL);
}

static void
signal_event_loop(void)
{
#ifdef _WIN32
  WakeConditionVariable(&cv);
#else
  pthread_cond_signal(&cv);
#endif /* _WIN32 */
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
#ifdef _WIN32
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  signal(SIGINT, handle_signal);
#else
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  pthread_condattr_destroy(&attr);
#endif /* _WIN32 */
  return true;
}

static void
deinit(void)
{
#ifndef _WIN32
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
#endif /* !_WIN32 */
}

static void
run_loop(void)
{
#ifdef _WIN32
  while (!quit) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    if (next_event_mt == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now_mt = oc_clock_time_monotonic();
      if (now_mt < next_event_mt) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }
#else  /* !_WIN32 */
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
#endif /* _WIN32 */
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

  // set at 18K may need to be increased if server contains a large IDD.
  oc_set_max_app_data_size(18432);
#ifdef OC_STORAGE
  oc_storage_config("./introspectionclient_creds");
#endif /* OC_STORAGE */

  OC_PRINTF("Initilizing the introspection client...\n");
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
