/*
 * Copyright (c) 2017 Intel Corporation
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
 */

#include "test.h"
#include "oc_api.h"
#include "oc_clock_util.h"
#include "port/oc_clock.h"
#include "util/oc_compiler.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define NUM_LIGHTS 3

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static bool quit = false;
static bool light[NUM_LIGHTS] = { true, false, true };
static int client_status;
static int server_status;
static pid_t client_pid;
static pid_t server_pid;

/*********** common ***************/

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
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    printf("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    printf("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    printf("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    printf("ERROR: pthread_cond_init failed (error=%d)!\n", err);
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

/*********** client ***************/

static void
check_resource_cb(oc_client_response_t *data)
{
  static int count = 0;
  bool light = *(bool *)data->user_data;

  for (oc_rep_t *rep = data->payload; rep; rep = rep->next) {
    switch (rep->type) {
    case OC_REP_BOOL:
      if (light != rep->value.boolean)
        exit(EXIT_FAILURE);
      break;
    default:
      exit(EXIT_FAILURE);
    }
  }

  count++;
  if (count >= NUM_LIGHTS) {
    quit = true;
    signal_event_loop();
  }
}

static oc_discovery_flags_t
discovery_cb(const char *di, const char *uri, oc_string_array_t types,
             oc_interface_mask_t iface_mask, oc_endpoint_t *server,
             oc_resource_properties_t bm, void *user_data)
{
  (void)bm;
  (void)di;
  (void)iface_mask;
  (void)user_data;

  static int pos = 0;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    int ret;
    const char *rt = oc_string_array_get_item(types, i);

    if (!rt || strcmp(rt, "constrained.r.test") != 0) {
      continue;
    }

    ret =
      oc_do_get(uri, server, NULL, check_resource_cb, HIGH_QOS, &light[pos]);
    pos++;
    if (!ret)
      exit(EXIT_FAILURE);
  }

  return OC_CONTINUE_DISCOVERY;
}

static void
requests_entry(void)
{
  oc_do_ip_discovery("constrained.r.test", &discovery_cb, NULL);
}

static int
app_init_client(void)
{
  int ret;

  ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.test-client", "Client Test", "1.0",
                       "1.0", NULL, NULL);

  return ret;
}

static int
start_client(void)
{
  if (!init()) {
    return -1;
  }

  static const oc_handler_t handler = {
    .init = app_init_client,
    .signal_event_loop = signal_event_loop,
    .requests_entry = requests_entry,
  };

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }

  while (!quit) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    if (quit) {
      break;
    }
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

  oc_main_shutdown();
  deinit();
  return 0;
}

/*********** server ***************/
static int
app_init(void)
{
  int r = oc_init_platform("Intel", NULL, NULL);
  if (r != 0)
    return r;

  return oc_add_device("/oic/d", "constrained.d.server-test", "Server Test",
                       "1.0", "1.0", NULL, NULL);
}

static void
get_light(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  oc_rep_start_root_object();
  bool light = *(bool *)user_data;

  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    OC_FALLTHROUGH;
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, light);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
register_resources(void)
{
  int i;

  for (i = 0; i < NUM_LIGHTS; i++) {
    int r;
    char name[128];
    oc_resource_t *res;

    r = snprintf(name, sizeof(name), "/test/%d", i);
    if (r < 0 || r >= (int)sizeof(name))
      exit(EXIT_FAILURE);

    res = oc_new_resource(NULL, name, 1, 0);
    oc_resource_bind_resource_type(res, "constrained.r.test");
    oc_resource_bind_resource_interface(res, OC_IF_RW);
    oc_resource_set_default_interface(res, OC_IF_RW);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, 1);
    oc_resource_set_request_handler(res, OC_GET, get_light, &light[i]);
    oc_add_resource(res);
  }
}

static int
start_server(void)
{
  if (!init()) {
    return -1;
  }

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
  };

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }

  while (quit != true) {
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

  oc_main_shutdown();
  deinit();
  return 0;
}

/************************ main *********************************/

static void
child_handler(int sig)
{
  (void)sig;
  pid_t pid;
  int status;
  static int child_count = 0;

  while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
    child_count++;
    if (pid == client_pid) {
      client_status = status;
      kill(server_pid, SIGINT);
    } else {
      server_status = status;
      kill(client_pid, SIGINT);
    }
  }

  if (child_count >= 2) {
    pthread_cond_signal(&cv);
  }
}

int
main(int argc, const char *argv[])
{
  (void)argc;
  (void)argv;
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = child_handler;
  sigaction(SIGCHLD, &sa, NULL);

  if (pthread_mutex_init(&mutex, NULL) != 0) {
    return -1;
  }
  if (pthread_cond_init(&cv, NULL) != 0) {
    return -1;
  }

  server_pid = fork();
  if (server_pid < 0)
    exit(1);

  if (server_pid == 0)
    return start_server();

  client_pid = fork();
  if (client_pid < 0) {
    kill(server_pid, SIGTERM);
    exit(1);
  }

  if (client_pid == 0)
    return start_client();

  pthread_mutex_lock(&mutex);
  pthread_cond_wait(&cv, &mutex);
  pthread_mutex_unlock(&mutex);

  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);

  ASSERT((client_status | server_status) == 0);

  return 0;
}
