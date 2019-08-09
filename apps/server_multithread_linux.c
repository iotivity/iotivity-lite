/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";

static const char *resource_uri = "/a/light";
static const char *resource_rt = "core.light";
static const char *additional_rt = "core.brightlight";
static const char *resource_name = "Samsung's Light";

static const char *device_rt = "oic.d.light";
static const char *device_name = "Light";

static const char *manufacturer = "Samsung";

static bool discoverable = true;
static bool observable = true;

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

pthread_mutex_t app_mutex;
oc_resource_t *res;

int quit = 0;

static bool is_separate_response = false;
static bool state = false;
int power;
oc_string_t name;
static oc_separate_response_t sep_response;

oc_define_interrupt_handler(observe)
{
  oc_notify_observers(res);
}

static int
app_init(void)
{
  oc_activate_interrupt_handler(observe);
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  oc_new_string(&name, resource_name, strlen(resource_name));
  return ret;
}

static oc_event_callback_retval_t
handle_separate_response(void *data)
{
  (void)data;
  if (sep_response.active) {
    oc_set_separate_response_buffer(&sep_response);
    printf("handle_separate_response:\n");
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, state);
    oc_rep_set_int(root, power, power);
    oc_rep_set_text_string(root, name, oc_string(name));
    oc_rep_end_root_object();
    oc_send_separate_response(&sep_response, OC_STATUS_OK);
  }
  return OC_EVENT_DONE;
}

static void
get_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  (void)user_data;

  printf("get_handler:\n");
  if (is_separate_response) {
    oc_indicate_separate_response(request, &sep_response);
    oc_set_delayed_callback(NULL, &handle_separate_response, 1);
    return;
  }

  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, state);
    oc_rep_set_int(root, power, power);
    oc_rep_set_text_string(root, name, oc_string(name));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
             void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  printf("post_handler:\n");
  printf("  Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    printf("  %s :", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      printf("%d\n", state);
      break;
    case OC_REP_INT:
      power = (int)rep->value.integer;
      printf("%d\n", power);
      break;
    case OC_REP_STRING:
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
put_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  post_handler(request, iface_mask, user_data);
}

static void
change_state(void)
{
  state = !state;
  oc_signal_interrupt_handler(observe);
}

static void
change_power(void)
{
  power += 5;
  oc_signal_interrupt_handler(observe);
}

static void
change_separate_response_policy(void)
{
  is_separate_response = !is_separate_response;
}

static void
register_resources(void)
{
  res = oc_new_resource(NULL, resource_uri, 2, 0);
  oc_resource_bind_resource_type(res, resource_rt);
  oc_resource_bind_resource_type(res, additional_rt);
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, discoverable);
  oc_resource_set_observable(res, observable);
  oc_resource_set_request_handler(res, OC_GET, get_handler, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_handler, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_handler, NULL);
  oc_add_resource(res);
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event;

  while (quit != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_mutex);
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

  pthread_exit(0);
}

void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  printf("=====================================\n");
  printf("1. Change my state(%d)\n", state);
  printf("2. Change my power(%d)\n", power);
  printf("3. Change separate response policy(%d)\n", is_separate_response);
  printf("0. Quit\n");
  printf("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

int
main(void)
{
  int init = 0;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

#ifdef OC_STORAGE
  oc_storage_config("./server_multithread_linux_creds");
#endif /* OC_STORAGE */

  if (pthread_mutex_init(&mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    return -1;
  }

  if (pthread_mutex_init(&app_mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    pthread_mutex_destroy(&mutex);
    return -1;
  }

  init = oc_main_init(&handler);
  if (init < 0) {
    printf("oc_main_init failed!(%d)\n", init);
    goto exit;
  }

  size_t device_num = oc_core_get_num_devices();
  size_t i;
  for (i = 0; i < device_num; i++) {
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(i);
    printf("=== device(%zd) endpoint info. ===\n", i);
    while (ep) {
      oc_string_t ep_str;
      if (oc_endpoint_to_string(ep, &ep_str) == 0) {
        printf("-> %s\n", oc_string(ep_str));
        oc_free_string(&ep_str);
      }
      ep = ep->next;
    }
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    printf("Failed to create main thread\n");
    init = -1;
    goto exit;
  }

  int key;
  while (quit != 1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%d", &key)) {
      printf("scanf failed!!!!\n");
      quit = 1;
      handle_signal(0);
      break;
    }

    pthread_mutex_lock(&app_mutex);
    switch (key) {
    case 1:
      change_state();
      break;
    case 2:
      change_power();
      break;
    case 3:
      change_separate_response_policy();
      break;
    case 0:
      quit = 1;
      handle_signal(0);
      break;
    default:
      printf("unsupported command.\n");
      break;
    }
    pthread_mutex_unlock(&app_mutex);
  }

  pthread_join(thread, NULL);
  printf("pthread_join finish!\n");

exit:
  oc_main_shutdown();

  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_mutex);
  return 0;
}
