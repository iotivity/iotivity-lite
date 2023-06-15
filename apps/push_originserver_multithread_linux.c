/****************************************************************************
 *
 * Copyright 2021 ETRI All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * Created on: Aug 2, 2022,
 * 				Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_push.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "util/oc_atomic.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";

static const char *resource_rt = "oic.r.custom.light";
static const char *resource_uri = "/living-room/complex-light/1";
static const char *resource_uri2 = "/living-room/complex-light/2";

static const char *device_rt = "oic.d.push";
static const char *device_rt2 = "oic.d.custom.light";
static const char *device_name = "push-originserver-Complex_Light";
static const char *manufacturer = "ETRI";

static bool discoverable = true;
static bool observable = true;
static bool pushable = true;

static pthread_mutex_t app_mutex;
static pthread_mutex_t mutex;
static pthread_cond_t cv;

static OC_ATOMIC_INT8_T quit = 0;

static oc_resource_t *res;
static oc_resource_t *res2;

static int power;
static int brightness;

static int power2;
static int brightness2;

/*
 * callback function to be called whenever new PUSH arrives
 */
static void
push_arrived(oc_pushd_resource_rep_t *push_payload)
{
  printf("new push arrives (path: %s, rt: ",
         oc_string(push_payload->resource->uri));
  for (size_t i = 0;
       i < oc_string_array_get_allocated_size(push_payload->resource->types);
       i++) {
    printf("%s ", oc_string_array_get_item(push_payload->resource->types, i));
  }
  printf(")\n");

  oc_print_pushd_resource(push_payload->rep);
}

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);

  /* add additional device type */
  oc_device_bind_resource_type(0, device_rt2);

  /* set push callback function which will be called when new PUSH arrives */
  oc_set_on_push_arrived(push_arrived);

  return ret;
}

static void
cb_retrieve_light1(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *user_data)
{
  (void)user_data;

  printf("cb_retrieve_light1() is called\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_RW:
    oc_rep_set_int(root, brightness, brightness);
    oc_rep_set_int(root, power, power);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
cb_retrieve_light2(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *user_data)
{
  (void)user_data;

  printf("cb_retrieve_light2() is called\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_RW:
    oc_rep_set_int(root, brightness, brightness2);
    oc_rep_set_int(root, power, power2);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

/* ======== for light #1 ======== */
static void
change_brightness(void)
{
  brightness = (brightness + 1) % 100;
  /* notify PUSH origin Resource is changed */
  oc_resource_state_changed(resource_uri, strlen(resource_uri), res->device);
}

static void
change_power(void)
{
  power += 5;
  oc_resource_state_changed(resource_uri, strlen(resource_uri), res->device);
}

/* ======== for light #2 ======== */
static void
change_brightness2(void)
{
  brightness2 = (brightness2 + 1) % 100;
  oc_resource_state_changed(resource_uri2, strlen(resource_uri2), res2->device);
}

static void
change_power2(void)
{
  power2 += 5;
  oc_resource_state_changed(resource_uri2, strlen(resource_uri2), res2->device);
}

/* PUSH payload builder */
static void
build_light_payload(void)
{
  oc_rep_open_object(root, rep);
  oc_rep_set_int(rep, power, power);
  oc_rep_set_int(rep, brightness, brightness);
  oc_rep_close_object(root, rep);
}

static void
register_resources(void)
{
  /* light2 is not pushable */
  res2 = oc_new_resource(NULL, resource_uri2, 1, 0);
  oc_resource_bind_resource_type(res2, resource_rt);
  oc_resource_bind_resource_interface(res2, OC_IF_RW);
  oc_resource_set_default_interface(res2, OC_IF_RW);
  oc_resource_set_discoverable(res2, discoverable);
  oc_resource_set_observable(res2, observable);
  oc_resource_set_request_handler(res2, OC_GET, cb_retrieve_light2, NULL);
  oc_add_resource(res2);

  /* light1 is pushable */
  res = oc_new_resource(NULL, resource_uri, 1, 0);
  oc_resource_bind_resource_type(res, resource_rt);
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, discoverable);
  oc_resource_set_observable(res, observable);
  /* make a Resource pushable */
  oc_resource_set_pushable(res, pushable);
  oc_resource_set_request_handler(res, OC_GET, cb_retrieve_light1, NULL);
  /* set PUSH payload builder */
  res->payload_builder = build_light_payload;
  oc_add_resource(res);
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
  OC_ATOMIC_STORE8(quit, 1);
  signal_event_loop();
}

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event_mt = oc_main_poll_v1();
    pthread_mutex_unlock(&app_mutex);
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

  pthread_exit(0);
}

static void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  printf("=============== Light A =============\n");
  printf("1. Change brightness(%d) of light #1\n", brightness);
  printf("2. Change power(%d) of light #1\n", power);
  printf("3. Change brightness(%d) of light #2\n", brightness2);
  printf("4. Change power(%d) of light #2\n", power2);
  printf("0. Quit\n");
  printf("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&app_mutex, NULL);
  if (err != 0) {
    printf("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    printf("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    printf("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    printf("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    printf("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
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
  pthread_mutex_destroy(&app_mutex);
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
    .register_resources = register_resources,
  };

#ifdef OC_STORAGE
  oc_storage_config("./push_originserver_multithread_linux_creds");
#endif /* OC_STORAGE */

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    printf("oc_main_init failed!(%d)\n", ret);
    deinit();
    return ret;
  }

  size_t device_num = oc_core_get_num_devices();
  for (size_t i = 0; i < device_num; i++) {
    const oc_endpoint_t *ep = oc_connectivity_get_endpoints(i);
    printf("=== device(%zd) endpoint info. ===\n", i);
    while (ep) {
      oc_string_t ep_str;
      if (oc_endpoint_to_string(ep, &ep_str) == 0) {
        printf("%s\n", oc_string(ep_str));
        oc_free_string(&ep_str);
      }
      ep = ep->next;
    }
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    printf("Failed to create main thread\n");
    ret = -1;
    goto exit;
  }

  int key;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%d", &key)) {
      printf("scanf failed!!!!\n");
      handle_signal(0);
      break;
    }

    pthread_mutex_lock(&app_mutex);
    switch (key) {
    case 1:
      change_brightness();
      break;
    case 2:
      change_power();
      break;
    case 3:
      change_brightness2();
      break;
    case 4:
      change_power2();
      break;
    case 0:
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
  deinit();
  return ret;
}
