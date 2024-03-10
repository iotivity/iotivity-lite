/******************************************************************
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
#include "oc_helpers.h"
#include "port/oc_clock.h"
#include "port/oc_storage.h"
#include "util/oc_compiler.h"

#if defined(OC_INTROSPECTION) && defined(OC_IDD_API)
#include "oc_introspection.h"
#endif /* OC_INTROSPECTION && OC_IDD_API */

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define CHAR_ARRAY_LEN(x) (sizeof(x) - 1)

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

static oc_string_t name;
static oc_string_array_t my_supportedactions;

/* global property variables for path: "/binaryswitch" */
bool g_binaryswitch_value = false;

#if defined(OC_INTROSPECTION) && defined(OC_IDD_API)

#define INTROSPECTION_IDD_FILE "server_introspection.cbor"

static bool
set_introspection_data(size_t device)
{
  FILE *fp = fopen("./" INTROSPECTION_IDD_FILE, "rb");
  if (fp == NULL) {
    return false;
  }
  long ret = fseek(fp, 0, SEEK_END);
  if (ret < 0) {
    fclose(fp);
    return false;
  }
  ret = ftell(fp);
  if (ret < 0) {
    fclose(fp);
    return false;
  }
  rewind(fp);

  size_t buffer_size = (size_t)ret;
  uint8_t *buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
  if (buffer == NULL) {
    fclose(fp);
    return false;
  }
  size_t fread_ret = fread(buffer, buffer_size, 1, fp);
  fclose(fp);

  if (fread_ret != 1) {
    free(buffer);
    return false;
  }

  if (oc_set_introspection_data_v1(device, buffer, buffer_size) < 0) {
    free(buffer);
    return false;
  }
  printf("\tIntrospection data set '" INTROSPECTION_IDD_FILE "': %d [bytes]\n",
         (int)buffer_size);
  free(buffer);
  return true;
}
#endif /* OC_INTROSPECTION && OC_IDD_API */

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.2.2.3",
                       "ocf.res.1.3.0, ocf.sh.1.3.0", NULL, NULL);
  if (ret < 0) {
    return ret;
  }

  oc_new_string(&name, "John's Light", 12);
  oc_new_string_array(&my_supportedactions, (size_t)19);
  oc_string_array_add_item(my_supportedactions, "arrowup");
  oc_string_array_add_item(my_supportedactions, "arrowdown");
  oc_string_array_add_item(my_supportedactions, "arrowleft");
  oc_string_array_add_item(my_supportedactions, "arrowright");
  oc_string_array_add_item(my_supportedactions, "enter");
  oc_string_array_add_item(my_supportedactions, "return");
  oc_string_array_add_item(my_supportedactions, "exit");
  oc_string_array_add_item(my_supportedactions, "home");
  oc_string_array_add_item(my_supportedactions, "1");
  oc_string_array_add_item(my_supportedactions, "2");
  oc_string_array_add_item(my_supportedactions, "3");
  oc_string_array_add_item(my_supportedactions, "4");
  oc_string_array_add_item(my_supportedactions, "5");
  oc_string_array_add_item(my_supportedactions, "6");
  oc_string_array_add_item(my_supportedactions, "7");
  oc_string_array_add_item(my_supportedactions, "8");
  oc_string_array_add_item(my_supportedactions, "9");
  oc_string_array_add_item(my_supportedactions, "0");
  oc_string_array_add_item(my_supportedactions, "-");

#ifdef OC_INTROSPECTION
#ifdef OC_IDD_API
  if (!set_introspection_data(/*device*/ 0)) {
    printf("%s", "\tERROR Could not read '" INTROSPECTION_IDD_FILE "'\n"
                 "\tIntrospection data not set.\n");
  }
#else  /* !OC_IDD_API */
  printf("\t introspection via header file\n");
#endif /* OC_IDD_API */
#endif /* OC_INTROSPECTION */
  return ret;
}

static bool
verify_action_in_supported_set(oc_string_t action)
{
  const char *act = oc_string(action);
  size_t act_len = oc_string_len(action);
  for (size_t i = 0;
       i < oc_string_array_get_allocated_size(my_supportedactions); i++) {
    const char *sv = oc_string_array_get_item(my_supportedactions, i);
    printf("Action compare. Supported action %s against received action %s \n",
           sv, act);
    if (strlen(sv) == act_len && memcmp(sv, act, act_len) == 0) {
      return true;
    }
  }

  return false;
}

static void
get_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces,
                 void *user_data)
{
  (void)user_data; /* not used */

  printf("get_binaryswitch: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    printf("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);
    OC_FALLTHROUGH;
  case OC_IF_A:
    /* property "value" */
    oc_rep_set_boolean(root, value, g_binaryswitch_value);
    printf("   value : %d\n", g_binaryswitch_value); /* not handled value */
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

/**
* post method for "/binaryswitch" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
*/
static void
post_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces,
                  void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  printf("post_binaryswitch:\n");
  oc_rep_t *rep = request->request_payload;
  /* loop over the request document to check if all inputs are ok */
  while (rep != NULL) {
    printf("key: (check) %s \n", oc_string(rep->name));
    if (memcmp(oc_string(rep->name), "value", 5) == 0) {
      /* property "value" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        printf("   property 'value' is not of type bool %d \n", rep->type);
      }
    }

    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    /* loop over all the properties in the input document */
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
      printf("key: (assign) %s \n", oc_string(rep->name));
      /* no error: assign the variables */
      if (memcmp(oc_string(rep->name), "value", 5) == 0) {
        /* assign "value" */
        g_binaryswitch_value = rep->value.boolean;
      }
      rep = rep->next;
    }
    /* set the response */
    printf("Set response \n");
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, value, g_binaryswitch_value);
    oc_rep_end_root_object();

    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    /* TODO: add error response, if any */
    oc_send_response(request, OC_STATUS_NOT_MODIFIED);
  }
}

static void
get_remotecontrol(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *user_data)
{
  (void)user_data;

  /* Check if query string includes action selectio, it is does, reject the
   * request. */
  const char *action = NULL;
  int action_len = -1;
  oc_init_query_iterator();
  oc_iterate_query_get_values_v1(request, "action", CHAR_ARRAY_LEN("action"),
                                 &action, &action_len);

  if (action_len > 0) {
    // An action parm was received
    //
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  printf("GET_remotecontrol:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    OC_FALLTHROUGH;
  case OC_IF_A:
    oc_rep_set_key(oc_rep_object(root), "supportedactions");
    oc_rep_begin_array(oc_rep_object(root), supportedactions);
    for (size_t i = 0;
         i < oc_string_array_get_allocated_size(my_supportedactions); i++) {
      oc_rep_add_text_string(supportedactions,
                             oc_string_array_get_item(my_supportedactions, i));
    }
    oc_rep_end_array(oc_rep_object(root), supportedactions);
    oc_rep_end_root_object();
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_remotecontrol(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  printf("POST_remotecontrol:\n");

  /* Check if query string includes action selection. */
  const char *action = NULL;
  int action_len = -1;
  oc_init_query_iterator();
  oc_iterate_query_get_values_v1(request, "action", CHAR_ARRAY_LEN("action"),
                                 &action, &action_len);

  if (action_len > 0) {
    printf("POST action length = %d \n", action_len);
    printf("POST action string actual size %zu \n", strlen(action));
    printf("POST action received raw = %s \n", action);

    // Validate that the action requests is in the set
    //
    oc_string_t act;
    oc_new_string(&act, action, action_len);
    bool valid_action = verify_action_in_supported_set(act);

    // Build response with selected action
    //
    if (valid_action) {
      oc_rep_start_root_object();
      oc_rep_set_key(oc_rep_object(root), "selectedactions");
      oc_rep_begin_array(oc_rep_object(root), selectedactions);
      oc_rep_add_text_string(selectedactions, oc_string(act));
      oc_rep_end_array(oc_rep_object(root), selectedactions);
      oc_rep_end_root_object();
      oc_send_response(request, OC_STATUS_CHANGED);
    } else {
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
    }
    oc_free_string(&act);
  } else {
    printf("POST no action received \n");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
register_resources(void)
{
  printf("Register Resource with local path \"/binaryswitch\"\n");
  oc_resource_t *res = oc_new_resource("Binary Switch", "/binaryswitch", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(res, OC_IF_A);
  oc_resource_set_default_interface(res, OC_IF_A);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_request_handler(res, OC_GET, get_binaryswitch, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_binaryswitch, NULL);
  oc_add_resource(res);

  printf("Register Resource with local path \"/remotecontrol\"\n");
  oc_resource_t *res2 =
    oc_new_resource("Remote Control", "/remotecontrol", 1, 0);
  oc_resource_bind_resource_type(res2, "oic.r.remotecontrol");
  oc_resource_bind_resource_interface(res2, OC_IF_A);
  oc_resource_set_default_interface(res2, OC_IF_A);
  oc_resource_set_discoverable(res2, true);
  oc_resource_set_request_handler(res2, OC_GET, get_remotecontrol, NULL);
  oc_resource_set_request_handler(res2, OC_POST, post_remotecontrol, NULL);
  oc_add_resource(res2);
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
    printf("pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    printf("pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    printf("pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    printf("pthread_cond_init failed (error=%d)!\n", err);
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
#endif /* _WIN32 */

#ifdef __linux__
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
#endif /* __linux__ */
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
  oc_storage_config("./simpleserver_creds/");
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
