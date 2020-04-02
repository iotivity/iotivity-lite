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
#include "oc_bridge.h"
#include "port/oc_clock.h"
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <pthread.h>
#else
#error "Unsupported OS"
#endif
#include <signal.h>
#include <stdio.h>

#if defined(_WIN32)
static HANDLE event_thread;
static CRITICAL_SECTION app_sync_lock;
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

/* OS specific definition for lock/unlock */
#define app_mutex_lock(m) EnterCriticalSection(&m)
#define app_mutex_unlock(m) LeaveCriticalSection(&m)

#elif defined(__linux__)
static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;

/* OS specific definition for lock/unlock */
#define app_mutex_lock(m) pthread_mutex_lock(&m)
#define app_mutex_unlock(m) pthread_mutex_unlock(&m)

static struct timespec ts;
#endif

int quit = 0;

#define UUID_LEN 37

static bool discover_vitual_devices = true;

typedef struct virtual_light_t
{
  const char device_name[32];
  const char uuid[UUID_LEN];
  const char eco_system[32];
  bool on;
  bool discovered;
  bool added_to_bridge;
} virtual_light_t;

#define VOD_COUNT 5
struct virtual_light_t virtual_lights[VOD_COUNT] = {
  { "Light 1", "1b32e152-3756-4fb6-b3f2-d8db7aafe39f", "ABC", true, false,
    false },
  { "Light 2", "f959f6fd-8d08-4766-849b-74c3eec5e041", "ABC", false, false,
    false },
  { "Light 3", "686ef93d-36e0-47fc-8316-fbd7045e850a", "ABC", true, false,
    false },
  { "Light 4", "02feb15a-bf94-4f33-9794-adfb25c7bc60", "XYZ", false, false,
    false },
  { "Light 5", "e2f0109f-ef7d-496a-9676-d3d87b38e52f", "XYZ", true, false,
    false }
};

static int
app_init(void)
{
  int ret = oc_init_platform("Desktop PC", NULL, NULL);
  ret |= oc_bridge_add_bridge_device("Dummy Bridge", "ocf.1.0.0",
                                     "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
register_resources(void)
{
}

static void
signal_event_loop(void)
{
#if defined(_WIN32)
  WakeConditionVariable(&cv);
#elif defined(__linux__)
  app_mutex_lock(mutex);
  pthread_cond_signal(&cv);
  app_mutex_unlock(mutex);
#endif
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

static void
get_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *user_data)
{
  virtual_light_t *light = (virtual_light_t *)user_data;

  // uint8_t *virtual_device_id;
  // size_t id_size;
  // oc_string_t econame;
  // oc_bridge_get_virtual_device_info(&virtual_device_id, &id_size, &econame,
  // request->resource->device);
  // oc_bridge_get_virtual_device_info(oc_virtual_device_info_t *virtual_device,
  // &econame, request->resource->device);

  // user virtual_device_id to lookup actual virtual device information.
  // use actual virtual device info.

  oc_status_t resp = OC_STATUS_OK;
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_A:

  case OC_IF_RW:
    oc_rep_set_boolean(root, value, light->on);
    break;
  default:
    resp = OC_STATUS_BAD_REQUEST;
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, resp);
}

static void
post_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *user_data)
{
  (void)iface_mask;
  virtual_light_t *light = (virtual_light_t *)user_data;
  oc_status_t resp = OC_STATUS_CHANGED;
  PRINT("POST_BinarySwitch\n");
  oc_rep_t *rep = request->request_payload;
  if (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      oc_rep_get_bool(rep, "value", &light->on);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      break;
    }
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
put_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *user_data)
{
  post_binary_switch(request, iface_mask, user_data);
}

void
register_binaryswitch_resource(const char *name, const char *uri,
                               size_t device_index, void *user_data)
{
  oc_resource_t *r = oc_new_resource(name, uri, 1, device_index);
  oc_resource_bind_resource_type(r, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(r, OC_IF_A);
  oc_resource_set_default_interface(r, OC_IF_A);
  oc_resource_set_discoverable(r, true);
  oc_resource_set_request_handler(r, OC_GET, get_binary_switch, user_data);
  oc_resource_set_request_handler(r, OC_POST, post_binary_switch, user_data);
  oc_resource_set_request_handler(r, OC_PUT, put_binary_switch, user_data);
  oc_add_resource(r);
}

/*
 * TODO place this in a thread loop
 * When a device is discovered it will be added to
 * the bridge as a virtual_device
 */
void
poll_for_discovered_devices()
{
  size_t virtual_device_index;
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered && !virtual_lights[i].added_to_bridge) {
      PRINT("Adding %s to bridge\n", virtual_lights[i].device_name);
      app_mutex_lock(app_sync_lock);

      virtual_device_index = oc_bridge_add_virtual_device(
        (uint8_t *)virtual_lights[i].uuid, strlen(virtual_lights[i].uuid),
        virtual_lights[i].eco_system, "/oic/d", "oic.d.light",
        virtual_lights[i].device_name, "ocf.1.0.0", "ocf.res.1.0.0", NULL,
        NULL);
      if (virtual_device_index != 0) {
        register_binaryswitch_resource(
          virtual_lights[i].device_name, "/bridge/light/switch",
          virtual_device_index, &virtual_lights[i]);
        // IDD could be added here.
      }

      app_mutex_unlock(app_sync_lock);
      virtual_lights[i].added_to_bridge = true;
    }
  }
}

#if defined(_WIN32)
DWORD WINAPI
ocf_event_thread(LPVOID lpParam)
{
  oc_clock_time_t next_event;
  while (quit != 1) {
    app_mutex_lock(app_sync_lock);
    next_event = oc_main_poll();
    app_mutex_unlock(app_sync_lock);

    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }

  oc_main_shutdown();
  return TRUE;
}
#elif defined(__linux__)
static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    app_mutex_lock(app_sync_lock);
    next_event = oc_main_poll();
    app_mutex_unlock(app_sync_lock);

    app_mutex_lock(mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    app_mutex_unlock(mutex);
  }
  oc_main_shutdown();
  return NULL;
}
#endif

static void
display_ascii_lights()
{
  PRINT("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    PRINT(" %s ", (virtual_lights[i].on) ? " _ " : " _ ");
  }
  PRINT("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    PRINT(" %s ", (virtual_lights[i].on) ? "(*)" : "(~)");
  }
  PRINT("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    PRINT(" %s ", (virtual_lights[i].on) ? " # " : " # ");
  }
  PRINT("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      PRINT(" %s ", (virtual_lights[i].on) ? "ON " : "OFF");
    } else {
      PRINT(" N/A ");
    }
  }
  PRINT("\n");
}

static void
display_menu(void)
{
  PRINT("\n\n");
  display_ascii_lights();
  PRINT("################################################\n");
  PRINT("Dummy Bridge\n");
  PRINT("################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Simulate discovery of 'Light 1'\n");
  PRINT("[2] Simulate discovery of 'Light 2'\n");
  PRINT("[3] Simulate discovery of 'Light 3'\n");
  PRINT("[4] Simulate discovery of 'Light 4'\n");
  PRINT("[5] Simulate discovery of 'Light 5'\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[6] Display summary of dummy bridge.\n");
  PRINT("[7] Start/Stop virtual device discovery.\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[99] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

void
discover_light(unsigned int index)
{
  virtual_lights[index].discovered = !virtual_lights[index].discovered;

  // TODO Move the poll code into its own thread.
  if (discover_vitual_devices) {
    poll_for_discovered_devices();
  }
}

void
display_summary(void)
{
  for (size_t i = 0; i < VOD_COUNT; i++) {
    PRINT("%s, %s, %s, %s, %s\n\n", virtual_lights[i].device_name,
          virtual_lights[i].uuid, virtual_lights[i].eco_system,
          (virtual_lights[i].on ? "ON" : "OFF"),
          (virtual_lights[i].discovered ? "discovered" : "not discovered"));
  }
  PRINT((discover_vitual_devices) ? "ACTIVELY DISCOVERING DEVICES\n"
                                  : "NOT DISCOVERING DEVICES\n");
}
#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

int
main(void)
{
  int init;
#if defined(_WIN32)
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  InitializeCriticalSection(&app_sync_lock);
#elif defined(__linux__)
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
#endif

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

#ifdef OC_STORAGE
  oc_storage_config("./dummy_bridge_creds/");
#endif /* OC_STORAGE */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

#if defined(_WIN32)
  event_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ocf_event_thread,
                              NULL, 0, NULL);
  if (NULL == event_thread) {
    return -1;
  }
#elif defined(__linux__)
  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }
#endif

  int c;
  while (quit != 1) {
    display_menu();
    SCANF("%d", &c);
    switch (c) {
    case 0:
      continue;
      break;
    case 1:
      discover_light(0u);
      break;
    case 2:
      discover_light(1u);
      break;
    case 3:
      discover_light(2u);
      break;
    case 4:
      discover_light(3u);
      break;
    case 5:
      discover_light(4u);
      break;
    case 6:
      display_summary();
      break;
    case 7:
      discover_vitual_devices = !discover_vitual_devices;
      break;
    case 99:
      handle_signal(0);
      break;
    default:
      break;
    }
  }

#if defined(_WIN32)
  WaitForSingleObject(event_thread, INFINITE);
#elif defined(__linux__)
  pthread_join(event_thread, NULL);
#endif
  return 0;
}
