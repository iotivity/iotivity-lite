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
#include "oc_core_res.h"
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
#include <sys/types.h>
#include <sys/stat.h>

#if defined(OC_IDD_API)
#include "oc_introspection.h"
#endif

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

/*
 * There are two ways that GET/POST/PUT calls can get the information about a
 * virtual device. The information can be passed to the GET/PUT/POST callback
 * via the user_data context pointer, or the device index can be used to obtain
 * the virtual device information and that information can then be used to look
 * up the virtual device.
 *
 * Both methods are shown in this sample if USE_VIRTUAL_DEVICE_LOOKUP is `1`
 * then the device index will be used to obtain the virtual device info. If it
 * is `0` then the information will be sent via the user_data context pointer.
 */
#define USE_VIRTUAL_DEVICE_LOOKUP 1

#define UUID_LEN 37

static bool discover_vitual_devices = true;
static bool display_ascii_ui = false;

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

#if defined(_WIN32)
HANDLE hConsole;
CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
WORD saved_attributes;

#define C_RESET                                                                \
  do {                                                                         \
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);                                \
    SetConsoleTextAttribute(hConsole, saved_attributes);                       \
  } while (false)
#define C_YELLOW                                                               \
  do {                                                                         \
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);                                \
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);                        \
    saved_attributes = consoleInfo.wAttributes;                                \
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_RED |      \
                                        FOREGROUND_INTENSITY);                 \
  } while (false)

#elif defined(__linux__)
#define C_RESET PRINT("\x1B[0m")
#define C_YELLOW PRINT("\x1B[1;33m")
#endif

static void
print_ascii_lights_ui()
{
  PRINT("\n");

  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      if (virtual_lights[i].on) {
        C_YELLOW;
      }
      PRINT(" %s ", (virtual_lights[i].on) ? " _ " : " _ ");
      if (virtual_lights[i].on) {
        C_RESET;
      }
    } else {
      PRINT("     ");
    }
  }
  PRINT("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      if (virtual_lights[i].on) {
        C_YELLOW;
      }
      PRINT(" %s ", (virtual_lights[i].on) ? "(*)" : "(~)");
      if (virtual_lights[i].on) {
        C_RESET;
      }
    } else {
      PRINT("     ");
    }
  }
  PRINT("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      if (virtual_lights[i].on) {
        C_YELLOW;
      }
      PRINT(" %s ", (virtual_lights[i].on) ? " # " : " # ");
      if (virtual_lights[i].on) {
        C_RESET;
      }
    } else {
      PRINT("     ");
    }
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

void
set_idd_from_file(const char *file_name, size_t device)
{
#if defined(OC_IDD_API)
  FILE *fp;
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error1[] = "\tERROR Could not read ";
  const char introspection_error2[] =
    "\tIntrospection data not set for device.\n";
  fp = fopen(file_name, "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(device, buffer, buffer_size);
      PRINT("\tIntrospection data set for device.\n");
    } else {
      PRINT("%s %s\n %s", introspection_error1, file_name,
            introspection_error2);
    }
    free(buffer);
  } else {
    PRINT("%s %s\n %s", introspection_error1, file_name, introspection_error2);
  }
#endif
}

static int
app_init(void)
{
  int ret = oc_init_platform("Desktop PC", NULL, NULL);
  ret |= oc_bridge_add_bridge_device("Dummy Bridge", "ocf.2.0.0",
                                     "ocf.res.1.0.0, ocf.sh.1.0.0", NULL, NULL);
  return ret;
}

static void
register_resources(void)
{
  set_idd_from_file("dummy_bridge_bridge_device_IDD.cbor", 0);
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

virtual_light_t *
lookup_virtual_light(size_t device_index)
{
  oc_virtual_device_t *virtual_device_info =
    oc_bridge_get_virtual_device_info(device_index);
  for (size_t i = 0; i < VOD_COUNT; ++i) {
    if (strncmp(virtual_lights[i].eco_system,
                oc_string(virtual_device_info->econame), 32) == 0) {
      if (memcmp(virtual_lights[i].uuid, virtual_device_info->v_id,
                 virtual_device_info->v_id_size) == 0) {
        return &virtual_lights[i];
      }
    }
  }
  return NULL;
}

static void
get_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *user_data)
{
  (void)user_data;
  virtual_light_t *light = NULL;
#if USE_VIRTUAL_DEVICE_LOOKUP
  light = lookup_virtual_light(request->resource->device);
#else
  light = (virtual_light_t *)user_data;
#endif

  oc_status_t resp = OC_STATUS_OK;
  oc_rep_begin_root_object();
  if (light) {
    switch (iface_mask) {
    case OC_IF_BASELINE:
      oc_process_baseline_interface(request->resource);
      /* fall through */
    case OC_IF_A:
    case OC_IF_RW:
      oc_rep_set_boolean(root, value, light->on);
      break;
    default:
      resp = OC_STATUS_BAD_REQUEST;
      break;
    }
  } else {
    resp = OC_STATUS_BAD_REQUEST;
  }
  oc_rep_end_root_object();
  oc_send_response(request, resp);
}

static void
post_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  virtual_light_t *light = NULL;
#if USE_VIRTUAL_DEVICE_LOOKUP
  light = lookup_virtual_light(request->resource->device);
#else
  light = (virtual_light_t *)user_data;
#endif
  PRINT("POST_BinarySwitch\n");
  if (light) {
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
    if (display_ascii_ui) {
      print_ascii_lights_ui();
    }
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
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
        (uint8_t *)virtual_lights[i].uuid, OC_UUID_LEN,
        virtual_lights[i].eco_system, "/oic/d", "oic.d.light",
        virtual_lights[i].device_name, "ocf.2.0.0",
        "ocf.res.1.0.0, ocf.sh.1.0.0", NULL, NULL);
      if (virtual_device_index != 0) {
#if USE_VIRTUAL_DEVICE_LOOKUP
        register_binaryswitch_resource(virtual_lights[i].device_name,
                                       "/bridge/light/switch",
                                       virtual_device_index, NULL);
#else
        register_binaryswitch_resource(
          virtual_lights[i].device_name, "/bridge/light/switch",
          virtual_device_index, &virtual_lights[i]);
#endif
        // the immutable_device_identifier ("piid")
        oc_uuid_t piid;
        oc_str_to_uuid(virtual_lights[i].uuid, &piid);
        oc_set_immutable_device_identifier(virtual_device_index, &piid);
        // Set Introspection Device Data
        set_idd_from_file("dummy_bridge_virtual_light_IDD.cbor",
                          virtual_device_index);
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
display_menu(void)
{
  PRINT("\n");
  if (display_ascii_ui) {
    print_ascii_lights_ui();
  }
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
  PRINT("   Select simulate discovery of any device again\n");
  PRINT("   to simulate that device being disconnected.\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[6] Display summary of dummy bridge.\n");
  PRINT("[7] Start/Stop virtual device discovery.\n");
  PRINT("[8] Enable/Disable ASCII light bulb UI.\n");
  PRINT("    A representation of the bridged lights\n");
  PRINT("    using ASCII art.\n");
#ifdef OC_SECURITY
  PRINT("[9] Reset Device\n");
  PRINT("[10] Delete Device\n");
#endif /* OC_SECURITY */
  PRINT("-----------------------------------------------\n");
  PRINT("[99] Exit\n");
  PRINT("################################################\n");
  PRINT("Select option: \n");
}

void
disconnect_light(unsigned int index)
{
  virtual_lights[index].discovered = false;
  virtual_lights[index].added_to_bridge = false;
  size_t device = oc_bridge_get_virtual_device_index(
    (uint8_t *)virtual_lights[index].uuid, OC_UUID_LEN,
    virtual_lights[index].eco_system);
  if (device != 0) {
    if (oc_bridge_remove_virtual_device(device) == 0) {
      PRINT("%s removed from the bridge\n", virtual_lights[index].device_name);
    } else {
      PRINT("FAILED to remove %s from the bridge\n",
            virtual_lights[index].device_name);
    }
  } else {
    PRINT("FAILED to find virtual light to remove.");
  }
}

void
discover_light(unsigned int index)
{
  virtual_lights[index].discovered = !virtual_lights[index].discovered;
  // virtual_lights[index].discovered = true;
  // TODO Move the poll code into its own thread.

  if (virtual_lights[index].discovered && discover_vitual_devices) {
    poll_for_discovered_devices();
  } else {
    if (!virtual_lights[index].discovered) {
      disconnect_light(index);
    }
  }
}

void
display_summary(void)
{
  for (size_t i = 0; i < VOD_COUNT; i++) {
    char di_str[OC_UUID_LEN] = "\0";
    if (virtual_lights[i].added_to_bridge) {
      size_t device = oc_bridge_get_virtual_device_index(
        (uint8_t *)virtual_lights[i].uuid, OC_UUID_LEN,
        virtual_lights[i].eco_system);
      if (device != 0) {
        oc_uuid_t *id = oc_core_get_device_id(device);
        oc_uuid_to_str(id, di_str, OC_UUID_LEN);
      } else {
        strcpy(di_str, "ERROR FETCHING");
      }
    }

    PRINT("%s:\n", virtual_lights[i].device_name);
    PRINT("\tVirtual Device ID :%s\n", virtual_lights[i].uuid);
    PRINT("\teconame: %s\n", virtual_lights[i].eco_system);
    PRINT("\tlight switch is: %s\n", (virtual_lights[i].on ? "ON" : "OFF"));
    PRINT("\tAdded to bridge: %s\n",
          (virtual_lights[i].discovered ? "discovered" : "not discovered"));
    PRINT("\tOCF Device ID: %s\n",
          (virtual_lights[i].added_to_bridge ? di_str : "N/A"));
  }
  PRINT((discover_vitual_devices) ? "ACTIVELY DISCOVERING DEVICES\n"
                                  : "NOT DISCOVERING DEVICES\n");
}
#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
      while ((c = getchar()) != EOF && c != '\n')                              \
        ;                                                                      \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

#ifdef OC_SECURITY
void
reset_light(unsigned int index)
{
  (void)index;
  size_t device_index = oc_bridge_get_virtual_device_index(
    (uint8_t *)virtual_lights[index].uuid, OC_UUID_LEN,
    virtual_lights[index].eco_system);
  if (device_index != 0) {
    oc_reset_device(device_index);
    virtual_lights[index].discovered = false;
    virtual_lights[index].added_to_bridge = false;
  }
}

void
reset_device()
{
  PRINT("################################################\n");
  PRINT("[0] Reset Bridge\n");
  PRINT("    Reseting the Bridge will reset all Virtual\n");
  PRINT("    Devices exposed by the Bridge.\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Reset 'Light 1'\n");
  PRINT("[2] Reset 'Light 2'\n");
  PRINT("[3] Reset 'Light 3'\n");
  PRINT("[4] Reset 'Light 4'\n");
  PRINT("[5] Reset 'Light 5'\n");
  PRINT("################################################\n");
  PRINT("Select option: \n");
  int c = 1000;
  SCANF("%d", &c);
  switch (c) {
  case 0:
    oc_reset_device(0u);
    break;
  case 1:
    reset_light(0u);
    break;
  case 2:
    reset_light(1u);
    break;
  case 3:
    reset_light(2u);
    break;
  case 4:
    reset_light(3u);
    break;
  case 5:
    reset_light(4u);
    break;
  default:
    break;
  }
}
#endif /* OC_SECURITY */

void
delete_light(unsigned int index)
{
  size_t device_index = oc_bridge_get_virtual_device_index(
    (uint8_t *)virtual_lights[index].uuid, OC_UUID_LEN,
    virtual_lights[index].eco_system);
  if (device_index != 0) {
    oc_bridge_delete_virtual_device(device_index);
    virtual_lights[index].discovered = false;
    virtual_lights[index].added_to_bridge = false;
  }
}

void
delete_device()
{
  PRINT("################################################\n");
  PRINT("[1] Delete 'Light 1'\n");
  PRINT("[2] Delete 'Light 2'\n");
  PRINT("[3] Delete 'Light 3'\n");
  PRINT("[4] Delete 'Light 4'\n");
  PRINT("[5] Delete 'Light 5'\n");
  PRINT("################################################\n");
  PRINT("Select option: \n");
  int c = 1000;
  SCANF("%d", &c);
  switch (c) {
  case 1:
    delete_light(0u);
    break;
  case 2:
    delete_light(1u);
    break;
  case 3:
    delete_light(2u);
    break;
  case 4:
    delete_light(3u);
    break;
  case 5:
    delete_light(4u);
    break;
  default:
    break;
  }
}

bool
directoryFound(const char *path)
{
  struct stat info;
  if (stat(path, &info) != 0) {
    return false;
  }
  if (info.st_mode & S_IFDIR) {
    return true;
  }
  return false;
}

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

  oc_set_con_res_announced(false);
  // max app data size set to 13k large enough to hold full IDD
  oc_set_max_app_data_size(13312);
#ifdef OC_STORAGE
  if (!directoryFound("dummy_bridge_creds")) {
    printf("Creating dummy_bridge_creds directory for persistant storage.");
#ifdef WIN32
    CreateDirectory("dummy_bridge_creds", NULL);
#else
    mkdir("dummy_bridge_creds", 0755);
#endif
  }
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
    case 8:
      display_ascii_ui = !display_ascii_ui;
      break;
#ifdef OC_SECURITY
    case 9:
      reset_device();
      break;
#endif /* OC_SECURITY */
    case 10:
      delete_device();
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
