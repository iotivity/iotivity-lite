/****************************************************************************
 *
 * Copyright (c) 2017-2019 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd.
 * Copyright (c) 2021 Cable Televesion Laboratories Ltd.
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
 ****************************************************************************/

#include "api/oc_ri_internal.h"
#include "oc_api.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "oc_log.h"
#include "oc_obt.h"
#include "oc_python.h"
#include "oc_python_internal.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"
#include "util/oc_buffer_internal.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#ifdef OC_SECURITY
#include "security/oc_obt_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_SO
#include "oc_streamlined_onboarding.h"
#endif

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#include <pthread.h>
#else
#error "Unsupported OS"
#endif
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NUM_DEVICES (50)
#define MAX_URI_LENGTH (30)

/* Pool of device handles */
OC_MEMB(g_device_handles_s, device_handle_t, MAX_NUM_DEVICES);
/* List of known owned devices */
OC_LIST(g_owned_devices);
/* List of known un-owned devices */
OC_LIST(g_unowned_devices);

#ifdef OC_SO
/* Diplomat resource information */
static char diplomat_uri[MAX_URI_LENGTH];
static oc_endpoint_t *diplomat_ep;
#endif

#if defined(_WIN32)
static HANDLE event_thread;
static CRITICAL_SECTION app_sync_lock;
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

/* OS specific definition for lock/unlock */
#define otb_mutex_lock(m) EnterCriticalSection(&m)
#define otb_mutex_unlock(m) LeaveCriticalSection(&m)

#elif defined(__linux__)
static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;

/* OS specific definition for lock/unlock */
#define otb_mutex_lock(m) pthread_mutex_lock(&(m))
#define otb_mutex_unlock(m) pthread_mutex_unlock(&(m))
#endif

static OC_ATOMIC_INT8_T quit = 0;

/**
 * structure with the callback
 *
 */
struct py_cb_struct
{
  changedCB changedFCB;
  diplomatCB diplomatFCB;
  resourceCB resourceFCB;
  clientCB clientFCB;
};

/**
 * declaration of the callback
 *
 */
struct py_cb_struct my_CBFunctions;

#if 0

/**
 * Function to return response strings
 */

static inline char *
stringFromResponse(int code)
{
  static char *strings[] = { "STATUS_OK",
                             "STATUS_CREATED",
                             "STATUS_CHANGED",
                             "STATUS_DELETED",
                             "STATUS_NOT_MODIFIED",
                             "STATUS_BAD_REQUEST",
                             "STATUS_UNAUTHORIZED",
                             "STATUS_BAD_OPTION",
                             "STATUS_FORBIDDEN",
                             "STATUS_NOT_FOUND",
                             "STATUS_METHOD_NOT_ALLOWED",
                             "STATUS_NOT_ACCEPTABLE",
                             "STATUS_REQUEST_ENTITY_TOO_LARGE",
                             "STATUS_UNSUPPORTED_MEDIA_TYPE",
                             "STATUS_INTERNAL_SERVER_ERROR",
                             "STATUS_NOT_IMPLEMENTED",
                             "STATUS_BAD_GATEWAY",
                             "STATUS_SERVICE_UNAVAILABLE",
                             "STATUS_GATEWAY_TIMEOUT",
                             "STATUS_PROXYING_NOT_SUPPORTED",
                             "__NUM_STATUS_CODES__",
                             "IGNORE",
                             "PING_TIMEOUT",
                             "OC_REQUEST_TIMEOUT" };
  return strings[code];
}

#endif

void
install_changedCB(changedCB changedCB)
{
  OC_PRINTF("[C]install_changedCB\n");
  my_CBFunctions.changedFCB = changedCB;
}

void
install_diplomatCB(diplomatCB diplomatCB)
{
  OC_PRINTF("[C]install_diplomatCB\n");
  my_CBFunctions.diplomatFCB = diplomatCB;
}

void
install_resourceCB(resourceCB resourceCB)
{
  OC_PRINTF("[C]install_resourceCB\n");
  my_CBFunctions.resourceFCB = resourceCB;
}

void
install_clientCB(clientCB clientCB)
{
  OC_PRINTF("[C]install_clientCB\n");
  my_CBFunctions.clientFCB = clientCB;
}

void
inform_python(const char *uuid, const char *state, const char *event)
{
  // OC_PRINTF("[C]inform_python %p\n",my_CBFunctions.changedFCB);
  if (my_CBFunctions.changedFCB != NULL) {
    my_CBFunctions.changedFCB(uuid, state, event);
  }
}

void
inform_resource_python(const char *anchor, const char *uri, const char *types,
                       const char *interfaces)
{
  // OC_PRINTF("[C]inform_resource_python %p %s %s [%s]
  // [%s]\n",my_CBFunctions.resourceFCB, anchor, uri, types, interfaces);
  if (my_CBFunctions.resourceFCB != NULL) {
    my_CBFunctions.resourceFCB(anchor, uri, types, interfaces);
  }
}

void
print_rep(const oc_rep_t *rep, bool pretty_print)
{
  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, pretty_print);
  OC_PRINTF("%s\n", json);
  free(json);
}

char *response_payload;
char *
get_response_payload(void)
{
  return response_payload;
}

void
save_rep(const oc_rep_t *rep, bool pretty_print)
{
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  response_payload = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, response_payload, json_size + 1, pretty_print);
}

void
inform_diplomat_python(const char *anchor, const char *uri, const char *state,
                       const char *event, const char *target,
                       const char *target_cred)
{
  // OC_PRINTF("[C]inform_python %p\n", (void
  // *)(uintptr_t)my_CBFunctions.diplomatFCB);
  if (my_CBFunctions.diplomatFCB != NULL) {
    my_CBFunctions.diplomatFCB(anchor, uri, state, event, target, target_cred);
  }
}

void
inform_client_python(const char *uuid, const char *state, const char *event)
{
  // OC_PRINTF("[C]inform_python %p\n", (void
  // *)(uintptr_t)my_CBFunctions.clientFCB);
  if (my_CBFunctions.clientFCB != NULL) {
    my_CBFunctions.clientFCB(uuid, state, event);
  }
}

device_handle_t *
py_getdevice_from_uuid(const char *uuid, int owned)
{
  device_handle_t *device = NULL;
  if (owned == 1) {
    device = (device_handle_t *)oc_list_head(g_owned_devices);
  } else {
    device = (device_handle_t *)oc_list_head(g_unowned_devices);
  }

  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    if (strcmp(di, uuid) == 0) {
      return device;
    }
    device = device->next;
  }
  return NULL;
}

/**
 * start the application, e.g. the OBT/client
 */
static int
app_init(void)
{
  // OC_PRINTF("[C]app_init\n");
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.2.2",
                       "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
  oc_device_bind_resource_type(0, "oic.d.ams");
  oc_device_bind_resource_type(0, "oic.d.cms");
  return ret;
}

/**
 * function to initate the obt
 * this is a callback function of device init.
 *
 */
static void
issue_requests(void)
{
  // OC_PRINTF("[C]issue_requests\n");
  int retval = oc_obt_init();
  OC_PRINTF("[C]obt initialized! %d\n", retval);
}

/**
 * event loop (window/linux) used for the python initated thread.
 *
 */
static void
signal_event_loop(void)
{
#if defined(_WIN32)
  WakeConditionVariable(&cv);
#elif defined(__linux__)
  pthread_cond_signal(&cv);
#endif
}

void
python_exit(int signal)
{
  (void)signal;
  OC_ATOMIC_STORE8(quit, 1);
  signal_event_loop();
}

/**
 * the event thread (windows or linux)
 *
 */
#if defined(_WIN32)
static DWORD WINAPI
ocf_event_thread(LPVOID lpParam)
{
  (void)lpParam;
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event_mt = oc_main_poll_v1();
    otb_mutex_unlock(app_sync_lock);

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

  oc_main_shutdown();
  oc_obt_shutdown();
  return TRUE;
}
#elif defined(__linux__)
static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event_mt = oc_main_poll_v1();
    otb_mutex_unlock(app_sync_lock);

    otb_mutex_lock(mutex);
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
    otb_mutex_unlock(mutex);
  }
  oc_main_shutdown();
  oc_obt_shutdown();
  return NULL;
}
#endif

/* App utility functions */
static device_handle_t *
is_device_in_list(const oc_uuid_t *uuid, oc_list_t list)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(list);
  while (device != NULL) {
    if (memcmp(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id)) == 0) {
      return device;
    }
    device = device->next;
  }
  return NULL;
}

static void
set_obt_device(device_handle_t *device, const oc_uuid_t *uuid,
               const char *device_name)
{
  memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  size_t len = 0;
  if (device_name != NULL) {
    len = strlen(device_name);
    len = (len > 63) ? 63 : len;
    memcpy(device->device_name, device_name, len);
  }
  device->device_name[len] = '\0';
}

static bool
add_device_to_list(const oc_uuid_t *uuid, const char *device_name,
                   oc_list_t list)
{
  device_handle_t *device = is_device_in_list(uuid, list);

  if (!device) {
    device = oc_memb_alloc(&g_device_handles_s);
    if (!device) {
      return false;
    }
    memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
    oc_list_add(list, device);
  }

  size_t len = 0;
  if (device_name != NULL) {
    len = strlen(device_name);
    len = (len > 63) ? 63 : len;
    memcpy(device->device_name, device_name, len);
  }
  device->device_name[len] = '\0';
  return true;
}

void
empty_device_list(oc_list_t list)
{
  device_handle_t *device = (device_handle_t *)oc_list_pop(list);
  while (device != NULL) {
    oc_memb_free(&g_device_handles_s, device);
    device = (device_handle_t *)oc_list_pop(list);
  }
}
/* End of app utility functions */

/* App invocations of oc_obt APIs */

bool cb_result = false;
bool
get_cb_result(void)
{
  bool result_to_return = cb_result;
  cb_result = false;
  return result_to_return;
}

static void
get_device(oc_client_response_t *data)
{
  const oc_rep_t *rep = data->payload;
  char *di = NULL;
  size_t di_len = 0;
  if (!oc_rep_get_string(rep, "di", &di, &di_len)) {
    return;
  }

  char *n = NULL;
  size_t n_len = 0;
  oc_uuid_t uuid;
  oc_str_to_uuid(di, &uuid);
  if (!oc_rep_get_string(rep, "n", &n, &n_len)) {
    n = NULL;
    n_len = 0;
  }

  OC_PRINTF("[C] adding device to list.%s.%s\n", di, n);
  add_device_to_list(&uuid, n, data->user_data);

  bool owned = oc_obt_is_owned_device(&uuid);
  const char *state = owned ? "owned" : "unowned";
  OC_PRINTF("[C] adding device to list...\n");
  inform_python(di, state, NULL);
}

static void
unowned_device_cb(const oc_uuid_t *uuid, const oc_endpoint_t *eps, void *data)
{
  (void)data;
  (void)uuid;
  oc_do_get("/oic/d", eps, NULL, &get_device, HIGH_QOS, g_unowned_devices);
}

static void
owned_device_cb(const oc_uuid_t *uuid, const oc_endpoint_t *eps, void *data)
{
  (void)data;
  (void)uuid;
  oc_do_get("/oic/d", eps, NULL, &get_device, HIGH_QOS, g_owned_devices);
}

void
discover_owned_devices(int scope)
{
  // OC_PRINTF("[C]discover_owned_devices: scope %d\n", scope);
  otb_mutex_lock(app_sync_lock);
  if (scope == 0x02) {
    oc_obt_discover_owned_devices(owned_device_cb, NULL);
  } else if (scope == 0x03) {
    oc_obt_discover_owned_devices_realm_local_ipv6(owned_device_cb, NULL);
  } else if (scope == 0x05) {
    oc_obt_discover_owned_devices_site_local_ipv6(owned_device_cb, NULL);
  }
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

void
discover_unowned_devices(int scope)
{
  // OC_PRINTF("[C]discover_unowned_devices: scope %d\n", scope);
  otb_mutex_lock(app_sync_lock);
  if (scope == 0x02) {
    oc_obt_discover_unowned_devices(unowned_device_cb, NULL);
  } else if (scope == 0x03) {
    oc_obt_discover_unowned_devices_realm_local_ipv6(unowned_device_cb, NULL);
  } else if (scope == 0x05) {
    oc_obt_discover_unowned_devices_site_local_ipv6(unowned_device_cb, NULL);
  }
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

void
py_discover_unowned_devices(int scope)
{
  // OC_PRINTF("[C]discover_unowned_devices: scope %d\n", scope);
  otb_mutex_lock(app_sync_lock);
  if (scope == 0x02) {
    oc_obt_discover_unowned_devices(unowned_device_cb, NULL);
  } else if (scope == 0x03) {
    oc_obt_discover_unowned_devices_realm_local_ipv6(unowned_device_cb, NULL);
  } else if (scope == 0x05) {
    oc_obt_discover_unowned_devices_site_local_ipv6(unowned_device_cb, NULL);
  }
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

static void
otm_rdp_cb(const oc_uuid_t *uuid, int status, void *data)
{
  device_handle_t *device = (device_handle_t *)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));
  if (status < 0) {
    OC_PRINTF("[C]\nERROR performing ownership transfer on device %s\n", di);
    oc_memb_free(&g_device_handles_s, device);
    return;
  }

  memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  OC_PRINTF("[C]\nSuccessfully performed OTM on device %s\n", di);
  oc_list_add(g_owned_devices, device);
  inform_python(NULL, NULL, NULL);
}

void
py_otm_rdp(const char *uuid, const char *pin)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(g_unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  int c = -1;
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    devices[i] = device;
    if (strcmp(uuid, di) == 0) {
      c = i;
    }
    i++;
    device = device->next;
  }
  if (c == -1) {
    OC_PRINTF("[C] ERROR: Invalid uuid\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret =
    oc_obt_perform_random_pin_otm(&devices[c]->uuid, (const unsigned char *)pin,
                                  strlen(pin), otm_rdp_cb, devices[c]);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued request to perform Random PIN OTM\n");
    /* Having issued an OTM request, remove this item from the unowned device
     * list
     */
    oc_list_remove(g_unowned_devices, devices[c]);
  } else {
    OC_PRINTF("[C]\nERROR issuing request to perform Random PIN OTM\n");
  }

  otb_mutex_unlock(app_sync_lock);
}

static void
random_pin_cb(const oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF(
      "[C]\nSuccessfully requested device %s to generate a Random PIN\n", di);
    inform_python(di, "unowned", "random_pin_request");
  } else {
    OC_PRINTF("[C]\nERROR requesting device %s to generate a Random PIN\n", di);
    inform_python(di, "unowned", "random_pin_request_error");
  }
}

void
py_request_random_pin(const char *uuid)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(g_unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  int c = -1;
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    devices[i] = device;
    if (strcmp(uuid, di) == 0) {
      c = i;
    }
    i++;
    device = device->next;
  }
  if (c == -1) {
    OC_PRINTF("[C] ERROR: Invalid uuid\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);

  int ret = oc_obt_request_random_pin(&devices[c]->uuid, random_pin_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued request to generate a random PIN\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing request to generate random PIN\n");
  }

  otb_mutex_unlock(app_sync_lock);
}

#ifdef OC_PKI
void
otm_cert_cb(const oc_uuid_t *uuid, int status, void *data)
{
  device_handle_t *device = (device_handle_t *)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));
  if (status < 0) {
    OC_PRINTF("[C]\nERROR performing ownership transfer on device %s\n", di);
    oc_memb_free(&g_device_handles_s, device);
    return;
  }

  memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  OC_PRINTF("[C]\nSuccessfully performed OTM on device %s\n", di);
  oc_list_add(g_owned_devices, device);
  inform_python(NULL, NULL, NULL);
}

#endif /* OC_PKI */

static void
otm_just_works_cb(const oc_uuid_t *uuid, int status, void *data)
{
  device_handle_t *device = (device_handle_t *)data;
  memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status < 0) {
    oc_memb_free(&g_device_handles_s, device);
    OC_PRINTF("[C]\nERROR performing ownership transfer on device %s\n", di);
    cb_result = false;
    return;
  }
  OC_PRINTF("[C]\nSuccessfully performed OTM on device with UUID %s\n", di);
  oc_list_add(g_owned_devices, device);
  inform_python(NULL, NULL, NULL);
  cb_result = true;
}

void
py_list_unowned_devices(void)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(g_unowned_devices);
  int i = 0;
  OC_PRINTF("[C] py_list_unowned_devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[C] [%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
}

void
py_list_owned_devices(void)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(g_owned_devices);
  int i = 0;
  OC_PRINTF("[C] py_list_owned_devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[C] [%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
}

void
py_otm_just_works(const char *uuid)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(g_unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  int c = -1;
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    devices[i] = device;
    if (strcmp(uuid, di) == 0) {
      c = i;
    }
    i++;
    device = device->next;
  }
  if (c == -1) {
    OC_PRINTF("[C] ERROR: Invalid uuid\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);

  int ret = oc_obt_perform_just_works_otm(&devices[c]->uuid, otm_just_works_cb,
                                          devices[c]);
  if (ret >= 0) {
    OC_PRINTF(
      "[C] Successfully issued request to perform ownership transfer\n");
    /* Having issued an OTM request, remove this item from the unowned device
     * list
     */
    oc_list_remove(g_unowned_devices, devices[c]);
    inform_python(NULL, NULL, NULL);
  } else {
    OC_PRINTF("[C] ERROR issuing request to perform ownership transfer\n");
  }

  otb_mutex_unlock(app_sync_lock);
}

static void
retrieve_acl2_rsrc_cb(oc_sec_acl_t *acl, void *data)
{
  (void)data;
  if (acl) {
    OC_PRINTF("[C]\n/oic/sec/acl2:\n");
    oc_sec_ace_t *ac = oc_list_head(acl->subjects);
    OC_PRINTF("[C]\n################################################\n");
    while (ac) {
      OC_PRINTF("[C]aceid: %d\n", ac->aceid);
      if (ac->subject_type == OC_SUBJECT_UUID) {
        char uuid[37];
        oc_uuid_to_str(&ac->subject.uuid, uuid, 37);
        OC_PRINTF("[C]subject: %s\n", uuid);
      } else if (ac->subject_type == OC_SUBJECT_ROLE) {
        OC_PRINTF("[C]Roleid_role: %s\n", oc_string(ac->subject.role.role));
        if (oc_string_len(ac->subject.role.authority) > 0) {
          OC_PRINTF("[C]Roleid_authority: %s\n",
                    oc_string(ac->subject.role.authority));
        }
      } else if (ac->subject_type == OC_SUBJECT_CONN) {
        OC_PRINTF("[C]connection type: ");
        if (ac->subject.conn == OC_CONN_AUTH_CRYPT) {
          OC_PRINTF("auth-crypt\n");
        } else {
          OC_PRINTF("anon-clear\n");
        }
      }
      OC_PRINTF("[C]Permissions: ");
      if (ac->permission & OC_PERM_CREATE) {
        OC_PRINTF("[C] C ");
      }
      if (ac->permission & OC_PERM_RETRIEVE) {
        OC_PRINTF("[C] R ");
      }
      if (ac->permission & OC_PERM_UPDATE) {
        OC_PRINTF("[C] U ");
      }
      if (ac->permission & OC_PERM_DELETE) {
        OC_PRINTF("[C] D ");
      }
      if (ac->permission & OC_PERM_NOTIFY) {
        OC_PRINTF("[C] N ");
      }
      OC_PRINTF("[C]\n");
      OC_PRINTF("[C]Resources: ");
      oc_ace_res_t *res = oc_list_head(ac->resources);
      while (res) {
        if (oc_string_len(res->href) > 0) {
          OC_PRINTF("[C] %s ", oc_string(res->href));
        } else if (res->wildcard != 0) {
          switch (res->wildcard) {
          case OC_ACE_WC_ALL:
            OC_PRINTF("[C] * ");
            break;
          case OC_ACE_WC_ALL_SECURED:
            OC_PRINTF("[C] + ");
            break;
          case OC_ACE_WC_ALL_PUBLIC:
            OC_PRINTF("[C] - ");
            break;
          default:
            break;
          }
        }
        res = res->next;
      }
      ac = ac->next;
      OC_PRINTF("[C]\n-----\n");
    }
    OC_PRINTF("[C]\n################################################\n");

    /* Freeing the ACL structure */
    oc_obt_free_acl(acl);
    cb_result = true;
  } else {
    OC_PRINTF("[C]\nERROR RETRIEVING /oic/sec/acl2\n");
    cb_result = false;
  }
}

void
py_retrieve_acl2(const char *uuid)
{
  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);
  if (device == NULL) {
    device = py_getdevice_from_uuid(uuid, 0);
  }
  if (device == NULL) {
    OC_PRINTF("[C] py_retrieve_acl2 ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_retrieve_acl2: name = %s ", device->device_name);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_retrieve_acl(&device->uuid, retrieve_acl2_rsrc_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued request to retrieve ACL2\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing request to retrieve ACL2\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

void
display_cred_rsrc(const oc_sec_creds_t *creds)
{
  if (creds) {
    OC_PRINTF("[C]\n/oic/sec/cred:\n");
    const oc_sec_cred_t *cr = oc_list_head(creds->creds);
    OC_PRINTF("[C]\n################################################\n");
    while (cr) {
      char uuid[OC_UUID_LEN];
      oc_uuid_to_str(&cr->subjectuuid, uuid, OC_ARRAY_SIZE(uuid));
      OC_PRINTF("[C]credid: %d\n", cr->credid);
      OC_PRINTF("[C]subjectuuid: %s\n", uuid);
      OC_PRINTF("[C]credtype: %s\n", oc_cred_credtype_string(cr->credtype));
#ifdef OC_PKI
      OC_PRINTF("[C]credusage: %s\n", oc_cred_read_credusage(cr->credusage));
      if (oc_string_len(cr->publicdata.data) > 0) {
        OC_PRINTF("[C]publicdata_encoding: %s\n",
                  oc_cred_read_encoding(cr->publicdata.encoding));
      }
#endif /* OC_PKI */
      OC_PRINTF("[C]privatedata_encoding: %s\n",
                oc_cred_read_encoding(cr->privatedata.encoding));
      if (oc_string_len(cr->role.role) > 0) {
        OC_PRINTF("[C]roleid_role: %s\n", oc_string(cr->role.role));
      }
      if (oc_string_len(cr->role.authority) > 0) {
        OC_PRINTF("[C]roleid_authority: %s\n", oc_string(cr->role.authority));
      }
      OC_PRINTF("[C]\n-----\n");
      cr = cr->next;
    }
    OC_PRINTF("[C]\n################################################\n");
  }
}

void
retrieve_cred_rsrc_cb(oc_sec_creds_t *creds, void *data)
{
  (void)data;
  if (creds) {
    display_cred_rsrc(creds);
    /* Freeing the creds structure */
    oc_obt_free_creds(creds);
  } else {
    OC_PRINTF("[C]\nERROR RETRIEving /oic/sec/cred\n");
  }
}

void
retrieve_own_creds(void)
{
  otb_mutex_lock(app_sync_lock);
  /* The creds returned by oc_obt_retrieve_own_creds() point to
     internal data structures that store the security context of the OBT.
     DO NOT free them.
  */
  display_cred_rsrc(oc_obt_retrieve_own_creds());
  otb_mutex_unlock(app_sync_lock);
}

void
delete_ace_by_aceid_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully DELETEd ace\n");
  } else {
    OC_PRINTF("[C]\nERROR DELETing ace\n");
  }
}

void
delete_cred_by_credid_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully DELETEd cred\n");
  } else {
    OC_PRINTF("[C]\nERROR DELETing cred\n");
  }
}

/**
 * function to handle the reset
 */
static void
reset_device_cb(const oc_uuid_t *uuid, int status, void *data)
{
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status < 0) {
    OC_PRINTF("[C]\nERROR performing hard RESET to device %s\n", di);
    oc_memb_free(&g_device_handles_s, data);
    cb_result = false;
    return;
  }

  OC_PRINTF("[C]\nSuccessfully performed hard RESET to device %s\n", di);
  inform_python(NULL, NULL, NULL);

  const device_handle_t *device = py_getdevice_from_uuid(di, 1);
  oc_list_remove(g_owned_devices, device);
  oc_memb_free(&g_device_handles_s, data);

  const char *state = "reset";
  inform_python(di, state, NULL);
  cb_result = true;
}

int
py_get_nr_owned_devices(void)
{
  return (oc_list_length(g_owned_devices));
}

const char *
get_uuid(int owned, int index)
{
  device_handle_t *device = NULL;
  if (owned == 1) {
    device = (device_handle_t *)oc_list_head(g_owned_devices);
  } else {
    device = (device_handle_t *)oc_list_head(g_unowned_devices);
  }

  int i = 0;
  static char di[OC_UUID_LEN];
  while (device != NULL) {
    oc_uuid_to_str(&device->uuid, di, OC_ARRAY_SIZE(di));
    if (index == i) {
      return di;
    }
    i++;
    device = device->next;
  }
  return " empty ";
}

const char *
get_device_name(int owned, int index)
{
  device_handle_t *device = NULL;
  if (owned == 1) {
    device = (device_handle_t *)oc_list_head(g_owned_devices);
  } else {
    device = (device_handle_t *)oc_list_head(g_unowned_devices);
  }

  int i = 0;
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    if (index == i) {
      return device->device_name;
    }
    i++;
    device = device->next;
  }
  return " empty ";
}

const char *
get_device_name_from_uuid(const char *uuid)
{
  device_handle_t *device = NULL;
  device = (device_handle_t *)oc_list_head(g_owned_devices);
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    if (strcmp(di, uuid) == 0) {
      return device->device_name;
    }
    device = device->next;
  }

  device = (device_handle_t *)oc_list_head(g_unowned_devices);
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    if (strcmp(di, uuid) == 0) {
      return device->device_name;
    }
    device = device->next;
  }
  return " empty ";
}

int
py_get_nr_unowned_devices(void)
{
  return (oc_list_length(g_unowned_devices));
}

void
py_reset_device(const char *uuid)
{
  device_handle_t *device = py_getdevice_from_uuid(uuid, 1);

  if (device == NULL) {
    OC_PRINTF("[C]ERROR: Invalid uuid\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_device_hard_reset(&device->uuid, reset_device_cb, device);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued request to perform hard RESET\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing request to perform hard RESET\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

#ifdef OC_PKI
static void
provision_id_cert_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully provisioned identity certificate\n");
    cb_result = true;
  } else {
    OC_PRINTF("[C]\nERROR provisioning identity certificate\n");
    cb_result = false;
  }
}

void
py_provision_id_cert(const char *uuid)
{
  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);

  if (device == NULL) {
    OC_PRINTF("[C]py_provision_id_cert ERROR: Invalid uuid\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_identity_certificate(&device->uuid,
                                                  provision_id_cert_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF(
      "[C]\nSuccessfully issued request to provision identity certificate\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing request to provision identity certificate\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
provision_role_cert_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully provisioned role certificate\n");
  } else {
    OC_PRINTF("[C]\nERROR provisioning role certificate\n");
  }
}

void
py_provision_role_cert(const char *uuid, const char *role, const char *auth)
{
  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);

  if (device == NULL) {
    OC_PRINTF("[C]py_provision_role_cert ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C]py_provision_role_cert: %s %s %s \n", uuid, role, auth);

  oc_role_t *roles = NULL;
  if (auth != NULL) {
    roles = oc_obt_add_roleid(roles, role, auth);
  } else {
    roles = oc_obt_add_roleid(roles, role, NULL);
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_role_certificate(roles, &device->uuid,
                                              provision_role_cert_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF(
      "[C]\nSuccessfully issued request to provision role certificate\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing request to provision role certificate\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

void
provision_role_wildcard_ace_cb(const oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully provisioned rold * ACE to device %s\n", di);
  } else {
    OC_PRINTF("[C]\nERROR provisioning ACE to device %s\n", di);
  }
}

#endif /* OC_PKI */

#ifdef OC_OSCORE
void
provision_group_context_cb(const oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF(
      "[C]\nSuccessfully provisioned group OSCORE context to device %s\n", di);
  } else {
    OC_PRINTF("[C]\nERROR provisioning group OSCORE context to device %s\n",
              di);
  }
}

void
provision_oscore_contexts_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully provisioned pairwise OSCORE contexts\n");
  } else {
    OC_PRINTF("[C]\nERROR provisioning pairwise OSCORE contexts\n");
  }
}

#endif /* OC_OSCORE */

static void
provision_credentials_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully provisioned pairwise credentials\n");
  } else {
    OC_PRINTF("[C]\nERROR provisioning pairwise credentials\n");
  }
}

void
py_provision_pairwise_credentials(const char *uuid1, const char *uuid2)
{
  OC_PRINTF("[C] Source %s, Target %s", uuid1, uuid2);
  if (oc_list_length(g_owned_devices) == 0) {
    OC_PRINTF("[C]\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  const device_handle_t *device1 = py_getdevice_from_uuid(uuid1, 1);
  const device_handle_t *device2 = py_getdevice_from_uuid(uuid2, 1);
  if (device1 == NULL) {
    OC_PRINTF("[C]py_provision_role_cert ERROR: Invalid uuid1 %s \n", uuid1);
    return;
  }
  if (device2 == NULL) {
    OC_PRINTF("[C]py_provision_role_cert ERROR: Invalid uuid2 %s \n", uuid2);
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_pairwise_credentials(
    &device1->uuid, &device2->uuid, provision_credentials_cb, NULL);
  OC_PRINTF("[C]Provisioning Pariwise\n");
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued request to provision credentials\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing request to provision credentials\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

void
provision_authcrypt_wildcard_ace_cb(const oc_uuid_t *uuid, int status,
                                    void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully provisioned auth-crypt * ACE to device %s\n",
              di);
  } else {
    OC_PRINTF("[C]\nERROR provisioning ACE to device %s\n", di);
  }
}

static void
provision_ace2_cb(const oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully provisioned ACE to device %s\n", di);
    cb_result = true;
  } else {
    OC_PRINTF("[C]\nERROR provisioning ACE to device %s\n", di);
    cb_result = false;
  }
}

void
py_provision_ace_cloud_access(const char *uuid)
{

  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);

  if (device == NULL) {
    OC_PRINTF("[C]py_provision_ace_cloud_access ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_provision_ace: name = %s \n", device->device_name);

  oc_sec_ace_t *ace = NULL;
  ace = oc_obt_new_ace_for_connection(OC_CONN_AUTH_CRYPT);

  oc_ace_res_t *res = oc_obt_ace_new_resource(ace);
  oc_obt_ace_resource_set_href(res, "/CoapCloudConfResURI");
  oc_obt_ace_resource_set_wc(res, OC_ACE_NO_WC);

  oc_ace_res_t *res_wc = oc_obt_ace_new_resource(ace);
  oc_obt_ace_resource_set_wc(res_wc, OC_ACE_WC_ALL);

  oc_obt_ace_add_permission(ace, OC_PERM_CREATE);
  oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE);
  oc_obt_ace_add_permission(ace, OC_PERM_UPDATE);
  oc_obt_ace_add_permission(ace, OC_PERM_DELETE);
  oc_obt_ace_add_permission(ace, OC_PERM_NOTIFY);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_ace(&device->uuid, ace, provision_ace2_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("[C] Successfully issued request to provision ACE\n");
  } else {
    OC_PRINTF("[C] ERROR issuing request to provision ACE\n");
    oc_obt_free_ace(ace);
  }
}

void
py_provision_ace_to_obt(const char *uuid, const char *res_uri)
{

  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);

  if (device == NULL) {
    OC_PRINTF("[C]py_provision_ace_to_obt ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_provision_ace: name = %s \n", device->device_name);

  oc_sec_ace_t *ace = NULL;
  ace = oc_obt_new_ace_for_subject(oc_core_get_device_id(0));

  oc_ace_res_t *res = oc_obt_ace_new_resource(ace);
  oc_obt_ace_resource_set_href(res, res_uri);
  oc_obt_ace_resource_set_wc(res, OC_ACE_NO_WC);

  oc_obt_ace_add_permission(ace, OC_PERM_CREATE);
  oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE);
  oc_obt_ace_add_permission(ace, OC_PERM_UPDATE);
  oc_obt_ace_add_permission(ace, OC_PERM_DELETE);
  oc_obt_ace_add_permission(ace, OC_PERM_NOTIFY);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_ace(&device->uuid, ace, provision_ace2_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("[C] Successfully issued request to provision ACE %s\n", res_uri);
  } else {
    OC_PRINTF("[C] ERROR issuing request to provision ACE %s\n", res_uri);
    oc_obt_free_ace(ace);
  }
}

void
py_provision_ace_device_resources(const char *device_uuid,
                                  const char *subject_uuid)
{

  const device_handle_t *device = py_getdevice_from_uuid(device_uuid, 1);

  oc_uuid_t subjectuuid;
  oc_str_to_uuid(subject_uuid, &subjectuuid);

  if (device == NULL) {
    OC_PRINTF("[C]py_provision_ace_device_resources ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_provision_ace: name = %s \n", device->device_name);

  oc_sec_ace_t *ace = NULL;
  ace = oc_obt_new_ace_for_subject(&subjectuuid);

  oc_ace_res_t *res_wc = oc_obt_ace_new_resource(ace);
  oc_obt_ace_resource_set_wc(res_wc, OC_ACE_WC_ALL);

  oc_obt_ace_add_permission(ace, OC_PERM_CREATE);
  oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE);
  oc_obt_ace_add_permission(ace, OC_PERM_UPDATE);
  oc_obt_ace_add_permission(ace, OC_PERM_DELETE);
  oc_obt_ace_add_permission(ace, OC_PERM_NOTIFY);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_ace(&device->uuid, ace, provision_ace2_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("[C] Successfully issued request to provision ACE\n");
  } else {
    OC_PRINTF("[C] ERROR issuing request to provision ACE\n");
    oc_obt_free_ace(ace);
  }
}

void
py_provision_ace2(const char *target, const char *subject, const char *href,
                  char *crudn)
{
  assert(target != NULL);
  assert(subject != NULL);
  assert(href != NULL);
  assert(crudn != NULL);
  OC_PRINTF("[C] Provision ACE2: %s,%s,%s,%s\n", target, subject, href, crudn);
  const device_handle_t *device = py_getdevice_from_uuid(target, 1);
  device_handle_t subject_device_obt;
  const device_handle_t *subject_device = py_getdevice_from_uuid(subject, 1);

  /*check if subject is OBT device*/
  const oc_uuid_t *obt_uuid = oc_core_get_device_id(0);
  char di[OC_UUID_LEN];
  oc_uuid_to_str(obt_uuid, di, OC_UUID_LEN);
  if (strncmp(di, subject, OC_UUID_LEN) == 0) {
    memset(&subject_device_obt, 0, sizeof(device_handle_t));
    set_obt_device(&subject_device_obt, obt_uuid, "OBT");
    subject_device = &subject_device_obt;
  }
  if (device == NULL) {
    OC_PRINTF("[C]py_provision_ace_access ERROR: Invalid uuid\n");
    return;
  }
  if (subject_device == NULL) {
    OC_PRINTF("[C]py_provision_ace_access ERROR: Invalid subject uuid\n");
    return;
  }
  if (crudn[0] == '\0') {
    OC_PRINTF("[C]py_provision_ace_access ERROR: No CRUDN provided\n");
    return;
  }
  if (href[0] == '\0') {
    OC_PRINTF("[C]py_provision_ace_access ERROR: No resource href provided\n");
    return;
  }
  OC_PRINTF("[C] py_provision_ace: name = %s  href = %s crudn=%s",
            device->device_name, href, crudn);

  oc_sec_ace_t *ace = oc_obt_new_ace_for_subject(&subject_device->uuid);

  oc_ace_res_t *res = oc_obt_ace_new_resource(ace);
  oc_obt_ace_resource_set_href(res, href);
  oc_obt_ace_resource_set_wc(res, OC_ACE_NO_WC);
  const char *crudn_array = strtok(crudn, "|");

  while (crudn_array != NULL) {
    OC_PRINTF("- %s\n", crudn_array);
    if (strcmp(crudn_array, "create") == 0) {
      oc_obt_ace_add_permission(ace, OC_PERM_CREATE);
    }
    if (strcmp(crudn_array, "retrieve") == 0) {
      oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE);
    }
    if (strcmp(crudn_array, "update") == 0) {
      oc_obt_ace_add_permission(ace, OC_PERM_UPDATE);
    }
    if (strcmp(crudn_array, "delete") == 0) {
      oc_obt_ace_add_permission(ace, OC_PERM_DELETE);
    }
    if (strcmp(crudn_array, "notify") == 0) {
      oc_obt_ace_add_permission(ace, OC_PERM_NOTIFY);
    }
    crudn_array = strtok(NULL, "|");
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_ace(&device->uuid, ace, provision_ace2_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("[C] Successfully issued request to provision ACE\n");
  } else {
    OC_PRINTF("[C] ERROR issuing request to provision ACE\n");
    oc_obt_free_ace(ace);
  }
}

#if defined(OC_SECURITY) && defined(OC_PKI)
int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    OC_PRINTF("[C]ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    OC_PRINTF("[C]ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    OC_PRINTF("[C]ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)*buffer_len) {
    OC_PRINTF("[C]ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    OC_PRINTF("[C]ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  size_t to_read = (size_t)pem_len;
  if (fread(buffer, 1, to_read, fp) < (size_t)pem_len) {
    OC_PRINTF("[C]ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buffer[pem_len] = '\0';
  *buffer_len = (size_t)pem_len;
  return 0;
}
#endif /* OC_SECURITY && OC_PKI */

#ifdef OC_PKI
void
install_trust_anchor(void)
{
  char cert[8192];
  size_t cert_len = 0;
  OC_PRINTF(
    "[C]\nPaste certificate here, then hit <ENTER> and type \"done\": ");
  int c;
  while ((c = getchar()) == '\n' || c == '\r')
    ;
  for (; (cert_len < 4 ||
          (cert_len >= 4 && memcmp(&cert[cert_len - 4], "done", 4) != 0));
       c = getchar()) {
    if (c == EOF) {
      OC_PRINTF("[C]ERROR processing input.. aborting\n");
      return;
    }
    cert[cert_len] = (char)c;
    cert_len++;
  }

  while (cert[cert_len - 1] != '-' && cert_len > 1) {
    cert_len--;
  }
  cert[cert_len] = '\0';

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, strlen(cert));
  if (rootca_credid < 0) {
    OC_PRINTF("[C]ERROR installing root cert\n");
    return;
  }
}
#endif /* OC_PKI */

void
set_sd_info(void)
{
  char name[64] = { 0 };
  int priv = 0;
  OC_PRINTF("[C]\n\nEnter security domain name: ");
  OC_PRINTF("[C]\n\nChoose security domain priv[0-No, 1-Yes]: ");
  oc_obt_set_sd_info(name, priv);
}

#ifdef OC_CLOUD

static void
post_response_cloud_config(oc_client_response_t *data)
{
  OC_PRINTF("[C]post_response_cloud_config:\n");
  if (data->code == OC_STATUS_CHANGED) {
    OC_PRINTF("[C]POST response: CHANGED\n");
    cb_result = true;
  } else if (data->code == OC_STATUS_CREATED) {
    OC_PRINTF("[C]POST response: CREATED\n");
    cb_result = true;
  } else {
    OC_PRINTF("[C]POST response code %d\n", data->code);
    cb_result = false;
  }
  if (data->payload != NULL) {
    print_rep(data->payload, false);
  }
}

void
py_provision_cloud_config_info(const char *uuid, const char *cloud_access_token,
                               const char *cloud_apn, const char *cloud_cis,
                               const char *cloud_id)
{
  oc_uuid_t device_uuid;
  oc_str_to_uuid(uuid, &device_uuid);

  char res_url[64] = "/CoapCloudConfResURI";

  otb_mutex_lock(app_sync_lock);

  oc_obt_update_cloud_conf_device(&device_uuid, res_url, cloud_access_token,
                                  cloud_apn, cloud_cis, cloud_id,
                                  post_response_cloud_config, NULL);

  otb_mutex_unlock(app_sync_lock);
}

void
trustanchorcb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("[C]\nSuccessfully installed trust anchor for cloud\n");
    cb_result = true;
  } else {
    OC_PRINTF("[C]\nERROR installing trust anchor %d\n", status);
    cb_result = false;
  }
}

void
py_provision_cloud_trust_anchor(const char *uuid, const char *cloud_id,
                                const char *cloud_trust_anchor)
{
  oc_uuid_t device_uuid;
  oc_str_to_uuid(uuid, &device_uuid);

  size_t cert_len = 545;

  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);
  if (device == NULL) {
    device = py_getdevice_from_uuid(uuid, 0);
  }
  if (device == NULL) {
    OC_PRINTF("[C] py_provision_cloud_trust_anchor ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_provision_cloud_trust_anchor: name = %s ",
            device->device_name);

  otb_mutex_lock(app_sync_lock);
  int retcode = oc_obt_provision_trust_anchor(
    cloud_trust_anchor, cert_len, cloud_id, &device_uuid, trustanchorcb, NULL);
  OC_PRINTF("[C]sending message: %d\n", retcode);
  otb_mutex_unlock(app_sync_lock);
}

static void
retrieve_d2dserverlist_cb(oc_client_response_t *data)
{
  if (data->payload != NULL) {
    OC_PRINTF("[C]get response /d2dserverlist payload: \n");
    print_rep(data->payload, false);
    cb_result = true;
  } else {
    OC_PRINTF("[C]ERROR RETRIEVING /d2dserverlist\n");
    cb_result = false;
  }
}

void
py_retrieve_d2dserverlist(const char *uuid)
{
  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);
  if (device == NULL) {
    device = py_getdevice_from_uuid(uuid, 0);
  }
  if (device == NULL) {
    OC_PRINTF("[C] py_retrieve_d2dserverlist ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_retrieve_d2dserverlist: name = %s ", device->device_name);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_retrieve_d2dserverlist(&device->uuid,
                                          retrieve_d2dserverlist_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued request to retrieve d2dserverlist\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing request to retrieve d2dserverlist\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
post_response_d2dserverlist(oc_client_response_t *data)
{
  OC_PRINTF("[C]post_response_d2dserverlist:\n");
  if (data->code == OC_STATUS_CHANGED) {
    OC_PRINTF("[C]POST response: CHANGED\n");
    cb_result = true;
  } else if (data->code == OC_STATUS_CREATED) {
    OC_PRINTF("[C]POST response: CREATED\n");
    cb_result = true;
  } else {
    OC_PRINTF("[C]POST response code %d\n", data->code);
    cb_result = false;
  }

  if (data->payload != NULL) {
    print_rep(data->payload, false);
  }
}

void
py_post_d2dserverlist(const char *cloud_proxy_uuid, const char *query)
{
  oc_uuid_t cloudproxyuuid;
  oc_str_to_uuid(cloud_proxy_uuid, &cloudproxyuuid);

  char res_url[64] = "/d2dserverlist";

  otb_mutex_lock(app_sync_lock);

  oc_obt_post_d2dserverlist(&cloudproxyuuid, query, res_url,
                            post_response_d2dserverlist, NULL);

  otb_mutex_unlock(app_sync_lock);
}
#endif /* OC_CLOUD */

static void
py_general_get_cb(oc_client_response_t *data)
{
  if (data->payload != NULL) {
    OC_PRINTF("[C]get response payload: \n");
    print_rep(data->payload, false);
    save_rep(data->payload, false);
    cb_result = true;
  } else {
    OC_PRINTF("[C]ERROR PERFORMING GET\n");
    cb_result = false;
  }
}

void
py_general_get(const char *uuid, const char *url)
{
  cb_result = false;
  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);
  if (device == NULL) {
    device = py_getdevice_from_uuid(uuid, 0);
  }
  if (device == NULL) {
    OC_PRINTF("[C] py_general_get ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_general_get: name = %s \n", device->device_name);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_general_get(&device->uuid, url, py_general_get_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued GET request\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing GET request\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
py_general_post_cb(oc_client_response_t *data)
{
  OC_PRINTF("[C]py_general_post_cb:\n");
  if (data->code == OC_STATUS_CHANGED) {
    OC_PRINTF("[C]POST response: CHANGED\n");
    cb_result = true;
  } else if (data->code == OC_STATUS_CREATED) {
    OC_PRINTF("[C]POST response: CREATED\n");
    cb_result = true;
  } else if (data->code == OC_STATUS_OK) {
    OC_PRINTF("[C]POST response: OK\n");
    cb_result = true;
  } else {
    OC_PRINTF("[C]POST response code %d\n", data->code);
    cb_result = false;
  }

  if (data->payload != NULL) {
    print_rep(data->payload, false);
    save_rep(data->payload, false);
  }
}

void
py_general_post(const char *uuid, const char *query, const char *url,
                char **payload_properties, char **payload_values,
                char **payload_types, int array_size)
{
  cb_result = false;
  oc_uuid_t deviceuuid;
  oc_str_to_uuid(uuid, &deviceuuid);

  otb_mutex_lock(app_sync_lock);

  oc_obt_general_post(&deviceuuid, query, url, py_general_post_cb, NULL,
                      payload_properties, payload_values, payload_types,
                      array_size);

  otb_mutex_unlock(app_sync_lock);
}

static void
py_general_delete_cb(oc_client_response_t *data)
{
  OC_PRINTF("[C]py_general_delete_cb:\n");
  if (data->code == OC_STATUS_CHANGED) {
    OC_PRINTF("[C]DELETE response: CHANGED\n");
    cb_result = true;
  } else if (data->code == OC_STATUS_CREATED) {
    OC_PRINTF("[C]DELETE response: CREATED\n");
    cb_result = true;
  } else if (data->code == OC_STATUS_OK) {
    OC_PRINTF("[C]DELETE response: OK\n");
    cb_result = true;
  } else {
    OC_PRINTF("[C]DELETE response code %d\n", data->code);
    cb_result = false;
  }

  if (data->payload != NULL) {
    print_rep(data->payload, false);
    save_rep(data->payload, false);
  }
}

void
py_general_delete(const char *uuid, const char *query, const char *url)
{
  cb_result = false;
  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);
  if (device == NULL) {
    device = py_getdevice_from_uuid(uuid, 0);
  }
  if (device == NULL) {
    OC_PRINTF("[C] py_general_delete ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_general_delete: name = %s \n", device->device_name);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_general_delete(&device->uuid, query, url,
                                  py_general_delete_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued DELETE request\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing DELETE request\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
  oc_obt_shutdown();
  empty_device_list(g_owned_devices);
  empty_device_list(g_unowned_devices);
  oc_obt_init();
#if defined(OC_SECURITY) && defined(OC_PKI)
  char cert[8192];
  size_t cert_len = 8192;

  cert_len = 8192;
  if (read_pem("pki_certs/rootca1.pem", cert, &cert_len) < 0) {
    OC_PRINTF("[C]ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("[C]ERROR installing root cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem("pki_certs/rootca2.pem", cert, &cert_len) < 0) {
    OC_PRINTF("[C]ERROR: unable to read certificates\n");
    return;
  }

  rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("[C]ERROR installing root cert\n");
    return;
  }
#endif /* OC_SECURITY && OC_PKI */
}

static bool
encode_resource_types(char *buffer, size_t buffer_size, oc_string_array_t types)
{
  oc_write_buffer_t wb = {
    .buffer = buffer,
    .buffer_size = buffer_size,
    .total = 0,
  };
  size_t array_size = oc_string_array_get_allocated_size(types);
  for (size_t i = 0; i < array_size; i++) {
    const char *t = oc_string_array_get_item(types, i);
    if (oc_buffer_write(&wb, "\"%s\"", t) < 0) {
      return false;
    }
    if ((i < array_size - 1) && (oc_buffer_write(&wb, ",") < 0)) {
      return false;
    }
  }
  return true;
}

static bool
encode_resource_interface(oc_write_buffer_t *wb, const char *iface, bool comma)
{
  if (comma && oc_buffer_write(wb, ",") < 0) {
    return false;
  }
  return oc_buffer_write(wb, "\"%s\"", iface) >= 0;
}

static bool
encode_resource_interfaces(char *buffer, size_t buffer_size,
                           oc_interface_mask_t iface_mask)
{
  oc_write_buffer_t wb = {
    .buffer = buffer,
    .buffer_size = buffer_size,
    .total = 0,
  };

  bool comma = false;
  if ((iface_mask & OC_IF_BASELINE) == OC_IF_BASELINE) {
    if (!encode_resource_interface(&wb, OC_IF_BASELINE_STR, comma)) {
      return false;
    }
    comma = true;
  }

  if ((iface_mask & OC_IF_RW) == OC_IF_RW) {
    if (!encode_resource_interface(&wb, OC_IF_RW_STR, comma)) {
      return false;
    }
    comma = true;
  }

  if ((iface_mask & OC_IF_R) == OC_IF_R) {
    if (!encode_resource_interface(&wb, OC_IF_R_STR, comma)) {
      return false;
    }
    comma = true;
  }

  if ((iface_mask & OC_IF_S) == OC_IF_S) {
    if (!encode_resource_interface(&wb, OC_IF_S_STR, comma)) {
      return false;
    }
    comma = true;
  }

  if ((iface_mask & OC_IF_A) == OC_IF_A) {
    if (!encode_resource_interface(&wb, OC_IF_A_STR, comma)) {
      return false;
    }
    comma = true;
  }

  if ((iface_mask & OC_IF_CREATE) == OC_IF_CREATE) {
    if (!encode_resource_interface(&wb, OC_IF_CREATE_STR, comma)) {
      return false;
    }
    comma = true;
  }

  if ((iface_mask & OC_IF_LL) == OC_IF_LL) {
    if (!encode_resource_interface(&wb, OC_IF_LL_STR, comma)) {
      return false;
    }
    comma = true;
  }

  if ((iface_mask & OC_IF_B) == OC_IF_B &&
      !encode_resource_interface(&wb, OC_IF_B_STR, comma)) {
    return false;
  }
  return true;
}

bool
encode_resource_discovery_payload(char *buffer, size_t buffer_size,
                                  const char *uri, const char *types,
                                  oc_interface_mask_t iface_mask)
{
  oc_write_buffer_t wb = {
    .buffer = buffer,
    .buffer_size = buffer_size,
    .total = 0,
  };
  if (oc_buffer_write(&wb, "{\"uri\":\"%s\",", uri) < 0) {
    return false;
  }
  if (oc_buffer_write(&wb, "\"types\":[%s],", types) < 0) {
    return false;
  }

  char strinterfaces[200] = " ";
  if (!encode_resource_interfaces(strinterfaces, OC_ARRAY_SIZE(strinterfaces),
                                  iface_mask)) {
    return false;
  }
  if (oc_buffer_write(&wb, "\"if\":[%s]", strinterfaces) < 0) {
    return false;
  }
  return oc_buffer_write(&wb, "}") > 0;
}

static oc_discovery_flags_t
resource_discovery(const char *anchor, const char *uri, oc_string_array_t types,
                   oc_interface_mask_t iface_mask,
                   const oc_endpoint_t *endpoint, oc_resource_properties_t bm,
                   bool more, void *user_data)
{
  (void)user_data;
  (void)bm;
  (void)endpoint;

  if (uri == NULL) {
    OC_PRINTF("[C]\nERROR DISCOVERING RESOURCES\n");
    cb_result = false;
    return OC_STOP_DISCOVERY;
  }

  char strtypes[200] = " ";
  if (!encode_resource_types(strtypes, OC_ARRAY_SIZE(strtypes), types)) {
    return false;
  }

  char json[1024] = "";
  if (!encode_resource_discovery_payload(json, OC_ARRAY_SIZE(json), uri,
                                         strtypes, iface_mask)) {
    OC_PRINTF("[C]\nERROR discovering resources: could not encode payload\n");
    cb_result = false;
    return OC_STOP_DISCOVERY;
  }

  // OC_PRINTF("[C]anchor %s, uri : %s\n", anchor, uri);
  inform_resource_python(anchor, uri, strtypes, json);
  if (!more) {
    OC_PRINTF("[C]----End of discovery response---\n");
    cb_result = true;
    return OC_STOP_DISCOVERY;
  }
  return OC_CONTINUE_DISCOVERY;
}

void
py_discover_resources(const char *uuid)
{
  const device_handle_t *device = py_getdevice_from_uuid(uuid, 1);
  if (device == NULL) {
    device = py_getdevice_from_uuid(uuid, 0);
  }
  if (device == NULL) {
    OC_PRINTF("[C]py_discover_resources ERROR: Invalid uuid\n");
    return;
  }
  OC_PRINTF("[C] py_discover_resources: name = %s ", device->device_name);

  otb_mutex_lock(app_sync_lock);
  int ret =
    oc_obt_discover_all_resources(&device->uuid, resource_discovery, NULL);
  if (ret >= 0) {
    OC_PRINTF("[C]\nSuccessfully issued resource discovery request\n");
  } else {
    OC_PRINTF("[C]\nERROR issuing resource discovery request\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, OC_ARRAY_SIZE(buffer));

  OC_PRINTF("[C] OBT Started device with ID: %s\n", buffer);
}

char *
py_get_obt_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, OC_ARRAY_SIZE(buffer));

  char *uuid = malloc(sizeof(char) * OC_UUID_LEN);
  if (uuid == NULL) {
    OC_PRINTF("ERROR: unable to allocate memory\n");
    return NULL;
  }
  strncpy(uuid, buffer, OC_UUID_LEN);
  return uuid;
}

void
test_print(void)
{
  OC_PRINTF("[C] test_print\n");
}

#ifdef OC_SO

static void
so_otm_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully performed OTM on device with UUID %s\n", di);
    inform_diplomat_python("", "", "", "so_otm:true", di, "");
    // oc_list_add(g_owned_devices, device);
  } else {
    // oc_memb_free(&g_device_handles_s, device);
    OC_PRINTF("\nERROR performing ownership transfer on device %s\n", di);
    inform_diplomat_python("", "", "", "so_otm:false", di, "");
  }
}
static void
streamlined_onboarding_discovery_cb(oc_uuid_t *uuid, oc_endpoint_t *eps,
                                    void *data)
{
  (void)eps;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_UUID_LEN);
  OC_PRINTF("Discovered device with uuid %s\n", di);
  if (data == NULL) {
    return;
  }
  // TODO: This should first prompt for user confirmation before onboarding

  int ret = oc_obt_perform_streamlined_otm(uuid, (const unsigned char *)data,
                                           strlen(data), so_otm_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF(
      "Successfully issued request to perform Streamlined Onboarding OTM\n");
  }
}
static void
perform_streamlined_discovery(oc_so_info_t *so_info)
{
  if (so_info != NULL) {
    char *cred = calloc(OC_SO_MAX_CRED_LEN, 1);
    OC_PRINTF("Onboarding device with UUID %s and cred %s\n", so_info->uuid,
              so_info->cred);
    memcpy(cred, so_info->cred, strlen(so_info->cred));
    OC_PRINTF("After Memcopy\n");

    struct timespec onboarding_wait = { .tv_sec = 20, .tv_nsec = 0 };
    OC_PRINTF("AFTER TIMESPEC\n");
    nanosleep(&onboarding_wait, &onboarding_wait);
    OC_PRINTF("AFTER SLEEP\n");
    //
    oc_obt_discover_unowned_devices(streamlined_onboarding_discovery_cb,
                                    so_info->uuid, cred);
    // so_info = so_info->next;
  }
  oc_so_info_free(so_info);
}
static void
observe_diplomat_cb(oc_client_response_t *data)
{
  OC_PRINTF("Observe Diplomat: CODE %d\n", data->code);
  if (data->code > 4) {
    OC_PRINTF("Observe GET failed with code %d\n", data->code);
    // char* c = (char *) data->code;
    char code[40];
    snprintf(code, OC_ARRAY_SIZE(code), "observe_fail:%d", data->code);
    inform_diplomat_python("", "", "", code, "", "");
    return;
  }
  oc_rep_t *rep = data->payload;
  oc_rep_t *so_info_rep_array = NULL;
  if (rep == NULL) {
    char *error = "observe_fail:nopayload";
    inform_diplomat_python("", "", "", error, "", "");
    return;
  }
  while (rep != NULL) {
    OC_PRINTF("key %s", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_OBJECT_ARRAY:
      if (oc_rep_get_object_array(rep, "soinfo", &so_info_rep_array)) {
        oc_so_info_t *so_info = oc_so_parse_rep_array(so_info_rep_array);
        OC_PRINTF("Onboarding device with UUID %s and cred %s\n", so_info->uuid,
                  so_info->cred);
        char target_uuid[OC_UUID_LEN];
        snprintf(target_uuid, OC_ARRAY_SIZE(target_uuid), "%s", so_info->uuid);
        inform_diplomat_python("", "", "", "", target_uuid, "");
        perform_streamlined_discovery(so_info);
        break;
      }
      break;
    default:
      OC_PRINTF("NOT an OC_REP\n");
      break;
    }
    rep = rep->next;
  }
}

static oc_discovery_flags_t
diplomat_discovery(const char *anchor, const char *uri, oc_string_array_t types,
                   oc_interface_mask_t iface_mask,
                   const oc_endpoint_t *endpoint, oc_resource_properties_t bm,
                   void *user_data)
{
  OC_PRINTF("[C] Diplomat discovery requested\n");
  (void)anchor;
  (void)iface_mask;
  (void)bm;
  (void)user_data;
  size_t uri_len = oc_strnlen(uri, MAX_URI_LENGTH - 1);
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    const char *t = oc_string_array_get_item(types, i);
    if (oc_strnlen(t, STRING_ARRAY_ITEM_MAX_LEN) == 14 &&
        strncmp(t, "oic.r.diplomat", 14) == 0) {
      oc_endpoint_list_copy(&diplomat_ep, endpoint);
      strncpy(diplomat_uri, uri, uri_len);
      diplomat_uri[uri_len] = '\0';

      OC_PRINTF("Resource %s anchor: %s hosted at endpoints:\n", diplomat_uri,
                anchor);

      char di[OC_UUID_LEN];
      strncpy(di, anchor + 6, OC_UUID_LEN);
      oc_uuid_t uuid;
      oc_str_to_uuid(di, &uuid);

      bool owned = oc_obt_is_owned_device(&uuid);
      char *state = "";
      if (owned) {
        state = "owned";
      } else {
        state = "unowned";
      }

      inform_diplomat_python(anchor, diplomat_uri, state, NULL, NULL, NULL);

      const oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        ep = ep->next;
      }
      oc_do_observe(diplomat_uri, diplomat_ep, NULL, &observe_diplomat_cb,
                    HIGH_QOS, NULL);
      OC_PRINTF("[C] Sent OBSERVE request\n");
      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

void
discover_diplomat_for_observe(void)
{
  otb_mutex_lock(app_sync_lock);
  if (!oc_do_ip_discovery("oic.r.diplomat", &diplomat_discovery, NULL)) {
    OC_PRINTF("Failed to discover diplomat Devices\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

void
py_diplomat_set_observe(const char *state)
{
  OC_PRINTF("[C] %s", state);
}

void
py_diplomat_stop_observe(const char *uuid)
{
  (void)uuid;
  OC_PRINTF("Stopping OBSERVE\n");
  // oc_stop_observe(a_light, light_server);
}

void
py_discover_diplomat_for_observe(void)
{
  otb_mutex_lock(app_sync_lock);
  oc_do_ip_discovery("oic.r.diplomat", &diplomat_discovery, NULL);
  otb_mutex_unlock(app_sync_lock);
}
#endif /* OC_SO */

#ifdef OC_CLIENT

static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;

static bool state;
static int power;
static oc_string_t name;
static bool discovered;

static void
post_light_response_cb(oc_client_response_t *data)
{
  if (data->code > OC_STATUS_CHANGED) {
    OC_PRINTF("ERROR: POST returned unexpected response code %d\n", data->code);
  }
}
static void
get_light_cb(oc_client_response_t *data)
{
  OC_PRINTF("GET_light:\n");
  const oc_rep_t *rep = data->payload;

  if (data->code > 4) {
    OC_PRINTF("GET failed with code %d\n", data->code);
    char code[40];
    snprintf(code, OC_ARRAY_SIZE(code), "observe_fail:%d", data->code);
    return;
  }
  while (rep != NULL) {
    OC_PRINTF("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_PRINTF("%d\n", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      OC_PRINTF("%d \n", (int)rep->value.integer);
      power = (int)rep->value.integer;
      break;
    case OC_REP_STRING:
      OC_PRINTF("%s\n", oc_string(rep->value.string));
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      break;
    }
    rep = rep->next;
  }
}

static oc_discovery_flags_t
discovery_cb(const char *anchor, const char *uri, oc_string_array_t types,
             oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
             oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)iface_mask;
  (void)bm;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    const char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, "core.light", 10) == 0) {
      oc_endpoint_list_copy(&light_server, endpoint);
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      OC_PRINTF("Resource %s hosted at endpoints:\n", a_light);
      discovered = true;
      const oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        ep = ep->next;
      }

      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static oc_discovery_flags_t
doxm_discovery_cb(const char *anchor, const char *uri, oc_string_array_t types,
                  oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
                  oc_resource_properties_t bm, void *user_data)
{

  (void)anchor;
  (void)iface_mask;
  (void)bm;
  (void)user_data;
  (void)types;
  (void)endpoint;
  (void)uri;
  OC_PRINTF("DOXM CB\n");
  const oc_endpoint_t *ep = endpoint;
  while (ep != NULL) {
    OC_PRINTipaddr(*ep);
    OC_PRINTF("\n");
    ep = ep->next;
  }

#if 0
  if (oc_rep_get_int_array(data->payload, "oxms", &oxms, &oxms_len)) {
    size_t i;
    for (i = 0; i < oxms_len; i++) {
     OC_PRINTF("[C] %d \n",oxms[i]);
    }
  }
#endif

  return OC_STOP_DISCOVERY;
}

void
discover_doxm(void)
{
  otb_mutex_lock(app_sync_lock);
  if (!oc_do_ip_discovery("oic.r.doxm", &doxm_discovery_cb, NULL)) {
    OC_PRINTF("Failed to discover DOXM\n");
  }
  otb_mutex_unlock(app_sync_lock);

#if 0
  OC_PRINTF("[C] Discover Doxm %s\n",uuid);
  if (oc_do_get("/oic/sec/doxm", ep, NULL, &doxm_discovery_cb, HIGH_QOS, NULL)) { 
    OC_PRINTF("[C] doxm return\n");
  }
#endif
}

void
discover_resource(const char *rt, const char *uuid)
{
  OC_PRINTF("[C] rt:%s uuid:%s\n", rt, uuid);
  oc_do_ip_discovery(rt, &discovery_cb, NULL);
  oc_do_get(a_light, light_server, NULL, &get_light_cb, LOW_QOS, NULL);
  OC_PRINTF("[C] rt:%s uuid:%s\n", rt, uuid);
}

void
change_light(int value)
{
  OC_PRINTF("[C] POST_light: %d\n", value);
  bool light_cmd;
  if (value == 1) {
    light_cmd = true;
  } else {
    light_cmd = false;
  }

#if 0
  OC_PRINTF("SETTING LIGHT\n");
  otb_mutex_lock(app_sync_lock);
  if (!oc_do_ip_discovery("core.light", &discovery_cb, NULL)) {
    OC_PRINTF("Failed to discover Devices\n");
  } else {
    OC_PRINTF("Discovered device\n");
  }
  if(!discovered){
    otb_mutex_unlock(app_sync_lock);
    return;
  }
  otb_mutex_unlock(app_sync_lock);
#endif

  if (oc_init_post(a_light, light_server, NULL, &post_light_response_cb,
                   LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, light_cmd);
    oc_rep_end_root_object();
    if (oc_do_post())
      OC_PRINTF("Sent POST request\n");
    else
      OC_PRINTF("Could not send POST request\n");
  } else {
    OC_PRINTF("Could not init POST request\n");
  }
}
#endif /*OC Client*/

static bool
init(void)
{
#if defined(_WIN32)
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  InitializeCriticalSection(&app_sync_lock);
  signal(SIGINT, python_exit);
#elif defined(__linux__)
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = python_exit;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&app_sync_lock, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  pthread_condattr_destroy(&attr);
#endif
  return true;
}

static void
deinit(void)
{
#ifdef __linux__
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_sync_lock);
#endif /* __linux__ */
}

int
python_main(void)
{
  if (!init()) {
    return -1;
  }

#ifdef OC_SERVER
  OC_PRINTF("[C]OC_SERVER\n");
#endif
#ifdef OC_CLIENT
  OC_PRINTF("[C]OC_CLIENT\n");
#endif

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
#ifdef OC_SERVER
    .register_resources = NULL,
#endif
#ifdef OC_CLIENT
    .requests_entry = issue_requests,
#endif
  };

#ifdef OC_STORAGE
  oc_storage_config("./onboarding_tool_creds");
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
  oc_set_con_res_announced(false);
  oc_set_max_app_data_size(16384);

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }

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

  display_device_uuid();

  while (OC_ATOMIC_LOAD8(quit) != 1) {
#if defined(_WIN32)
    Sleep(5000);
#elif defined(__linux__)
    sleep(5);
#endif
  }

#if defined(_WIN32)
  WaitForSingleObject(event_thread, INFINITE);
#elif defined(__linux__)
  pthread_join(event_thread, NULL);
#endif

  /* Free all device_handle_t objects allocated by this application */
  device_handle_t *device = (device_handle_t *)oc_list_pop(g_owned_devices);
  while (device) {
    oc_memb_free(&g_device_handles_s, device);
    device = (device_handle_t *)oc_list_pop(g_owned_devices);
  }
  device = (device_handle_t *)oc_list_pop(g_unowned_devices);
  while (device) {
    oc_memb_free(&g_device_handles_s, device);
    device = (device_handle_t *)oc_list_pop(g_unowned_devices);
  }

  deinit();
  return 0;
}
