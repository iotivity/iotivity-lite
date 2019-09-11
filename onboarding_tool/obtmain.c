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
#include "oc_obt.h"
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

#define MAX_NUM_DEVICES (50)
#define MAX_NUM_RESOURCES (100)
#define MAX_NUM_RT (50)

/* Structure in app to track currently discovered owned/unowned devices */
typedef struct device_handle_t
{
  struct device_handle_t *next;
  oc_uuid_t uuid;
  char device_name[64];
} device_handle_t;
/* Pool of device handles */
OC_MEMB(device_handles, device_handle_t, MAX_OWNED_DEVICES);
/* List of known owned devices */
OC_LIST(owned_devices);
/* List of known un-owned devices */
OC_LIST(unowned_devices);

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
#define otb_mutex_lock(m) pthread_mutex_lock(&m)
#define otb_mutex_unlock(m) pthread_mutex_unlock(&m)

static struct timespec ts;
#endif
static int quit;

static void
display_menu(void)
{
  PRINT("\n\n################################################\nOCF 2.0 "
        "Onboarding Tool\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Discover un-owned devices\n");
  PRINT("[2] Discover un-owned devices in the realm-local IPv6 scope\n");
  PRINT("[3] Discover un-owned devices in the site-local IPv6 scope\n");
  PRINT("[4] Discover owned devices\n");
  PRINT("[5] Discover owned devices in the realm-local IPv6 scope\n");
  PRINT("[6] Discover owned devices in the site-local IPv6 scope\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[7] Just-Works Ownership Transfer Method\n");
  PRINT("[8] Request Random PIN from device for OTM\n");
  PRINT("[9] Random PIN Ownership Transfer Method\n");
#ifdef OC_PKI
  PRINT("[10] Manufacturer Certificate based Ownership Transfer Method\n");
#endif /* OC_PKI */
  PRINT("-----------------------------------------------\n");
  PRINT("[11] Provision pair-wise credentials\n");
  PRINT("[12] Provision ACE2\n");
  PRINT("[13] Provision auth-crypt RW access to NCRs\n");
#ifdef OC_PKI
  PRINT("[14] Provision role RW access to NCRs\n");
  PRINT("[15] Provision identity certificate\n");
  PRINT("[16] Provision role certificate\n");
#endif /* OC_PKI */
  PRINT("-----------------------------------------------\n");
  PRINT("[97] RESET device\n");
  PRINT("[98] RESET OBT\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[99] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
    }                                                                          \
  } while (0)

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.wk.d", "OBT", "ocf.2.0.2",
                       "ocf.res.1.3.0", NULL, NULL);
  return ret;
}

static void
issue_requests(void)
{
  oc_obt_init();
}

static void
signal_event_loop(void)
{
#if defined(_WIN32)
  WakeConditionVariable(&cv);
#elif defined(__linux__)
  otb_mutex_lock(mutex);
  pthread_cond_signal(&cv);
  otb_mutex_unlock(mutex);
#endif
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = 1;
  signal_event_loop();
}

#if defined(_WIN32)
DWORD WINAPI
ocf_event_thread(LPVOID lpParam)
{
  oc_clock_time_t next_event;
  while (quit != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event = oc_main_poll();
    otb_mutex_unlock(app_sync_lock);

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
  oc_obt_shutdown();
  return TRUE;
}
#elif defined(__linux__)
static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event = oc_main_poll();
    otb_mutex_unlock(app_sync_lock);

    otb_mutex_lock(mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    otb_mutex_unlock(mutex);
  }
  oc_main_shutdown();
  oc_obt_shutdown();
  return NULL;
}
#endif

/* App utility functions */
static bool
remove_device_from_list(oc_uuid_t *uuid, oc_list_t list)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(list);
  while (device != NULL) {
    if (memcmp(device->uuid.id, uuid->id, 16) == 0) {
      oc_list_remove(list, device);
      oc_memb_free(&device_handles, device);
      return true;
    }
    device = device->next;
  }
  return false;
}

static bool
is_device_in_list(oc_uuid_t *uuid, oc_list_t list)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(list);
  while (device != NULL) {
    if (memcmp(device->uuid.id, uuid->id, 16) == 0) {
      return true;
    }
    device = device->next;
  }
  return false;
}

static bool
add_device_to_list(oc_uuid_t *uuid, const char *device_name, oc_list_t list)
{
  if (is_device_in_list(uuid, list)) {
    return true;
  }

  device_handle_t *device = oc_memb_alloc(&device_handles);
  if (!device) {
    return false;
  }

  memcpy(device->uuid.id, uuid->id, 16);
  if (device_name) {
    strncpy(device->device_name, device_name, 63);
    device->device_name[64 - 1] = '\0';
  } else {
    device->device_name[0] = '\0';
  }
  oc_list_add(list, device);
  return true;
}

void
empty_device_list(oc_list_t list)
{
  device_handle_t *device = (device_handle_t *)oc_list_pop(list);
  while (device != NULL) {
    oc_memb_free(&device_handles, device);
    device = (device_handle_t *)oc_list_pop(list);
  }
}
/* End of app utility functions */

/* App invocations of oc_obt APIs */
static void
get_device(oc_client_response_t *data)
{
  oc_rep_t *rep = data->payload;
  char *di = NULL, *n = NULL;
  size_t di_len = 0, n_len = 0;

  if (oc_rep_get_string(rep, "di", &di, &di_len)) {
    oc_uuid_t uuid;
    oc_str_to_uuid(di, &uuid);
    if (!oc_rep_get_string(rep, "n", &n, &n_len)) {
      n = NULL;
      n_len = 0;
    }

    add_device_to_list(&uuid, n, data->user_data);
  }
}

static void
unowned_device_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);
  oc_endpoint_t *ep = eps;

  PRINT("\nDiscovered unowned device: %s at:\n", di);
  while (eps != NULL) {
    PRINTipaddr(*eps);
    PRINT("\n");
    eps = eps->next;
  }

  oc_do_get("/oic/d", ep, NULL, &get_device, LOW_QOS, unowned_devices);
}

static void
owned_device_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);
  oc_endpoint_t *ep = eps;

  PRINT("\nDiscovered owned device: %s at:\n", di);
  while (eps != NULL) {
    PRINTipaddr(*eps);
    PRINT("\n");
    eps = eps->next;
  }

  oc_do_get("/oic/d", ep, NULL, &get_device, LOW_QOS, owned_devices);
}

static void
discover_owned_devices(uint8_t scope)
{
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

static void
discover_unowned_devices(uint8_t scope)
{
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
otm_rdp_cb(oc_uuid_t *uuid, int status, void *data)
{
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully performed OTM on device %s\n", di);
    add_device_to_list(uuid, (const char *)data, owned_devices);
  } else {
    PRINT("\nERROR performing ownership transfer on device %s\n", di);
  }
  free(data);
}

static void
otm_rdp(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    PRINT("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0, c;

  PRINT("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }
  PRINT("\n\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  unsigned char pin[24];
  PRINT("\nEnter Random PIN: ");
  SCANF("%10s", pin);

  otb_mutex_lock(app_sync_lock);
  char *d_name =
    (char *)malloc(sizeof(char) * (strlen(devices[c]->device_name) + 1));
  if (d_name) {
    strcpy(d_name, devices[c]->device_name);
  }
  int ret = oc_obt_perform_random_pin_otm(
    &devices[c]->uuid, pin, strlen((const char *)pin), otm_rdp_cb, d_name);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform Random PIN OTM\n");
  } else {
    free(d_name);
    PRINT("\nERROR issuing request to perform Random PIN OTM\n");
  }
  /* Having issued an OTM request, remove this item from the unowned device list
   */
  remove_device_from_list(&devices[c]->uuid, unowned_devices);

  otb_mutex_unlock(app_sync_lock);
}

static void
random_pin_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully requested device %s to generate a Random PIN\n", di);
  } else {
    PRINT("\nERROR requesting device %s to generate a Random PIN\n", di);
  }
}

static void
request_random_pin(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    PRINT("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0, c;

  PRINT("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }
  PRINT("\n\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);

  int ret = oc_obt_request_random_pin(&devices[c]->uuid, random_pin_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to generate a random PIN\n");
  } else {
    PRINT("\nERROR issuing request to generate random PIN\n");
  }

  otb_mutex_unlock(app_sync_lock);
}

#ifdef OC_PKI
static void
otm_cert_cb(oc_uuid_t *uuid, int status, void *data)
{
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully performed OTM on device %s\n", di);
    add_device_to_list(uuid, data, owned_devices);
  } else {
    PRINT("\nERROR performing ownership transfer on device %s\n", di);
  }
  free(data);
}

static void
otm_cert(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    PRINT("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0, c;

  PRINT("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }
  PRINT("\n\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  char *d_name =
    (char *)malloc(sizeof(char) * (strlen(devices[c]->device_name) + 1));
  if (d_name) {
    strcpy(d_name, devices[c]->device_name);
  }

  int ret = oc_obt_perform_cert_otm(&devices[c]->uuid, otm_cert_cb, d_name);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform ownership transfer\n");
  } else {
    PRINT("\nERROR issuing request to perform ownership transfer\n");
    free(d_name);
  }

  /* Having issued an OTM request, remove this item from the unowned device list
   */
  remove_device_from_list(&devices[c]->uuid, unowned_devices);

  otb_mutex_unlock(app_sync_lock);
}
#endif /* OC_PKI */

static void
otm_just_works_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully performed OTM on device with UUID %s\n", di);
    add_device_to_list(uuid, (const char *)data, owned_devices);
  } else {
    PRINT("\nERROR performing ownership transfer on device %s\n", di);
  }
  free(data);
}

static void
otm_just_works(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    PRINT("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0, c;

  PRINT("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }
  PRINT("\n\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);

  char *d_name =
    (char *)malloc(sizeof(char) * (strlen(devices[c]->device_name) + 1));
  if (d_name) {
    strcpy(d_name, devices[c]->device_name);
  }
  int ret =
    oc_obt_perform_just_works_otm(&devices[c]->uuid, otm_just_works_cb, d_name);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform ownership transfer\n");
  } else {
    free(d_name);
    PRINT("\nERROR issuing request to perform ownership transfer\n");
  }

  /* Having issued an OTM request, remove this item from the unowned device list
   */
  remove_device_from_list(&devices[c]->uuid, unowned_devices);

  otb_mutex_unlock(app_sync_lock);
}

static void
reset_device_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  remove_device_from_list(uuid, owned_devices);

  if (status >= 0) {
    PRINT("\nSuccessfully performed hard RESET to device %s\n", di);
  } else {
    PRINT("\nERROR performing hard RESET to device %s\n", di);
  }
}

static void
reset_device(void)
{
  if (oc_list_length(owned_devices) == 0) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0, c;

  PRINT("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
  PRINT("\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_device_hard_reset(&devices[c]->uuid, reset_device_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform hard RESET\n");
  } else {
    PRINT("\nERROR issuing request to perform hard RESET\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

#ifdef OC_PKI
static void
provision_id_cert_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    PRINT("\nSuccessfully provisioned identity certificate\n");
  } else {
    PRINT("\nERROR provisioning identity certificate\n");
  }
}

static void
provision_id_cert(void)
{
  if (oc_list_length(owned_devices) == 0) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0, c;

  PRINT("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
  PRINT("\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_identity_certificate(&devices[c]->uuid,
                                                  provision_id_cert_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision identity certificate\n");
  } else {
    PRINT("\nERROR issuing request to provision identity certificate\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
provision_role_cert_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    PRINT("\nSuccessfully provisioned role certificate\n");
  } else {
    PRINT("\nERROR provisioning role certificate\n");
  }
}

static void
provision_role_cert(void)
{
  if (oc_list_length(owned_devices) == 0) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0, c;

  PRINT("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
  PRINT("\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  oc_role_t *roles = NULL;
  do {
    char role[64];
    PRINT("\nEnter role: ");
    SCANF("%63s", role);
    PRINT("\nAuthority? [0-No, 1-Yes]: ");
    SCANF("%d", &i);
    if (i == 1) {
      char authority[64];
      PRINT("\nEnter Authority: ");
      SCANF("%63s", authority);
      roles = oc_obt_add_roleid(roles, role, authority);
    } else {
      roles = oc_obt_add_roleid(roles, role, NULL);
    }
    PRINT("\nMore Roles? [0-No, 1-Yes]: ");
    SCANF("%d", &i);
  } while (i == 1);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_role_certificate(roles, &devices[c]->uuid,
                                              provision_role_cert_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision role certificate\n");
  } else {
    PRINT("\nERROR issuing request to provision role certificate\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
provision_role_wildcard_ace_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully provisioned rold * ACE to device %s\n", di);
  } else {
    remove_device_from_list(uuid, owned_devices);
    PRINT("\nERROR provisioning ACE to device %s\n", di);
  }
}

static void
provision_role_wildcard_ace(void)
{
  if (oc_list_length(owned_devices) == 0) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0, dev;

  PRINT("\nProvision role * ACE\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    PRINT("\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  PRINT("\n\nSelect device for provisioning: ");
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  char role[64], authority[64];
  PRINT("\nEnter role: ");
  SCANF("%63s", role);
  int d;
  PRINT("\nAuthority? [0-No, 1-Yes]: ");
  SCANF("%d", &d);
  if (d == 1) {
    char authority[64];
    PRINT("\nEnter Authority: ");
    SCANF("%63s", authority);
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_role_wildcard_ace(
    &devices[dev]->uuid, role, (d == 1) ? authority : NULL,
    provision_role_wildcard_ace_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision role * ACE\n");
  } else {
    PRINT("\nERROR issuing request to provision role * ACE\n");
  }
}
#endif /* OC_PKI */

static void
provision_credentials_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    PRINT("\nSuccessfully provisioned pair-wise credentials\n");
  } else {
    PRINT("\nERROR provisioning pair-wise credentials\n");
  }
}

static void
provision_credentials(void)
{
  if (oc_list_length(owned_devices) == 0) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0, c1, c2;

  PRINT("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
  PRINT("\nSelect device 1: ");
  SCANF("%d", &c1);
  if (c1 < 0 || c1 >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }
  PRINT("Select device 2:");
  SCANF("%d", &c2);
  if (c2 < 0 || c2 >= i || c2 == c1) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_pairwise_credentials(
    &devices[c1]->uuid, &devices[c2]->uuid, provision_credentials_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision credentials\n");
  } else {
    PRINT("\nERROR issuing request to provision credentials\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
provision_authcrypt_wildcard_ace_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully provisioned auth-crypt * ACE to device %s\n", di);
  } else {
    remove_device_from_list(uuid, owned_devices);
    PRINT("\nERROR provisioning ACE to device %s\n", di);
  }
}

static void
provision_authcrypt_wildcard_ace(void)
{
  if (oc_list_length(owned_devices) == 0) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0, dev;

  PRINT("\nProvision auth-crypt * ACE\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    PRINT("\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  PRINT("\n\nSelect device for provisioning: ");
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_auth_wildcard_ace(
    &devices[dev]->uuid, provision_authcrypt_wildcard_ace_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision auth-crypt * ACE\n");
  } else {
    PRINT("\nERROR issuing request to provision auth-crypt * ACE\n");
  }
}

static void
provision_ace2_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully provisioned ACE to device %s\n", di);
  } else {
    remove_device_from_list(uuid, owned_devices);
    PRINT("\nERROR provisioning ACE to device %s\n", di);
  }
}

static void
provision_ace2(void)
{
  if (oc_list_length(owned_devices) == 0) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  const char *conn_types[2] = { "anon-clear", "auth-crypt" };
  int num_resources = 0;

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0, dev, sub;

  PRINT("\nProvision ACL2\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    PRINT("\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  PRINT("\n\nSelect device for provisioning: ");
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  PRINT("\nSubjects:");
  device = (device_handle_t *)oc_list_head(owned_devices);
  PRINT("\n[0]: %s\n", conn_types[0]);
  PRINT("[1]: %s\n", conn_types[1]);
  PRINT("[2]: Role\n");
  i = 0;
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i + 3, di, device->device_name);
    i++;
    device = device->next;
  }
  PRINT("\nSelect subject: ");
  SCANF("%d", &sub);

  if (sub >= (i + 3)) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  oc_sec_ace_t *ace = NULL;
  if (sub > 2) {
    ace = oc_obt_new_ace_for_subject(&devices[sub - 3]->uuid);
  } else {
    if (sub == 0) {
      ace = oc_obt_new_ace_for_connection(OC_CONN_ANON_CLEAR);
    } else if (sub == 1) {
      ace = oc_obt_new_ace_for_connection(OC_CONN_AUTH_CRYPT);
    } else {
      char role[64];
      PRINT("\nEnter role: ");
      SCANF("%63s", role);
      int d;
      PRINT("\nAuthority? [0-No, 1-Yes]: ");
      SCANF("%d", &d);
      if (d == 1) {
        char authority[64];
        PRINT("\nEnter Authority: ");
        SCANF("%63s", authority);
        ace = oc_obt_new_ace_for_role(role, authority);
      } else {
        ace = oc_obt_new_ace_for_role(role, NULL);
      }
    }
  }

  if (!ace) {
    PRINT("\nERROR: Could not create ACE\n");
    return;
  }

  while (num_resources <= 0 || num_resources > MAX_NUM_RESOURCES) {
    if (num_resources != 0) {
      PRINT("\n\nERROR: Enter valid number\n\n");
    }
    PRINT("\nEnter number of resources in this ACE: ");
    SCANF("%d", &num_resources);
  }

  int c;
  PRINT("\nResource properties\n");
  i = 0;
  while (i < num_resources) {
    oc_ace_res_t *res = oc_obt_ace_new_resource(ace);

    if (!res) {
      PRINT("\nERROR: Could not allocate new resource for ACE\n");
      oc_obt_free_ace(ace);
      return;
    }

    PRINT("Have resource href? [0-No, 1-Yes]: ");
    SCANF("%d", &c);
    if (c == 1) {
      PRINT("Enter resource href (eg. /a/light): ");
      char href[64];
      SCANF("%63s", href);

      oc_obt_ace_resource_set_href(res, href);
      oc_obt_ace_resource_set_wc(res, OC_ACE_NO_WC);
    } else {
      PRINT("\nSet wildcard resource? [0-No, 1-Yes]: ");
      SCANF("%d", &c);
      if (c == 1) {
        PRINT("[1]: All NCRs '*' \n[2]: All NCRs with >=1 secured endpoint "
              "'+'\n[3]: "
              "All NCRs with >=1 unsecured endpoint '-'\n\nSelect wildcard "
              "resource: ");
        SCANF("%d", &c);
        switch (c) {
        case 1:
          oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL);
          break;
        case 2:
          oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL_SECURED);
          break;
        case 3:
          oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL_PUBLIC);
          break;
        default:
          break;
        }
      }
    }

    i++;
  }

  PRINT("\nSet ACE2 permissions\n");
  PRINT("CREATE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_CREATE);
  }
  PRINT("RETRIEVE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE);
  }
  PRINT("UPDATE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_UPDATE);
  }
  PRINT("DELETE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_DELETE);
  }
  PRINT("NOTIFY [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_NOTIFY);
  }

  otb_mutex_lock(app_sync_lock);
  int ret =
    oc_obt_provision_ace(&devices[dev]->uuid, ace, provision_ace2_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision ACE\n");
  } else {
    PRINT("\nERROR issuing request to provision ACE\n");
  }
}

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    PRINT("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    PRINT("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len > (long)*buffer_len) {
    PRINT("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  if (fread(buffer, 1, pem_len, fp) < (size_t)pem_len) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  fclose(fp);
  *buffer_len = (size_t)pem_len;
  return 0;
}
#endif /* OC_SECURITY && OC_PKI */

void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
  oc_obt_shutdown();
  empty_device_list(owned_devices);
  empty_device_list(unowned_devices);
  oc_obt_init();
#if defined(OC_SECURITY) && defined(OC_PKI)
  char cert[8192];
  size_t cert_len = 8192;

  cert_len = 8192;
  if (read_pem("pki_certs/rootca1.pem", cert, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    PRINT("ERROR installing root cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem("pki_certs/rootca2.pem", cert, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    PRINT("ERROR installing root cert\n");
    return;
  }
#endif /* OC_SECURITY && OC_PKI */
}

int
main(void)
{
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

  int init;

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .requests_entry = issue_requests };

  oc_storage_config("./onboarding_tool_creds");
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
  oc_set_con_res_announced(false);
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
      discover_unowned_devices(0x02);
      break;
    case 2:
      discover_unowned_devices(0x03);
      break;
    case 3:
      discover_unowned_devices(0x05);
      break;
    case 4:
      discover_owned_devices(0x02);
      break;
    case 5:
      discover_owned_devices(0x03);
      break;
    case 6:
      discover_owned_devices(0x05);
      break;
    case 7:
      otm_just_works();
      break;
    case 8:
      request_random_pin();
      break;
    case 9:
      otm_rdp();
      break;
#ifdef OC_PKI
    case 10:
      otm_cert();
      break;
#endif /* OC_PKI */
    case 11:
      provision_credentials();
      break;
    case 12:
      provision_ace2();
      break;
    case 13:
      provision_authcrypt_wildcard_ace();
      break;
#ifdef OC_PKI
    case 14:
      provision_role_wildcard_ace();
      break;
    case 15:
      provision_id_cert();
      break;
    case 16:
      provision_role_cert();
      break;
#endif /* OC_PKI */
    case 97:
      reset_device();
      break;
    case 98:
      otb_mutex_lock(app_sync_lock);
      oc_reset();
      otb_mutex_unlock(app_sync_lock);
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

  /* Free all device_handle_t objects allocated by this application */
  device_handle_t *device = (device_handle_t *)oc_list_pop(owned_devices);
  while (device) {
    oc_memb_free(&device_handles, device);
    device = (device_handle_t *)oc_list_pop(owned_devices);
  }
  device = (device_handle_t *)oc_list_pop(unowned_devices);
  while (device) {
    oc_memb_free(&device_handles, device);
    device = (device_handle_t *)oc_list_pop(unowned_devices);
  }

  return 0;
}
