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
} device_handle_t;
/* Pool of device handles */
OC_MEMB(device_handles, device_handle_t, MAX_OWNED_DEVICES);
/* List of known owned devices */
OC_LIST(owned_devices);
/* List of known un-owned devices */
OC_LIST(unowned_devices);

#if defined (_WIN32)
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
  PRINT("[2] Discover owned devices\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[3] Just-Works Ownership Transfer Method\n");
  PRINT("[4] Request Random PIN from device for OTM\n");
  PRINT("[5] Random PIN Ownership Transfer Method\n");
  PRINT("[6] Provision pair-wise credentials\n");
  PRINT("[7] Provision ACE2\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[8] RESET device\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[9] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) != 1) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
    }                                                                          \
  } while (0)

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "OBT", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
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
      }
      else {
          oc_clock_time_t now = oc_clock_time();
          if (now < next_event) {
              SleepConditionVariableCS(&cv, &cs,
                  (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
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
add_device_to_list(oc_uuid_t *uuid, oc_list_t list)
{
  if (is_device_in_list(uuid, list)) {
    return true;
  }

  device_handle_t *device = oc_memb_alloc(&device_handles);
  if (!device) {
    return false;
  }

  memcpy(device->uuid.id, uuid->id, 16);

  oc_list_add(list, device);

  return true;
}
/* End of app utility functions */

/* App invocations of oc_obt APIs */
static void
unowned_device_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  PRINT("\nDiscovered unowned device: %s at:\n", di);
  while (eps != NULL) {
    PRINTipaddr(*eps);
    PRINT("\n");
    eps = eps->next;
  }

  add_device_to_list(uuid, unowned_devices);
}

static void
owned_device_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  PRINT("\nDiscovered owned device: %s at:\n", di);
  while (eps != NULL) {
    PRINTipaddr(*eps);
    PRINT("\n");
    eps = eps->next;
  }

  add_device_to_list(uuid, owned_devices);
}

static void
discover_owned_devices(void)
{
  otb_mutex_lock(app_sync_lock);
  oc_obt_discover_owned_devices(owned_device_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

static void
discover_unowned_devices(void)
{
  otb_mutex_lock(app_sync_lock);
  oc_obt_discover_unowned_devices(unowned_device_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

static void
otm_rdp_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully performed OTM on device %s\n", di);
    add_device_to_list(uuid, owned_devices);
  } else {
    PRINT("\nERROR performing ownership transfer on device %s\n", di);
  }
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
    PRINT("[%d]: %s\n", i, di);
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

  int ret = oc_obt_perform_random_pin_otm(
    &devices[c]->uuid, pin, strlen((const char *)pin), otm_rdp_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform Random PIN OTM\n");
  } else {
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
    PRINT("[%d]: %s\n", i, di);
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

static void
otm_just_works_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully performed OTM on device %s\n", di);
    add_device_to_list(uuid, unowned_devices);
  } else {
    PRINT("\nERROR performing ownership transfer on device %s\n", di);
  }
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
    PRINT("[%d]: %s\n", i, di);
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

  int ret =
    oc_obt_perform_just_works_otm(&devices[c]->uuid, otm_just_works_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform ownership transfer\n");
  } else {
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
    PRINT("[%d]: %s\n", i, di);
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
    PRINT("[%d]: %s\n", i, di);
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
    PRINT("[%d]: %s\n", i, di);
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
  i = 0;
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s\n", i + 2, di);
    i++;
    device = device->next;
  }
  PRINT("\nSelect subject: ");
  SCANF("%d", &sub);

  if (sub >= (i + 2)) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  oc_sec_ace_t *ace = NULL;
  if (sub > 1) {
    ace = oc_obt_new_ace_for_subject(&devices[sub - 2]->uuid);
  } else {
    if (sub == 0) {
      ace = oc_obt_new_ace_for_connection(OC_CONN_ANON_CLEAR);
    } else {
      ace = oc_obt_new_ace_for_connection(OC_CONN_AUTH_CRYPT);
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

    PRINT("Enter number of resource types [0-None]: ");
    SCANF("%d", &c);
    if (c > 0 && c <= MAX_NUM_RT) {
      oc_obt_ace_resource_set_num_rt(res, c);

      char rt[128];
      int j = 0;
      while (j < c) {
        PRINT("Enter resource type [%d]: ", j + 1);
        SCANF("%127s", rt);
        oc_obt_ace_resource_bind_rt(res, rt);
        j++;
      }
    }
    PRINT("Enter number of interfaces [0-None]");
    SCANF("%d", &c);
    if (c > 0 && c <= 7) {
      int j = 0;
      while (j < c) {
        int k;
        PRINT("\n[1]: oic.if.baseline\n[2]: oic.if.ll\n[3]: oic.if.b\n[4]: "
              "oic.if.r\n[5]: oic.if.rw\n[6]: oic.if.a\n[7]: oic.if.s\n");
        PRINT("\nSelect interface [%d]:", j + 1);
        SCANF("%d", &k);
        switch (k) {
        case 1:
          oc_obt_ace_resource_bind_if(res, OC_IF_BASELINE);
          break;
        case 2:
          oc_obt_ace_resource_bind_if(res, OC_IF_LL);
          break;
        case 3:
          oc_obt_ace_resource_bind_if(res, OC_IF_B);
          break;
        case 4:
          oc_obt_ace_resource_bind_if(res, OC_IF_R);
          break;
        case 5:
          oc_obt_ace_resource_bind_if(res, OC_IF_RW);
          break;
        case 6:
          oc_obt_ace_resource_bind_if(res, OC_IF_A);
          break;
        case 7:
          oc_obt_ace_resource_bind_if(res, OC_IF_S);
          break;
        default:
          break;
        }
        j++;
      }
    } else if (c < 0 || c > 7) {
      PRINT("\nWARNING: Invalid number of interfaces.. skipping interface "
            "selection\n");
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

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

#if defined(_WIN32)
  event_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ocf_event_thread, NULL, 0, NULL);
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
      discover_unowned_devices();
      break;
    case 2:
      discover_owned_devices();
      break;
    case 3:
      otm_just_works();
      break;
    case 4:
      request_random_pin();
      break;
    case 5:
      otm_rdp();
      break;
    case 6:
      provision_credentials();
      break;
    case 7:
      provision_ace2();
      break;
    case 8:
      reset_device();
      break;
    case 9:
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
