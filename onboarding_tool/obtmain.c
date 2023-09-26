/****************************************************************************
 *
 * Copyright (c) 2017-2019 Intel Corporation
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

#include "oc_api.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "oc_log.h"
#include "oc_obt.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"
#include "util/oc_macros_internal.h"

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

/* Structure in app to track currently discovered owned/unowned devices */
typedef struct device_handle_t
{
  struct device_handle_t *next;
  oc_uuid_t uuid;
  char device_name[64];
} device_handle_t;
/* Pool of device handles */
OC_MEMB(device_handles, device_handle_t, MAX_NUM_DEVICES);
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
#define otb_mutex_lock(m) pthread_mutex_lock(&(m))
#define otb_mutex_unlock(m) pthread_mutex_unlock(&(m))

#endif

static OC_ATOMIC_INT8_T quit = 0;

static void
display_menu(void)
{
  OC_PRINTF(
    "\n\n################################################\nOCF 2.x "
    "Onboarding Tool\n################################################\n");
  OC_PRINTF("[0] Display this menu\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[1] Discover un-owned devices\n");
  OC_PRINTF("[2] Discover un-owned devices in the realm-local IPv6 scope\n");
  OC_PRINTF("[3] Discover un-owned devices in the site-local IPv6 scope\n");
  OC_PRINTF("[4] Discover owned devices\n");
  OC_PRINTF("[5] Discover owned devices in the realm-local IPv6 scope\n");
  OC_PRINTF("[6] Discover owned devices in the site-local IPv6 scope\n");
  OC_PRINTF("[7] Discover all resources on the device\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[8] Just-Works Ownership Transfer Method\n");
  OC_PRINTF("[9] Request Random PIN from device for OTM\n");
  OC_PRINTF("[10] Random PIN Ownership Transfer Method\n");
#ifdef OC_PKI
  OC_PRINTF("[11] Manufacturer Certificate based Ownership Transfer Method\n");
#endif /* OC_PKI */
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[12] Provision pairwise credentials\n");
  OC_PRINTF("[13] Provision ACE2\n");
  OC_PRINTF("[14] Provision auth-crypt RW access to NCRs\n");
  OC_PRINTF("[15] RETRIEVE /oic/sec/cred\n");
  OC_PRINTF("[16] DELETE cred by credid\n");
  OC_PRINTF("[17] RETRIEVE /oic/sec/acl2\n");
  OC_PRINTF("[18] DELETE ace by aceid\n");
  OC_PRINTF("[19] RETRIEVE own creds\n");
  OC_PRINTF("[20] DELETE own cred by credid\n");
#ifdef OC_PKI
  OC_PRINTF("[21] Provision role RW access to NCRs\n");
  OC_PRINTF("[22] Provision identity certificate\n");
  OC_PRINTF("[23] Provision role certificate\n");
#endif /* OC_PKI */
#ifdef OC_OSCORE
  OC_PRINTF("[24] Provision pairwise OSCORE contexts\n");
  OC_PRINTF("[25] Provision Client Group OSCORE context\n");
  OC_PRINTF("[26] Provision Server Group OSCORE context\n");
#endif /* OC_OSCORE */
  OC_PRINTF("[27] Set security domain info\n");
#ifdef OC_CLOUD
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[30] Provision cloud config info\n");
  OC_PRINTF("[31] RETRIEVE cloud config info\n");
  OC_PRINTF("[32] Provistion cloud trust anchor\n");
#endif /* OC_CLOUD */
  OC_PRINTF("-----------------------------------------------\n");
#ifdef OC_PKI
  OC_PRINTF("[96] Install new manufacturer trust anchor\n");
#endif /* OC_PKI */
  OC_PRINTF("[97] RESET device\n");
  OC_PRINTF("[98] RESET OBT\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[99] Exit\n");
  OC_PRINTF("################################################\n");
  OC_PRINTF("\nSelect option: \n");
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      OC_PRINTF("ERROR Invalid input\n");                                      \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.2.5",
                       "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
  oc_device_bind_resource_type(0, "oic.d.ams");
  oc_device_bind_resource_type(0, "oic.d.cms");
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
  pthread_cond_signal(&cv);
#endif
}

static void
handle_signal(int signal)
{
  (void)signal;
  OC_ATOMIC_STORE8(quit, 1);
  signal_event_loop();
}

#if defined(_WIN32)
DWORD WINAPI
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

static bool
add_device_to_list(const oc_uuid_t *uuid, const char *device_name,
                   oc_list_t list)
{
  device_handle_t *device = is_device_in_list(uuid, list);

  if (!device) {
    device = oc_memb_alloc(&device_handles);
    if (!device) {
      return false;
    }
    memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
    oc_list_add(list, device);
  }

  size_t len = 0;
  if (device_name != NULL) {
    len = strlen(device_name);
    len = len > OC_ARRAY_SIZE(device->device_name) - 1
            ? OC_ARRAY_SIZE(device->device_name) - 1
            : len;
    memcpy(device->device_name, device_name, len);
  }
  device->device_name[len] = '\0';
  return true;
}

static void
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
  const oc_rep_t *rep = data->payload;
  char *di = NULL;
  size_t di_len = 0;
  if (oc_rep_get_string(rep, "di", &di, &di_len)) {
    oc_uuid_t uuid;
    oc_str_to_uuid(di, &uuid);

    char *n = NULL;
    size_t n_len = 0;
    if (!oc_rep_get_string(rep, "n", &n, &n_len)) {
      n = NULL;
      n_len = 0;
    }

    add_device_to_list(&uuid, n, data->user_data);
  }
}

static void
unowned_device_cb(const oc_uuid_t *uuid, const oc_endpoint_t *eps, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));
  const oc_endpoint_t *ep = eps;

  OC_PRINTF("\nDiscovered unowned device: %s at:\n", di);
  while (eps != NULL) {
    OC_PRINTipaddr(*eps);
    OC_PRINTF("\n");
    eps = eps->next;
  }

  oc_do_get("/oic/d", ep, NULL, &get_device, HIGH_QOS, unowned_devices);
}

static void
owned_device_cb(const oc_uuid_t *uuid, const oc_endpoint_t *eps, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));
  const oc_endpoint_t *ep = eps;

  OC_PRINTF("\nDiscovered owned device: %s at:\n", di);
  while (eps != NULL) {
    OC_PRINTipaddr(*eps);
    OC_PRINTF("\n");
    eps = eps->next;
  }

  oc_do_get("/oic/d", ep, NULL, &get_device, HIGH_QOS, owned_devices);
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
otm_rdp_cb(const oc_uuid_t *uuid, int status, void *data)
{
  device_handle_t *device = (device_handle_t *)data;
  memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully performed OTM on device %s\n", di);
    oc_list_add(owned_devices, device);
  } else {
    OC_PRINTF("\nERROR performing ownership transfer on device %s\n", di);
    oc_memb_free(&device_handles, device);
  }
}

static void
otm_rdp(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    OC_PRINTF("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  OC_PRINTF("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }

  OC_PRINTF("\n\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  unsigned char pin[24];
  OC_PRINTF("\nEnter Random PIN: ");
  SCANF("%10s", pin);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_perform_random_pin_otm(
    &devices[c]->uuid, pin, strlen((const char *)pin), otm_rdp_cb, devices[c]);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to perform Random PIN OTM\n");
    /* Having issued an OTM request, remove this item from the unowned device
     * list
     */
    oc_list_remove(unowned_devices, devices[c]);
  } else {
    OC_PRINTF("\nERROR issuing request to perform Random PIN OTM\n");
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
    OC_PRINTF("\nSuccessfully requested device %s to generate a Random PIN\n",
              di);
  } else {
    OC_PRINTF("\nERROR requesting device %s to generate a Random PIN\n", di);
  }
}

static void
request_random_pin(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    OC_PRINTF("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  OC_PRINTF("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }

  OC_PRINTF("\n\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);

  int ret = oc_obt_request_random_pin(&devices[c]->uuid, random_pin_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to generate a random PIN\n");
  } else {
    OC_PRINTF("\nERROR issuing request to generate random PIN\n");
  }

  otb_mutex_unlock(app_sync_lock);
}

#ifdef OC_PKI
static void
otm_cert_cb(const oc_uuid_t *uuid, int status, void *data)
{
  device_handle_t *device = (device_handle_t *)data;
  memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully performed OTM on device %s\n", di);
    oc_list_add(owned_devices, device);
  } else {
    OC_PRINTF("\nERROR performing ownership transfer on device %s\n", di);
    oc_memb_free(&device_handles, device);
  }
}

static void
otm_cert(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    OC_PRINTF("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  OC_PRINTF("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }

  OC_PRINTF("\n\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);

  int ret = oc_obt_perform_cert_otm(&devices[c]->uuid, otm_cert_cb, devices[c]);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to perform ownership transfer\n");
    /* Having issued an OTM request, remove this item from the unowned device
     * list
     */
    oc_list_remove(unowned_devices, devices[c]);
  } else {
    OC_PRINTF("\nERROR issuing request to perform ownership transfer\n");
  }

  otb_mutex_unlock(app_sync_lock);
}
#endif /* OC_PKI */

static void
otm_just_works_cb(const oc_uuid_t *uuid, int status, void *data)
{
  device_handle_t *device = (device_handle_t *)data;
  memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully performed OTM on device with UUID %s\n", di);
    oc_list_add(owned_devices, device);
  } else {
    oc_memb_free(&device_handles, device);
    OC_PRINTF("\nERROR performing ownership transfer on device %s\n", di);
  }
}

static void
otm_just_works(void)
{
  if (oc_list_length(unowned_devices) == 0) {
    OC_PRINTF("\nPlease Re-discover Unowned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(unowned_devices);
  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  OC_PRINTF("\nUnowned Devices:\n");
  while (device != NULL) {
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    devices[i] = device;
    i++;
    device = device->next;
  }

  OC_PRINTF("\n\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);

  int ret = oc_obt_perform_just_works_otm(&devices[c]->uuid, otm_just_works_cb,
                                          devices[c]);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to perform ownership transfer\n");
    /* Having issued an OTM request, remove this item from the unowned device
     * list
     */
    oc_list_remove(unowned_devices, devices[c]);
  } else {
    OC_PRINTF("\nERROR issuing request to perform ownership transfer\n");
  }

  otb_mutex_unlock(app_sync_lock);
}

static void
retrieve_acl2_rsrc_cb(oc_sec_acl_t *acl, void *data)
{
  (void)data;
  if (acl) {
    OC_PRINTF("\n/oic/sec/acl2:\n");
    oc_sec_ace_t *ac = oc_list_head(acl->subjects);
    OC_PRINTF("\n################################################\n");
    while (ac) {
      OC_PRINTF("aceid: %d\n", ac->aceid);
      if (ac->subject_type == OC_SUBJECT_UUID) {
        char uuid[37];
        oc_uuid_to_str(&ac->subject.uuid, uuid, 37);
        OC_PRINTF("subject: %s\n", uuid);
      } else if (ac->subject_type == OC_SUBJECT_ROLE) {
        OC_PRINTF("Roleid_role: %s\n", oc_string(ac->subject.role.role));
        if (oc_string_len(ac->subject.role.authority) > 0) {
          OC_PRINTF("Roleid_authority: %s\n",
                    oc_string(ac->subject.role.authority));
        }
      } else if (ac->subject_type == OC_SUBJECT_CONN) {
        OC_PRINTF("connection type: ");
        if (ac->subject.conn == OC_CONN_AUTH_CRYPT) {
          OC_PRINTF("auth-crypt\n");
        } else {
          OC_PRINTF("anon-clear\n");
        }
      }
      OC_PRINTF("Permissions: ");
      if (ac->permission & OC_PERM_CREATE) {
        OC_PRINTF(" C ");
      }
      if (ac->permission & OC_PERM_RETRIEVE) {
        OC_PRINTF(" R ");
      }
      if (ac->permission & OC_PERM_UPDATE) {
        OC_PRINTF(" U ");
      }
      if (ac->permission & OC_PERM_DELETE) {
        OC_PRINTF(" D ");
      }
      if (ac->permission & OC_PERM_NOTIFY) {
        OC_PRINTF(" N ");
      }
      OC_PRINTF("\n");
      OC_PRINTF("Resources: ");
      oc_ace_res_t *res = oc_list_head(ac->resources);
      while (res) {
        if (oc_string_len(res->href) > 0) {
          OC_PRINTF(" %s ", oc_string(res->href));
        } else if (res->wildcard != 0) {
          switch (res->wildcard) {
          case OC_ACE_WC_ALL:
            OC_PRINTF(" * ");
            break;
          case OC_ACE_WC_ALL_SECURED:
            OC_PRINTF(" + ");
            break;
          case OC_ACE_WC_ALL_PUBLIC:
            OC_PRINTF(" - ");
            break;
          default:
            break;
          }
        }
        res = res->next;
      }
      ac = ac->next;
      OC_PRINTF("\n-----\n");
    }
    OC_PRINTF("\n################################################\n");

    /* Freeing the ACL structure */
    oc_obt_free_acl(acl);
  } else {
    OC_PRINTF("\nERROR RETRIEving /oic/sec/acl2\n");
  }
}

static void
retrieve_acl2_rsrc(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_retrieve_acl(&devices[c]->uuid, retrieve_acl2_rsrc_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to RETRIEVE /oic/sec/acl2\n");
  } else {
    OC_PRINTF("\nERROR issuing request to RETRIEVE /oic/sec/acl2\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
display_cred_rsrc(oc_sec_creds_t *creds)
{
  if (creds) {
    OC_PRINTF("\n/oic/sec/cred:\n");
    oc_sec_cred_t *cr = oc_list_head(creds->creds);
    OC_PRINTF("\n################################################\n");
    while (cr) {
      char uuid[37];
      oc_uuid_to_str(&cr->subjectuuid, uuid, 37);
      OC_PRINTF("credid: %d\n", cr->credid);
      OC_PRINTF("subjectuuid: %s\n", uuid);
      OC_PRINTF("credtype: %s\n", oc_cred_credtype_string(cr->credtype));
#ifdef OC_PKI
      OC_PRINTF("credusage: %s\n", oc_cred_read_credusage(cr->credusage));
      if (oc_string_len(cr->publicdata.data) > 0) {
        OC_PRINTF("publicdata_encoding: %s\n",
                  oc_cred_read_encoding(cr->publicdata.encoding));
      }
#endif /* OC_PKI */
      OC_PRINTF("privatedata_encoding: %s\n",
                oc_cred_read_encoding(cr->privatedata.encoding));
      if (oc_string_len(cr->role.role) > 0) {
        OC_PRINTF("roleid_role: %s\n", oc_string(cr->role.role));
      }
      if (oc_string_len(cr->role.authority) > 0) {
        OC_PRINTF("roleid_authority: %s\n", oc_string(cr->role.authority));
      }
      OC_PRINTF("\n-----\n");
      cr = cr->next;
    }
    OC_PRINTF("\n################################################\n");
  }
}

static void
retrieve_cred_rsrc_cb(oc_sec_creds_t *creds, void *data)
{
  (void)data;
  if (creds) {
    display_cred_rsrc(creds);
    /* Freeing the creds structure */
    oc_obt_free_creds(creds);
  } else {
    OC_PRINTF("\nERROR RETRIEving /oic/sec/cred\n");
  }
}

static void
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

static void
retrieve_cred_rsrc(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret =
    oc_obt_retrieve_creds(&devices[c]->uuid, retrieve_cred_rsrc_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to RETRIEVE /oic/sec/cred\n");
  } else {
    OC_PRINTF("\nERROR issuing request to RETRIEVE /oic/sec/cred\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
delete_ace_by_aceid_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("\nSuccessfully DELETEd ace\n");
  } else {
    OC_PRINTF("\nERROR DELETing ace\n");
  }
}

static void
delete_ace_by_aceid(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  OC_PRINTF("\nEnter aceid: ");
  int aceid;
  SCANF("%d", &aceid);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_delete_ace_by_aceid(&devices[c]->uuid, aceid,
                                       delete_ace_by_aceid_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to DELETE /oic/sec/acl2\n");
  } else {
    OC_PRINTF("\nERROR issuing request to DELETE /oic/sec/acl2\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
delete_cred_by_credid_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("\nSuccessfully DELETEd cred\n");
  } else {
    OC_PRINTF("\nERROR DELETing cred\n");
  }
}

static void
delete_own_cred_by_credid(void)
{
  OC_PRINTF("\nEnter credid: ");
  int credid;
  SCANF("%d", &credid);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_delete_own_cred_by_credid(credid);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully DELETED cred\n");
  } else {
    OC_PRINTF("\nERROR DELETing cred\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
delete_cred_by_credid(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  OC_PRINTF("\nEnter credid: ");
  int credid;
  SCANF("%d", &credid);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_delete_cred_by_credid(&devices[c]->uuid, credid,
                                         delete_cred_by_credid_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to DELETE /oic/sec/cred\n");
  } else {
    OC_PRINTF("\nERROR issuing request to DELETE /oic/sec/cred\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
reset_device_cb(const oc_uuid_t *uuid, int status, void *data)
{
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  oc_memb_free(&device_handles, data);

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully performed hard RESET to device %s\n", di);
  } else {
    OC_PRINTF("\nERROR performing hard RESET to device %s\n", di);
  }
}

static void
reset_device(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret =
    oc_obt_device_hard_reset(&devices[c]->uuid, reset_device_cb, devices[c]);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to perform hard RESET\n");
    oc_list_remove(owned_devices, devices[c]);
  } else {
    OC_PRINTF("\nERROR issuing request to perform hard RESET\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

#ifdef OC_PKI
static void
provision_id_cert_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned identity certificate\n");
  } else {
    OC_PRINTF("\nERROR provisioning identity certificate\n");
  }
}

static void
provision_id_cert(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_identity_certificate(&devices[c]->uuid,
                                                  provision_id_cert_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF(
      "\nSuccessfully issued request to provision identity certificate\n");
  } else {
    OC_PRINTF("\nERROR issuing request to provision identity certificate\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
provision_role_cert_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned role certificate\n");
  } else {
    OC_PRINTF("\nERROR provisioning role certificate\n");
  }
}

static void
provision_role_cert(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  oc_role_t *roles = NULL;
  do {
    char role[64];
    OC_PRINTF("\nEnter role: ");
    SCANF("%63s", role);
    OC_PRINTF("\nAuthority? [0-No, 1-Yes]: ");
    SCANF("%d", &i);
    if (i == 1) {
      char authority[64];
      OC_PRINTF("\nEnter Authority: ");
      SCANF("%63s", authority);
      roles = oc_obt_add_roleid(roles, role, authority);
    } else {
      roles = oc_obt_add_roleid(roles, role, NULL);
    }
    OC_PRINTF("\nMore Roles? [0-No, 1-Yes]: ");
    SCANF("%d", &i);
  } while (i == 1);

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_role_certificate(roles, &devices[c]->uuid,
                                              provision_role_cert_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision role certificate\n");
  } else {
    OC_PRINTF("\nERROR issuing request to provision role certificate\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
provision_role_wildcard_ace_cb(const oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned rold * ACE to device %s\n", di);
  } else {
    OC_PRINTF("\nERROR provisioning ACE to device %s\n", di);
  }
}

static void
provision_role_wildcard_ace(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nProvision role * ACE\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    OC_PRINTF(
      "\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  int dev;
  OC_PRINTF("\n\nSelect device for provisioning: ");
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  char role[64];
  OC_PRINTF("\nEnter role: ");
  SCANF("%63s", role);
  int d;
  OC_PRINTF("\nAuthority? [0-No, 1-Yes]: ");
  SCANF("%d", &d);
  char authority[64];
  if (d == 1) {
    OC_PRINTF("\nEnter Authority: ");
    SCANF("%63s", authority);
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_role_wildcard_ace(
    &devices[dev]->uuid, role, (d == 1) ? authority : NULL,
    provision_role_wildcard_ace_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision role * ACE\n");
  } else {
    OC_PRINTF("\nERROR issuing request to provision role * ACE\n");
  }
}
#endif /* OC_PKI */

#ifdef OC_OSCORE
static void
provision_group_context_cb(const oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned group OSCORE context to device %s\n",
              di);
  } else {
    OC_PRINTF("\nERROR provisioning group OSCORE context to device %s\n", di);
  }
}

static void
provision_server_group_oscore_context(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nProvision server group OSCORE context\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    OC_PRINTF(
      "\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  OC_PRINTF("\n\nSelect Server device for provisioning: ");
  int dev;
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  OC_PRINTF("\n\nSelect Client with secure multicast capability: ");
  int subject;
  SCANF("%d", &subject);
  if (subject < 0 || subject >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_server_group_oscore_context(
    &devices[dev]->uuid, &devices[subject]->uuid, NULL,
    provision_group_context_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision server group OSCORE "
              "context\n");
  } else {
    OC_PRINTF(
      "\nERROR issuing request to provision server group OSCORE context\n");
  }
}

static void
provision_client_group_oscore_context(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nProvision client group OSCORE context\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    OC_PRINTF(
      "\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  OC_PRINTF("\n\nSelect device for provisioning: ");
  int dev;
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_client_group_oscore_context(
    &devices[dev]->uuid, NULL, provision_group_context_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision client group OSCORE "
              "context\n");
  } else {
    OC_PRINTF(
      "\nERROR issuing request to provision client group OSCORE context\n");
  }
}

static void
provision_oscore_contexts_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned pairwise OSCORE contexts\n");
  } else {
    OC_PRINTF("\nERROR provisioning pairwise OSCORE contexts\n");
  }
}

static void
provision_oscore_contexts(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nProvision pairwise OSCORE contexts\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device 1: ");
  int c1;
  SCANF("%d", &c1);
  if (c1 < 0 || c1 >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  OC_PRINTF("Select device 2: ");
  int c2;
  SCANF("%d", &c2);
  if (c2 < 0 || c2 >= i || c2 == c1) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_pairwise_oscore_contexts(
    &devices[c1]->uuid, &devices[c2]->uuid, provision_oscore_contexts_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision OSCORE contexts\n");
  } else {
    OC_PRINTF("\nERROR issuing request to provision OSCORE contexts\n");
  }
  otb_mutex_unlock(app_sync_lock);
}
#endif /* OC_OSCORE */

static void
provision_credentials_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned pairwise credentials\n");
  } else {
    OC_PRINTF("\nERROR provisioning pairwise credentials\n");
  }
}

static void
provision_credentials(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nProvision pairwise (PSK) credentials\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device 1: ");
  int c1;
  SCANF("%d", &c1);
  if (c1 < 0 || c1 >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  OC_PRINTF("Select device 2: ");
  int c2;
  SCANF("%d", &c2);
  if (c2 < 0 || c2 >= i || c2 == c1) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_pairwise_credentials(
    &devices[c1]->uuid, &devices[c2]->uuid, provision_credentials_cb, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision credentials\n");
  } else {
    OC_PRINTF("\nERROR issuing request to provision credentials\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
provision_authcrypt_wildcard_ace_cb(const oc_uuid_t *uuid, int status,
                                    void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned auth-crypt * ACE to device %s\n", di);
  } else {
    OC_PRINTF("\nERROR provisioning ACE to device %s\n", di);
  }
}

static void
provision_authcrypt_wildcard_ace(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nProvision auth-crypt * ACE\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    OC_PRINTF(
      "\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  OC_PRINTF("\n\nSelect device for provisioning: ");
  int dev;
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret = oc_obt_provision_auth_wildcard_ace(
    &devices[dev]->uuid, provision_authcrypt_wildcard_ace_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision auth-crypt * ACE\n");
  } else {
    OC_PRINTF("\nERROR issuing request to provision auth-crypt * ACE\n");
  }
}

static void
provision_ace2_cb(const oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_ARRAY_SIZE(di));

  if (status >= 0) {
    OC_PRINTF("\nSuccessfully provisioned ACE to device %s\n", di);
  } else {
    OC_PRINTF("\nERROR provisioning ACE to device %s\n", di);
  }
}

static void
provision_ace2(void)
{
  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  const char *conn_types[2] = { "anon-clear", "auth-crypt" };
  int num_resources = 0;

  device_handle_t *devices[MAX_NUM_DEVICES];
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nProvision ACL2\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    OC_PRINTF(
      "\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  OC_PRINTF("\n\nSelect device for provisioning: ");
  int dev;
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  OC_PRINTF("\nSubjects:");
  device = (device_handle_t *)oc_list_head(owned_devices);
  OC_PRINTF("\n[0]: %s\n", conn_types[0]);
  OC_PRINTF("[1]: %s\n", conn_types[1]);
  OC_PRINTF("[2]: Role\n");
  OC_PRINTF("[3]: Cloud\n");
  i = 0;
  while (device != NULL) {
    char di[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i + 4, di, device->device_name);
    i++;
    device = device->next;

    if (!device) {
      oc_uuid_to_str(oc_core_get_device_id(0), di, OC_UUID_LEN);
      OC_PRINTF("[%d]: %s - (OBT)\n", i + 4, di);
      i++;
    }
  }
  OC_PRINTF("\nSelect subject: ");
  int sub;
  SCANF("%d", &sub);

  if ((sub > (i + 3)) || (sub < 0)) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  oc_sec_ace_t *ace = NULL;
  if (sub == 0) {
    ace = oc_obt_new_ace_for_connection(OC_CONN_ANON_CLEAR);
  } else if (sub == 1) {
    ace = oc_obt_new_ace_for_connection(OC_CONN_AUTH_CRYPT);
  } else if (sub == 2) {
    char role[64];
    OC_PRINTF("\nEnter role: ");
    SCANF("%63s", role);
    int d;
    OC_PRINTF("\nAuthority? [0-No, 1-Yes]: ");
    SCANF("%d", &d);
    if (d == 1) {
      char authority[64];
      OC_PRINTF("\nEnter Authority: ");
      SCANF("%63s", authority);
      ace = oc_obt_new_ace_for_role(role, authority);
    } else {
      ace = oc_obt_new_ace_for_role(role, NULL);
    }
  } else {
    if (sub == 3) {
      OC_PRINTF("\nEnter Cloud sid: ");
      char di[OC_UUID_LEN] = { 0 };
      SCANF("%36s", di);
      oc_uuid_t uuid_di;
      oc_str_to_uuid(di, &uuid_di);
      ace = oc_obt_new_ace_for_subject(&uuid_di);
    } else if (sub == (i + 3)) {
      ace = oc_obt_new_ace_for_subject(oc_core_get_device_id(0));
    } else {
      ace = oc_obt_new_ace_for_subject(&devices[sub - 4]->uuid);
    }
  }

  if (!ace) {
    OC_PRINTF("\nERROR: Could not create ACE\n");
    return;
  }

  while (num_resources <= 0 || num_resources > MAX_NUM_RESOURCES) {
    if (num_resources != 0) {
      OC_PRINTF("\n\nERROR: Enter valid number\n\n");
    }
    OC_PRINTF("\nEnter number of resources in this ACE: ");
    SCANF("%d", &num_resources);
  }

  int c;
  OC_PRINTF("\nResource properties\n");
  i = 0;
  while (i < num_resources) {
    oc_ace_res_t *res = oc_obt_ace_new_resource(ace);
    if (!res) {
      OC_PRINTF("\nERROR: Could not allocate new resource for ACE\n");
      oc_obt_free_ace(ace);
      return;
    }

    OC_PRINTF("Have resource href? [0-No, 1-Yes]: ");
    SCANF("%d", &c);
    if (c == 1) {
      OC_PRINTF("Enter resource href (eg. /a/light): ");
      char href[64];
      SCANF("%63s", href);

      oc_obt_ace_resource_set_href(res, href);
      oc_obt_ace_resource_set_wc(res, OC_ACE_NO_WC);
    } else {
      OC_PRINTF("\nSet wildcard resource? [0-No, 1-Yes]: ");
      SCANF("%d", &c);
      if (c == 1) {
        OC_PRINTF("[1]: All NCRs '*' \n"
                  "[2]: All NCRs with >=1 secured endpoint '+'\n"
                  "[3]: All NCRs with >=1 unsecured endpoint '-'\n"
                  "\nSelect wildcard resource: ");
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

  OC_PRINTF("\nSet ACE2 permissions\n");
  OC_PRINTF("CREATE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_CREATE);
  }
  OC_PRINTF("RETRIEVE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE);
  }
  OC_PRINTF("UPDATE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_UPDATE);
  }
  OC_PRINTF("DELETE [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_DELETE);
  }
  OC_PRINTF("NOTIFY [0-No, 1-Yes]: ");
  SCANF("%d", &c);
  if (c == 1) {
    oc_obt_ace_add_permission(ace, OC_PERM_NOTIFY);
  }

  otb_mutex_lock(app_sync_lock);
  int ret =
    oc_obt_provision_ace(&devices[dev]->uuid, ace, provision_ace2_cb, NULL);
  otb_mutex_unlock(app_sync_lock);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued request to provision ACE\n");
  } else {
    OC_PRINTF("\nERROR issuing request to provision ACE\n");
    oc_obt_free_ace(ace);
  }
}

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    OC_PRINTF("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)*buffer_len) {
    OC_PRINTF("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  size_t to_read = (size_t)pem_len;
  if (fread(buffer, 1, to_read, fp) < (size_t)pem_len) {
    OC_PRINTF("ERROR: unable to read PEM\n");
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
static void
install_trust_anchor(void)
{
  char cert[8192];
  size_t cert_len = 0;
  OC_PRINTF("\nPaste certificate here, then hit <ENTER> and type \"done\": ");
  int c;
  while ((c = getchar()) == '\n' || c == '\r')
    ;
  for (; (cert_len < 4 ||
          (cert_len >= 4 && memcmp(&cert[cert_len - 4], "done", 4) != 0));
       c = getchar()) {
    if (c == EOF) {
      OC_PRINTF("ERROR processing input.. aborting\n");
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
    OC_PRINTF("ERROR installing root cert\n");
    return;
  }
}
#endif /* OC_PKI */

static void
set_sd_info(void)
{
  char name[64] = { 0 };
  int priv = 0;
  OC_PRINTF("\n\nEnter security domain name: ");
  SCANF("%63s", name);
  OC_PRINTF("\n\nChoose security domain priv[0-No, 1-Yes]: ");
  SCANF("%d", &priv);
  oc_obt_set_sd_info(name, priv);
}

#ifdef OC_CLOUD
/**
 * function to print the returned cbor as JSON
 *
 */
static void
print_rep(const oc_rep_t *rep, bool pretty_print)
{
  size_t json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  char *json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, pretty_print);
  printf("%s\n", json);
  free(json);
}

static void
post_response_cloud_config(oc_client_response_t *data)
{
  OC_PRINTF("post_response_cloud_config:\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    OC_PRINTF("POST response: CREATED\n");
  else
    OC_PRINTF("POST response code %d\n", data->code);

  if (data->payload != NULL) {
    print_rep(data->payload, false);
  }
}

static void
set_cloud_info(void)
{
  char url[64] = "/CoapCloudConfResURI"; // url of the coap cloud config url
  char cis[64] = "coaps+tcp://127.0.0.1:5683";
  char at[64] = "test";
  char sid[64] = "00000000-0000-0000-0000-000000000001";
  char apn[64] = "plgd";
  char di[OC_UUID_LEN];
  oc_uuid_t device_uuid;

  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device to configure: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  i = 0;
  device = (device_handle_t *)oc_list_head(owned_devices);
  while (device != NULL) {
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    oc_str_to_uuid(di, &device_uuid);
    if (c == i) {
      OC_PRINTF("configuring: [%d]: %s - %s\n", i, di, device->device_name);
      break;
    }
    i++;
    device = device->next;
  }

  OC_PRINTF("\nEnter url of cloudconfig resource (/CoapCloudConfResURI) : ");
  SCANF("%63s", url);
  OC_PRINTF("\nPayload\n");
  OC_PRINTF("\nEnter access token 'at' ('test') :");
  SCANF("%63s", at);
  OC_PRINTF("\nEnter apn ('plgd'): ");
  SCANF("%63s", apn);
  OC_PRINTF("\nEnter cis ('coaps+tcp://127.0.0.1:5684'):");
  SCANF("%63s", cis);
  OC_PRINTF("\nEnter sid ('00000000-0000-0000-0000-000000000001'):");
  SCANF("%63s", sid);

  otb_mutex_lock(app_sync_lock);

  oc_obt_update_cloud_conf_device(&device_uuid, url, at, apn, cis, sid,
                                  post_response_cloud_config, NULL);

  otb_mutex_unlock(app_sync_lock);
}

static void
get_cloud_info(void)
{
  char di[OC_UUID_LEN];
  oc_uuid_t device_uuid;
  char url[64] = "/CoapCloudConfResURI"; // url of the coap cloud config url

  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device to retrieve Cloud config from: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  i = 0;
  device = (device_handle_t *)oc_list_head(owned_devices);
  while (device != NULL) {
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    oc_str_to_uuid(di, &device_uuid);
    if (c == i) {
      OC_PRINTF("retrieving: [%d]: %s - %s\n", i, di, device->device_name);
      break;
    }
    i++;
    device = device->next;
  }
  OC_PRINTF("\nEnter url of cloudconfig resource (/CoapCloudConfResURI) : ");
  SCANF("%63s", url);

  OC_PRINTF("\nretrieving data from %s :\n", url);

  otb_mutex_lock(app_sync_lock);
  oc_obt_retrieve_cloud_conf_device(&device_uuid, url,
                                    post_response_cloud_config, NULL);
  otb_mutex_unlock(app_sync_lock);
}

static void
trustanchorcb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    OC_PRINTF("\nSuccessfully installed trust anchor for cloud\n");
  } else {
    OC_PRINTF("\nERROR installing trust anchor %d\n", status);
  }
}

static void
set_cloud_trust_anchor(void)
{
  char di[OC_UUID_LEN];
  oc_uuid_t device_uuid;
  char sid[64] = "00000000-0000-0000-0000-000000000001";

  if (oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  int i = 0;
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device to set cloud trust anchor: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  i = 0;
  device = (device_handle_t *)oc_list_head(owned_devices);
  while (device != NULL) {
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    oc_str_to_uuid(di, &device_uuid);
    if (c == i) {
      OC_PRINTF("setting trust anchor on: [%d]: %s - %s\n", i, di,
                device->device_name);
      break;
    }
    i++;
    device = device->next;
  }

  OC_PRINTF("\nEnter subject ('00000000-0000-0000-0000-000000000001'):");
  SCANF("%63s", sid);

  char cert[8192];
  size_t cert_len = 0;
  OC_PRINTF("\nPaste certificate here, then hit <ENTER> and type \"done\": ");
  while ((c = getchar()) == '\n' || c == '\r')
    ;
  for (; (cert_len < 4 ||
          (cert_len >= 4 && memcmp(&cert[cert_len - 4], "done", 4) != 0));
       c = getchar()) {
    if (c == EOF) {
      OC_PRINTF("ERROR processing input.. aborting\n");
      return;
    }
    cert[cert_len] = (char)c;
    cert_len++;
  }

  while (cert[cert_len - 1] != '-' && cert_len > 1) {
    cert_len--;
  }
  cert[cert_len] = '\0';

  otb_mutex_lock(app_sync_lock);
  int retcode = oc_obt_provision_trust_anchor(cert, cert_len, sid, &device_uuid,
                                              trustanchorcb, NULL);
  OC_PRINTF("sending message: %d\n", retcode);

  otb_mutex_unlock(app_sync_lock);
}

#endif /* OC_CLOUD */

static void
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
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("ERROR installing root cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem("pki_certs/rootca2.pem", cert, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("ERROR installing root cert\n");
    return;
  }
#endif /* OC_SECURITY && OC_PKI */
}

static oc_discovery_flags_t
resource_discovery(const char *anchor, const char *uri, oc_string_array_t types,
                   oc_interface_mask_t iface_mask,
                   const oc_endpoint_t *endpoint, oc_resource_properties_t bm,
                   bool more, void *user_data)
{
  (void)user_data;
  (void)iface_mask;
  (void)bm;
  (void)types;
  (void)endpoint;
  OC_PRINTF("anchor %s, uri : %s\n", anchor, uri);
  if (!more) {
    OC_PRINTF("----End of discovery response---\n");
    return OC_STOP_DISCOVERY;
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
discover_resources(void)
{
  if (oc_list_length(unowned_devices) == 0 &&
      oc_list_length(owned_devices) == 0) {
    OC_PRINTF("\nPlease Re-discover devices\n");
    return;
  }

  device_handle_t *devices[MAX_NUM_DEVICES];
  int i = 0;
  device_handle_t *device = (device_handle_t *)oc_list_head(owned_devices);
  OC_PRINTF("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
  OC_PRINTF("\n\nUnowned Devices:\n");
  device = (device_handle_t *)oc_list_head(unowned_devices);
  while (device != NULL) {
    devices[i] = device;
    char di[OC_UUID_LEN];
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    OC_PRINTF("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  OC_PRINTF("\nSelect device: ");
  int c;
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    OC_PRINTF("ERROR: Invalid selection\n");
    return;
  }

  otb_mutex_lock(app_sync_lock);
  int ret =
    oc_obt_discover_all_resources(&devices[c]->uuid, resource_discovery, NULL);
  if (ret >= 0) {
    OC_PRINTF("\nSuccessfully issued resource discovery request\n");
  } else {
    OC_PRINTF("\nERROR issuing resource discovery request\n");
  }
  otb_mutex_unlock(app_sync_lock);
}

static void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, OC_ARRAY_SIZE(buffer));

  OC_PRINTF("Started device with ID: %s\n", buffer);
}

static bool
init(void)
{
#if defined(_WIN32)
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  InitializeCriticalSection(&app_sync_lock);
  signal(SIGINT, handle_signal);
#elif defined(__linux__)
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&app_sync_lock, NULL);
  if (err != 0) {
    printf("pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    printf("pthread_mutex_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    printf("pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    printf("pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    printf("pthread_cond_init failed (error=%d)!\n", err);
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
    deinit();
    return -1;
  }
#elif defined(__linux__)
  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    deinit();
    return -1;
  }
#endif

  display_device_uuid();

  int c;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
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
      discover_resources();
      break;
    case 8:
      otm_just_works();
      break;
    case 9:
      request_random_pin();
      break;
    case 10:
      otm_rdp();
      break;
#ifdef OC_PKI
    case 11:
      otm_cert();
      break;
#endif /* OC_PKI */
    case 12:
      provision_credentials();
      break;
    case 13:
      provision_ace2();
      break;
    case 14:
      provision_authcrypt_wildcard_ace();
      break;
    case 15:
      retrieve_cred_rsrc();
      break;
    case 16:
      delete_cred_by_credid();
      break;
    case 17:
      retrieve_acl2_rsrc();
      break;
    case 18:
      delete_ace_by_aceid();
      break;
    case 19:
      retrieve_own_creds();
      break;
    case 20:
      delete_own_cred_by_credid();
      break;
#ifdef OC_PKI
    case 21:
      provision_role_wildcard_ace();
      break;
    case 22:
      provision_id_cert();
      break;
    case 23:
      provision_role_cert();
      break;
#endif
#ifdef OC_OSCORE
    case 24:
      provision_oscore_contexts();
      break;
    case 25:
      provision_client_group_oscore_context();
      break;
    case 26:
      provision_server_group_oscore_context();
      break;
#endif /* OC_OSCORE */
    case 27:
      set_sd_info();
      break;
#ifdef OC_CLOUD
    case 30:
      set_cloud_info();
      break;
    case 31:
      get_cloud_info();
      break;
    case 32:
      set_cloud_trust_anchor();
      break;
#endif /* OC_CLOUD */
#ifdef OC_PKI
    case 96:
      install_trust_anchor();
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
  deinit();
  return 0;
}
