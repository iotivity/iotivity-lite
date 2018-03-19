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

#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#define MAX_OWNED_DEVICES (50)
#define MAX_NUM_RESOURCES (100)
#define MAX_NUM_RT (50)
static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit;

static void
display_menu(void)
{
  PRINT("\n\n################################################\nOCF 1.3 "
        "Onboarding Tool\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Discover un-owned devices\n");
  PRINT("[2] Discover owned devices\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[3] Take ownership of device (Just-works)\n");
  PRINT("[4] Provision pair-wise credentials\n");
  PRINT("[5] Provision ACE2\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[6] RESET device\n");
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
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = 1;
  signal_event_loop();
}

static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    pthread_mutex_lock(&app_sync_lock);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_sync_lock);

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
  oc_main_shutdown();
  return NULL;
}

/* Handles to lists of oc_device_t objects, one each for
   every discovered device.
   These lists are voided after every oc_obt..() call.
*/
static oc_device_t *unowned_devices, *my_devices;

static void
unowned_device_cb(oc_device_t *devices, void *data)
{
  (void)data;
  int i = 0;
  unowned_devices = devices;
  PRINT("\nUnowned devices:\n");
  while (devices != NULL) {
    char di[37];
    oc_uuid_to_str(&devices->uuid, di, 37);
    PRINT("[%d]: %s\n", i, di);
    i++;
    devices = devices->next;
  }
  display_menu();
}

static void
owned_device_cb(oc_device_t *devices, void *data)
{
  (void)data;
  int i = 0;
  my_devices = devices;
  PRINT("\nMy devices:\n");
  while (devices != NULL) {
    char di[37];
    oc_uuid_to_str(&devices->uuid, di, 37);
    PRINT("[%d]: %s\n", i, di);
    i++;
    devices = devices->next;
  }
  display_menu();
}

static void
discover_owned_devices(void)
{
  pthread_mutex_lock(&app_sync_lock);
  oc_obt_discover_owned_devices(owned_device_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
discover_unowned_devices(void)
{
  pthread_mutex_lock(&app_sync_lock);
  oc_obt_discover_unowned_devices(unowned_device_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
otm_just_works_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    PRINT("\nSuccessfully performed ownership transfer\n");
  } else {
    PRINT("\nERROR performing ownership transfer\n");
  }
  display_menu();
}

static void
take_ownership_of_device(void)
{
  if (unowned_devices == NULL) {
    PRINT("\n\nPlease Re-Discover Un-Owned devices\n");
    return;
  }
  oc_device_t *devices[MAX_OWNED_DEVICES];
  oc_device_t *device = unowned_devices;
  int i = 0, c;
  PRINT("\nUnowned Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[37];
    oc_uuid_to_str(&device->uuid, di, 37);
    PRINT("[%d]: %s\n", i, di);
    i++;
    device = device->next;
  }
  PRINT("\n\nSelect device: ");
  SCANF("%d", &c);
  if (c < 0 || c >= i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_obt_perform_just_works_otm(devices[c], otm_just_works_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform ownership transfer\n");
  } else {
    PRINT("\nERROR issuing request to perform ownership transfer\n");
  }
  unowned_devices = NULL;
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
reset_device_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    PRINT("\nSuccessfully performed hard RESET\n");
  } else {
    PRINT("\nERROR performing hard RESET\n");
  }
  display_menu();
}

static void
reset_device(void)
{
  if (my_devices == NULL) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }
  oc_device_t *devices[MAX_OWNED_DEVICES];
  oc_device_t *device = my_devices;
  int i = 0, c;
  PRINT("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[37];
    oc_uuid_to_str(&device->uuid, di, 37);
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
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_obt_device_hard_reset(devices[c], reset_device_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform hard RESET\n");
  } else {
    PRINT("\nERROR issuing request to perform hard RESET\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
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
  display_menu();
}

static void
provision_credentials(void)
{
  if (my_devices == NULL) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }
  oc_device_t *devices[MAX_OWNED_DEVICES];
  oc_device_t *device = my_devices;
  int i = 0, c1, c2;
  PRINT("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[37];
    oc_uuid_to_str(&device->uuid, di, 37);
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
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_obt_provision_pairwise_credentials(
    devices[c1], devices[c2], provision_credentials_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision credentials\n");
  } else {
    PRINT("\nERROR issuing request to provision credentials\n");
  }
  my_devices = NULL;
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
provision_ace2_cb(int status, void *data)
{
  (void)data;
  if (status >= 0) {
    PRINT("\nSuccessfully provisioned ACE\n");
  } else {
    PRINT("\nERROR provisioning ACE\n");
  }
  display_menu();
}

static void
provision_ace2(void)
{
  if (my_devices == NULL) {
    PRINT("\n\nPlease Re-Discover Owned devices\n");
    return;
  }

  const char *conn_types[2] = { "anon-clear", "auth-crypt" };
  int num_resources = 0;

  oc_device_t *devices[MAX_OWNED_DEVICES];
  oc_device_t *device = my_devices;
  int i = 0, dev, sub;
  PRINT("\nProvision ACL2\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    char di[37];
    oc_uuid_to_str(&device->uuid, di, 37);
    PRINT("[%d]: %s\n", i, di);
    i++;
    device = device->next;
  }

  if (i == 0) {
    PRINT("\nNo devices to provision.. Please Re-Discover owned devices.\n");
    my_devices = NULL;
    return;
  }

  PRINT("\n\nSelect device for provisioning: ");
  SCANF("%d", &dev);
  if (dev < 0 || dev >= i) {
    PRINT("ERROR: Invalid selection\n");
    my_devices = NULL;
    return;
  }

  PRINT("\nSubjects:");
  device = my_devices;
  PRINT("\n[0]: %s\n", conn_types[0]);
  PRINT("[1]: %s\n", conn_types[1]);
  i = 0;
  while (device != NULL) {
    char di[37];
    oc_uuid_to_str(&device->uuid, di, 37);
    PRINT("[%d]: %s\n", i + 2, di);
    i++;
    device = device->next;
  }
  PRINT("\nSelect subject: ");
  SCANF("%d", &sub);

  if (sub >= (i + 2)) {
    PRINT("ERROR: Invalid selection\n");
    my_devices = NULL;
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
    my_devices = NULL;
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
      my_devices = NULL;
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
        PRINT("[1]: All resources\n[2]: All discoverable resources\n[3]: All "
              "non-discoverable resources\n\nSelect wildcard resource: ");
        SCANF("%d", &c);
        switch (c) {
        case 1:
          oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL);
          break;
        case 2:
          oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL_DISCOVERABLE);
          break;
        case 3:
          oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL_NON_DISCOVERABLE);
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

  int ret = oc_obt_provision_ace(devices[dev], ace, provision_ace2_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision ACE\n");
  } else {
    PRINT("\nERROR issuing request to provision ACE\n");
  }

  my_devices = NULL;
}

int
main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int init;

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .requests_entry = issue_requests };

  oc_storage_config("./onboarding_tool_creds");

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }

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
      take_ownership_of_device();
      break;
    case 4:
      provision_credentials();
      break;
    case 5:
      provision_ace2();
      break;
    case 6:
      reset_device();
      break;
    case 9:
      handle_signal(0);
      break;
    default:
      break;
    }
  }

  pthread_join(event_thread, NULL);
  return 0;
}
