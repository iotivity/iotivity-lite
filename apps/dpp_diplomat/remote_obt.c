/**
 * OCF onboarding tool that can be remotely invoked by an authorized device.
 */

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_obt.h"
#include "port/oc_clock.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#define MAX_NUM_DEVICES (50)
#define MAX_NUM_RESOURCES (100)
#define MAX_REMOTE_ONBOARDING (5)
#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

/* Structure in app to track currently discovered owned/unowned devices */
typedef struct device_handle_t
{
  struct device_handle_t *next;
  oc_uuid_t uuid;
  char device_name[64];
} device_handle_t;

typedef struct remote_ob_worker
{
  bool in_use;
  pthread_t thread;
  pthread_mutex_t mutex;
  pthread_cond_t cv;
  oc_uuid_t uuid;
  bool found;
} remote_ob_worker;

/* Pool of device handles */
OC_MEMB(device_handles, device_handle_t, MAX_OWNED_DEVICES);
/* List of known owned devices */
OC_LIST(owned_devices);
/* List of known un-owned devices */
OC_LIST(unowned_devices);

/* Event threading variables */
static pthread_t event_thread;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;

/* Local Action mutex */
static pthread_mutex_t app_lock;

/* Discovery Thread Pool */
static remote_ob_worker remote_ob_workers[MAX_REMOTE_ONBOARDING];

/* Logic variables */
static int quit;

/* Main event thread */
static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    pthread_mutex_lock(&app_lock);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_lock);

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
  oc_obt_shutdown();

  return NULL;
}

/* Threading Functions */
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

/* App utility functions */
static device_handle_t *
is_device_in_list(oc_uuid_t *uuid, oc_list_t list)
{
  device_handle_t *device = (device_handle_t *)oc_list_head(list);
  while (device != NULL) {
    if (memcmp(device->uuid.id, uuid->id, 16) == 0) {
      return device;
    }
    device = device->next;
  }
  return NULL;
}

static bool
add_device_to_list(oc_uuid_t *uuid, const char *device_name, oc_list_t list)
{
  device_handle_t *device = is_device_in_list(uuid, list);

  if (!device) {
    device = oc_memb_alloc(&device_handles);
    if (!device) {
      return false;
    }
    memcpy(device->uuid.id, uuid->id, 16);
    oc_list_add(list, device);
  }

  if (device_name) {
    size_t len = strlen(device_name);
    len = (len > 63) ? 63 : len;
    strncpy(device->device_name, device_name, len);
    device->device_name[len] = '\0';
  } else {
    device->device_name[0] = '\0';
  }
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

/* Callback functions */
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

  oc_do_get("/oic/d", ep, NULL, &get_device, HIGH_QOS, unowned_devices);
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

  oc_do_get("/oic/d", ep, NULL, &get_device, HIGH_QOS, owned_devices);
}

static void
otm_just_works_cb(oc_uuid_t *uuid, int status, void *data)
{
  device_handle_t *device = (device_handle_t *)data;
  memcpy(device->uuid.id, uuid->id, 16);
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully performed OTM on device with UUID %s\n", di);
    oc_list_add(owned_devices, device);
  } else {
    oc_memb_free(&device_handles, device);
    PRINT("\nERROR performing ownership transfer on device %s\n", di);
  }
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
provision_ace2_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[37];
  oc_uuid_to_str(uuid, di, 37);

  if (status >= 0) {
    PRINT("\nSuccessfully provisioned ACE to device %s\n", di);
  } else {
    PRINT("\nERROR provisioning ACE to device %s\n", di);
    PRINT("\nStatus: %d\n", status);
  }
}

/* Locally invoked functions */
static void
display_menu(void)
{
  PRINT("##### Specialized OBT #####\n");
  PRINT("0. Show menu\n");
  PRINT("1. Discover unowned devices\n");
  PRINT("2. Discover owned devices\n");
  PRINT("3. Perform JW OTM\n");
  PRINT("4. Provision pairwise credentials\n");
  PRINT("5. Provision ACE2\n");
  PRINT("98. Display OBT Info\n");
  PRINT("99. Exit\n");
}

static void
display_obt_info(void)
{
  char di[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), di, OC_UUID_LEN);
  PRINT("\n### OBT Info ###\n");
  PRINT("OBT UUID: %s\n\n", di);
}

static void
discover_unowned_devices(void)
{
  pthread_mutex_lock(&app_lock);
  oc_obt_discover_unowned_devices(unowned_device_cb, NULL);
  pthread_mutex_unlock(&app_lock);
  signal_event_loop();
}

static void
discover_owned_devices(void)
{
  pthread_mutex_lock(&app_lock);
  oc_obt_discover_owned_devices(owned_device_cb, NULL);
  pthread_mutex_unlock(&app_lock);
  signal_event_loop();
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

  pthread_mutex_lock(&app_lock);

  int ret = oc_obt_perform_just_works_otm(&devices[c]->uuid, otm_just_works_cb,
                                          devices[c]);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform ownership transfer\n");
    /* Having issued an OTM request, remove this item from the unowned device
     * list
     */
    oc_list_remove(unowned_devices, devices[c]);
  } else {
    PRINT("\nERROR issuing request to perform ownership transfer\n");
  }

  pthread_mutex_unlock(&app_lock);
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

  char di[OC_UUID_LEN];
  PRINT("\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }
  PRINT("\nSelect device 1: ");
  SCANF("%d", &c1);
  if (c1 < 0 || c1 > i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }
  PRINT("Select device 2:");
  SCANF("%d", &c2);
  if (c2 < 0 || c2 >= i || c2 == c1) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  pthread_mutex_lock(&app_lock);
  int ret = oc_obt_provision_pairwise_credentials(&devices[c1]->uuid,
      &devices[c2]->uuid, provision_credentials_cb, NULL);

  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision credentials\n");
  } else {
    PRINT("\nERROR issuing request to provision credentials\n");
  }
  pthread_mutex_unlock(&app_lock);
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

  char di[OC_UUID_LEN];
  PRINT("\nProvision ACL2\nMy Devices:\n");
  while (device != NULL) {
    devices[i] = device;
    oc_uuid_to_str(&device->uuid, di, OC_UUID_LEN);
    PRINT("[%d]: %s - %s\n", i, di, device->device_name);
    i++;
    device = device->next;
  }

  if (i == 0) {
    PRINT("\nNo devices to provision.. Please Re-Discover Owned devices.\n");
    return;
  }

  oc_uuid_to_str(oc_core_get_device_id(0), di, OC_UUID_LEN);
  PRINT("[%d]: %s - (OBT)\n", i, di);

  PRINT("\n\nSelect device for provisioning: ");
  SCANF("%d", &dev);
  if (dev < 0 || dev > i) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  bool self = (dev == i);

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

    if (!device) {
      oc_uuid_to_str(oc_core_get_device_id(0), di, OC_UUID_LEN);
      PRINT("[%d]: %s - (OBT)\n", i + 3, di);
      i++;
    }
  }
  PRINT("\nSelect subject: ");
  SCANF("%d", &sub);

  if (sub >= (i + 3)) {
    PRINT("ERROR: Invalid selection\n");
    return;
  }

  oc_sec_ace_t *ace = NULL;
  if (sub > 2) {
    if (sub == (i + 2)) {
      ace = oc_obt_new_ace_for_subject(oc_core_get_device_id(0));
    } else {
      ace = oc_obt_new_ace_for_subject(&devices[sub - 3]->uuid);
    }
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
        PRINT("[1]: All NCRs '*' \n"
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

  pthread_mutex_lock(&app_lock);
  int ret = -1;
  if (self) {
    PRINT("Self is true\n");
    ret = oc_obt_self_provision_ace(ace, provision_ace2_cb, NULL);
  } else {
    ret = oc_obt_provision_ace(&devices[dev]->uuid, ace, provision_ace2_cb, NULL);
  }
  pthread_mutex_unlock(&app_lock);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to provision ACE\n");
  } else {
    PRINT("\nERROR issuing request to provision ACE\n");
  }
}

/* Remote onboarding functions */
static void
onboard_device_cb(oc_uuid_t *uuid, int status, void *data)
{
  (void)data;
  char di[OC_UUID_LEN];
  oc_uuid_to_str(uuid, di, OC_UUID_LEN);
  if (status >= 0) {
    PRINT("\nSuccessfully performed OTM on device with UUID %s\n", di);
  } else {
    PRINT("\nERROR performing ownership transfer on device %s\n", di);
  }
}

static void
onboard_device(remote_ob_worker *onboarding_worker)
{
  int ret = oc_obt_perform_just_works_otm(&onboarding_worker->uuid, onboard_device_cb, NULL);
  if (ret >= 0) {
    PRINT("\nSuccessfully issued request to perform ownership transfer\n");
  } else {
    PRINT("\nERROR issuing request to perform ownership transfer\n");
  }

  // Update found flag for polling discovery
  pthread_mutex_lock(&onboarding_worker->mutex);
  onboarding_worker->found = true;
  pthread_cond_signal(&onboarding_worker->cv);
  pthread_mutex_unlock(&onboarding_worker->mutex);
}

static void
remote_onboard_filter(oc_uuid_t *uuid, oc_endpoint_t *eps, void *data)
{
  (void)eps;
  remote_ob_worker *onboarding_worker = (remote_ob_worker *)data;

  if (!onboarding_worker) {
    return;
  }

  char di[OC_UUID_LEN];
  oc_uuid_to_str(&onboarding_worker->uuid, di, OC_UUID_LEN);
  OC_DBG("Remote onboard filter: Filtering for UUID: %s\n", di);

  if (memcmp(onboarding_worker->uuid.id, uuid->id, 16) == 0) {
    OC_DBG("Matching device found\n");
    onboard_device(onboarding_worker);
  }
}

static void *
do_polling_discovery(void *data)
{
  remote_ob_worker *onboarding_worker = (remote_ob_worker *)data;

  char di[OC_UUID_LEN];
  oc_uuid_to_str(&onboarding_worker->uuid, di, OC_UUID_LEN);

  struct timespec discovery_ts;
  int discovery_attempts = 0;
  while (discovery_attempts < 3 && quit != 1) {
    OC_DBG("Polling discovery attempt: %d\n", discovery_attempts + 1);
    clock_gettime(CLOCK_REALTIME, &discovery_ts);
    discovery_ts.tv_sec += 5;

    pthread_mutex_lock(&onboarding_worker->mutex);
    pthread_mutex_lock(&app_lock);
    oc_obt_discover_unowned_devices(remote_onboard_filter, onboarding_worker);
    pthread_mutex_unlock(&app_lock);
    signal_event_loop();

    pthread_cond_timedwait(&onboarding_worker->cv, &onboarding_worker->mutex, &discovery_ts);

    bool found = onboarding_worker->found;
    pthread_mutex_unlock(&onboarding_worker->mutex);
    if (found) {
      OC_DBG("Device %s was found. Stopping discovery poll\n", di);
      break;
    }
    discovery_attempts++;
  }

  onboarding_worker->in_use = false;
  return NULL;
}

/* Onboarding kick-off.
 * Takes UUID to filter on when performing discovery as a parameter of the request
 */
static void
post_obt(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  oc_status_t retval = OC_STATUS_NOT_MODIFIED;
  OC_DBG("POST_OBT:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name), "uuid") == 0) {
      OC_DBG("Processing UUID %s for onboarding\n", oc_string(rep->value.string));

      int i;
      for (i = 0; i < MAX_REMOTE_ONBOARDING; i++) {
        if (!remote_ob_workers[i].in_use) {
          PRINT("Free worker thread found\n");
          break;
        }
      }

      if (i >= MAX_REMOTE_ONBOARDING) {
        PRINT("Max number of remote onboarding threads in use\n");
        retval = OC_STATUS_INTERNAL_SERVER_ERROR;
        break;
      }

      remote_ob_workers[i].in_use = true;
      remote_ob_workers[i].found = false;
      oc_str_to_uuid(oc_string(rep->value.string), &remote_ob_workers[i].uuid);

      // Spin up an available thread for the discovery routine...
      if (pthread_create(&remote_ob_workers[i].thread, NULL, &do_polling_discovery, &remote_ob_workers[i]) != 0) {
        OC_ERR("Failed to create thread for discovery\n");
        retval =  OC_STATUS_INTERNAL_SERVER_ERROR;
        break;
      }
    }
    rep = rep->next;
  }
  oc_send_response(request, retval);
}

/* Init and setup functions */
static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.0.5",
                       "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
  oc_device_bind_resource_type(0, "oic.d.ams");
  oc_device_bind_resource_type(0, "oic.d.cms");
  return ret;
}

static void
register_resources(void)
{
  PRINT("Register Resource with local path \"/onboardreq\"\n");
  oc_resource_t *res_onboard = oc_new_resource(NULL, "/onboardreq", 1, 0);
  oc_resource_bind_resource_type(res_onboard, "obt.remote");
  oc_resource_bind_resource_interface(res_onboard, OC_IF_RW);
  oc_resource_set_default_interface(res_onboard, OC_IF_RW);
  oc_resource_set_discoverable(res_onboard, true);
  oc_resource_set_request_handler(res_onboard, OC_POST, post_obt, NULL);
  oc_add_resource(res_onboard);
}

static void
issue_requests(void)
{
  oc_obt_init();
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

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources = register_resources,
                                        .requests_entry = issue_requests };
#ifdef OC_STORAGE
  oc_storage_config("./remote_onboarding_tool_creds");
#endif /* OC_STORAGE */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    OC_ERR("Failed to create main OCF event thread\n");
    return -1;
  }

  /* Main interface loop */
  int c;
  while (quit != 1) {
    display_menu();
    SCANF("%d", &c);
    switch (c) {
      case 0:
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
        provision_credentials();
        break;
      case 5:
        provision_ace2();
        break;
      case 98:
        display_obt_info();
        break;
      case 99:
        handle_signal(0);
        break;
      default:
        break;
    }
  }

  // Block for any pending onboarding threads
  for (int i = 0; i < MAX_REMOTE_ONBOARDING; i++) {
    OC_DBG("Joining onboarding worker thread %d\n", i);
    pthread_join(remote_ob_workers[i].thread, NULL);
  }

  // Block for end of main event thread
  pthread_join(event_thread, NULL);

  OC_DBG("Main event thread done; freeing and exiting\n");

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
