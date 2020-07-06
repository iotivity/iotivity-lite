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

/* Logic variables */
static int quit;

/* Main event thread */
static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    next_event = oc_main_poll();
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

/* Locally invoked functions */
static void
display_menu(void)
{
  PRINT("##### Specialized OBT #####\n");
  PRINT("0. Show menu\n");
  PRINT("1. Discover unowned devices\n");
  PRINT("2. Discover owned devices\n");
  PRINT("3. Perform JW OTM\n");
  PRINT("99. Exit\n");
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

/* TODO: Implement onboarding kick-off.
 * Takes UUID to filter on when performing discovery as a parameter of the request
 */
static void
post_obt(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  OC_DBG("POST_OBT:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_DBG("Key: %s \n", oc_string(rep->name));
    switch (rep->type) {
      case OC_REP_STRING:
        OC_DBG("Value: %s \n", oc_string(rep->value.string));
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
        break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
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
        display_menu();
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
      case 99:
        handle_signal(0);
        break;
      default:
        break;
    }
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
