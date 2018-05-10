/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "security/oc_pstat.h"
#include "st_cloud_access.h"
#include "st_easy_setup.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

// define vendor specific properties.
#define ST_DEVICE_TYPE "deviceType"
#define ST_DEVICE_SUB_TYPE "deviceSubType"
#define ST_REG_SET_DEVICE                                                      \
  "{\"wm\":\"00:11:22:33:44:55\",\"pm\":\"00:11:22:33:44:55\",\"bm\":\"00:11:" \
  "22:33:44:55\",\"rk\":[\"VOICE\",\"EXTRA\",\"BTHIDPOWERON\"],\"sl\":["       \
  "\"TV2MOBILE\",\"MOBILE2TV\",\"BTWAKEUP\",\"WOWLAN\",\"BTREMOTECON\","       \
  "\"DLNADMR\"]}"
#define ST_NETWORK_PROV_INFO                                                   \
  "{\"IMEI\":\"123456789012345 / "                                             \
  "01\",\"IMSI\":\"123401234567890\",\"MCC_MNC\":\"100_10\",\"SN\":"           \
  "\"XY0123456XYZ\"}"
#define ST_PIN_NUMBER "pinNumber"
#define ST_MODEL_NUMBER "Model Number"
#define ST_PROTOCOL_VERSION "2.0"

// define application specific values.
#ifdef OC_SPEC_VER_OIC
static const char *spec_version = "core.1.1.0";
static const char *data_model_version = "res.1.1.0,sh.1.1.0";
#else  /* OC_SPEC_VER_OIC */
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";
#endif /* !OC_SPEC_VER_OIC */

static sc_properties st_vendor_props;

static const char *resource_uri = "/a/light";
static const char *resource_rt = "core.light";
static const char *additional_rt = "core.brightlight";
static const char *resource_name = "Samsung's Light";

static const char *device_rt = "oic.d.light";
static const char *device_name = "Light";

static const char *manufacturer = "Samsung";

static bool discoverable = true;
static bool observable = true;

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

pthread_mutex_t app_mutex;
oc_resource_t *res;
oc_link_t *publish_res;

int quit = 0;

static bool state = false;
int power;
oc_string_t name;

oc_define_interrupt_handler(observe)
{
  oc_notify_observers(res);
}

static int
app_init(void)
{
  oc_activate_interrupt_handler(observe);
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  oc_new_string(&name, resource_name, strlen(resource_name));
  return ret;
}

static void
get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;

  printf("get_handler:\n");

  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, state);
    oc_rep_set_int(root, power, power);
    oc_rep_set_text_string(root, name, oc_string(name));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_handler(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  (void)interface;
  (void)user_data;
  printf("post_handler:\n");
  printf("  Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    printf("  %s :", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      printf("%d\n", state);
      break;
    case OC_REP_INT:
      power = rep->value.integer;
      printf("%d\n", power);
      break;
    case OC_REP_STRING:
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
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

static void
put_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)interface;
  (void)user_data;
  post_handler(request, interface, user_data);
}

static void
change_state(void)
{
  state = !state;
  oc_signal_interrupt_handler(observe);
}

static void
change_power(void)
{
  power += 5;
  oc_signal_interrupt_handler(observe);
}

static void
register_resources(void)
{
  res = oc_new_resource(NULL, resource_uri, 2, 0);
  oc_resource_bind_resource_type(res, resource_rt);
  oc_resource_bind_resource_type(res, additional_rt);
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, discoverable);
  oc_resource_set_observable(res, observable);
  oc_resource_set_request_handler(res, OC_GET, get_handler, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_handler, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_handler, NULL);
  oc_add_resource(res);

  publish_res = oc_new_link(res);
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event;

  while (quit != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_mutex);
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

  pthread_exit(0);
}

void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  printf("=====================================\n");
  printf("1. Change my state(%d)\n", state);
  printf("2. Change my power(%d)\n", power);
  printf("3. Reset device\n");
  printf("0. Quit\n");
  printf("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

static bool is_easy_setup_success = false;
void
easy_setup_handler(st_easy_setup_status_t status)
{
  if (status == EASY_SETUP_FINISH) {
    is_easy_setup_success = true;
  } else if (status == EASY_SETUP_RESET) {
    // TODO
  } else if (status == EASY_SETUP_FAIL) {
    printf("Easy setup failed!!!\n");
    exit(-1);
  }
}

static bool is_cloud_access_success = false;
void
cloud_access_handler(st_cloud_access_status_t status)
{
  if (status == CLOUD_ACCESS_FINISH) {
    is_cloud_access_success = true;
  } else if (status == CLOUD_ACCESS_FAIL) {
    printf("Cloud access failed!!!\n");
    exit(-1);
  } else if (status == CLOUD_ACCESS_DISCONNECTED) {
    printf("Disconnected from cloud!\n");
    is_cloud_access_success = false;
  }
}

static void
st_vendor_props_initialize(void)
{
  memset(&st_vendor_props, 0, sizeof(sc_properties));
  strncpy(st_vendor_props.deviceType, ST_DEVICE_TYPE, MAXLEN_STRING);
  strncpy(st_vendor_props.deviceSubType, ST_DEVICE_SUB_TYPE, MAXLEN_STRING);
  st_vendor_props.netConnectionState = NET_STATE_INIT;
  st_vendor_props.discoveryChannel = WIFI_DISCOVERY_CHANNEL_INIT;
  strncpy(st_vendor_props.regSetDev, ST_REG_SET_DEVICE, MAXLEN_STRING);
  strncpy(st_vendor_props.nwProvInfo, ST_NETWORK_PROV_INFO, MAXLEN_STRING);
  strncpy(st_vendor_props.pnpPin, ST_PIN_NUMBER, MAXLEN_STRING);
  strncpy(st_vendor_props.modelNumber, ST_MODEL_NUMBER, MAXLEN_STRING);
  strncpy(st_vendor_props.esProtocolVersion, ST_PROTOCOL_VERSION,
          MAXLEN_STRING);
}

static bool
st_main_initialize(void)
{
  if (!st_easy_setup_start(&st_vendor_props, easy_setup_handler)) {
    printf("Failed to start easy setup!\n");
    return false;
  }

  printf("easy setup is started.\n");
  while (!is_easy_setup_success && quit != 1) {
    pthread_mutex_lock(&app_mutex);
    if (get_easy_setup_status() == EASY_SETUP_FINISH) {
      break;
    }
    pthread_mutex_unlock(&app_mutex);
    sleep(1);
    printf(".");
    fflush(stdout);
  }
  printf("\n");

  if (is_easy_setup_success) {
    printf("easy setup is successfully finished!\n");
  } else {
    return false;
  }

  es_coap_cloud_conf_data *cloud_info = get_cloud_informations();
  if (!cloud_info) {
    printf("could not get cloud informations.\n");
    return false;
  }

  sc_coap_cloud_server_conf_properties *st_cloud_info =
    get_st_cloud_informations();
  if (!st_cloud_info) {
    printf("Temporary access token: ");
    if (!scanf("%s", cloud_info->auth_code)) {
      printf("scanf failed!!!!\n");
      return false;
    }
  }

  // cloud access
  if (!st_cloud_access_start(cloud_info, st_cloud_info, publish_res,
                             res->device, cloud_access_handler)) {
    printf("Failed to access cloud!\n");
    return false;
  }

  printf("cloud access started.\n");
  while (!is_cloud_access_success && quit != 1) {
    pthread_mutex_lock(&app_mutex);
    if (get_cloud_access_status(res->device) == CLOUD_ACCESS_FINISH) {
      break;
    }
    pthread_mutex_unlock(&app_mutex);
    sleep(1);
    printf(".");
    fflush(stdout);
  }
  printf("\n");

  if (is_cloud_access_success) {
    printf("cloud access successfully finished!\n");
  } else {
    return false;
  }

  return true;
}

static void
st_main_reset(void)
{
#ifdef OC_SECURITY
  oc_sec_reset();
#endif /* OC_SECURITY */

  st_easy_setup_stop();
  is_easy_setup_success = false;

  st_cloud_access_stop(res->device);
  is_cloud_access_success = false;
}

int
main(void)
{
  int init = 0;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

#ifdef OC_SECURITY
  oc_storage_config("./st_things_creds");
#endif /* OC_SECURITY */

  if (pthread_mutex_init(&mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    return -1;
  }

  if (pthread_mutex_init(&app_mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    pthread_mutex_destroy(&mutex);
    return -1;
  }

  oc_set_max_app_data_size(3072);

  init = oc_main_init(&handler);
  if (init < 0) {
    printf("oc_main_init failed!(%d)\n", init);
    goto exit;
  }

  int device_num = oc_core_get_num_devices();
  int i;
  for (i = 0; i < device_num; i++) {
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(i);
    printf("=== device(%d) endpoint info. ===\n", i);
    while (ep) {
      oc_string_t ep_str;
      if (oc_endpoint_to_string(ep, &ep_str) == 0) {
        printf("-> %s\n", oc_string(ep_str));
        oc_free_string(&ep_str);
      }
      ep = ep->next;
    }
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    printf("Failed to create main thread\n");
    init = -1;
    goto exit;
  }

  st_vendor_props_initialize();

  while (quit != 1) {
    if (!st_main_initialize()) {
      printf("Failed to start easy setup & cloud access!\n");
      init = -1;
      goto exit;
    }

    char key[10];
    while (quit != 1) {
      print_menu();
      fflush(stdin);
      if (!scanf("%s", &key)) {
        printf("scanf failed!!!!\n");
        quit = 1;
        handle_signal(0);
        break;
      }

      if (!is_easy_setup_success || !is_cloud_access_success) {
        printf("Not initialized\n");
        continue;
      }

      pthread_mutex_lock(&app_mutex);
      switch (key[0]) {
      case '1':
        change_state();
        break;
      case '2':
        change_power();
        break;
      case '3':
        st_main_reset();
        pthread_mutex_unlock(&app_mutex);
        goto reset;
      case '0':
        quit = 1;
        handle_signal(0);
        break;
      default:
        printf("unsupported command.\n");
        break;
      }
      pthread_mutex_unlock(&app_mutex);
    }
  reset:
    printf("reset finished\n");
  }

  pthread_join(thread, NULL);
  printf("pthread_join finish!\n");

exit:
  oc_delete_link(publish_res);
  st_easy_setup_stop();
  printf("easy setup stop done\n");

  oc_main_shutdown();

  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_mutex);
  return 0;
}
