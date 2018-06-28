/* ***************************************************************************
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
#include "port/oc_clock.h"

#include "samsung/sc_easysetup.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "easysetup.h"

const char *deviceType = "deviceType";
static const char *deviceSubType = "deviceSubType";
static const char *regSetDev =
    "{\"wm\":\"00:11:22:33:44:55\",\"pm\":\"00:11:22:33:44:55\","
    "\"bm\":\"00:11:22:33:44:55\",\"rk\":[\"VOICE\",\"EXTRA\","
    "\"BTHIDPOWERON\"],\"sl\":[\"TV2MOBILE\",\"MOBILE2TV\","
    "\"BTWAKEUP\",\"WOWLAN\",\"BTREMOTECON\",\"DLNADMR\"]}";
static const char *nwProvInfo =
    "{\"IMEI\":\"123456789012345 / "
    "01\",\"IMSI\":\"123401234567890\",\"MCC_MNC\":\"100_10\","
    "\"SN\":\"XY0123456XYZ\"}";
static const char *pnpPin = "pinNumber";
static const char *modelNumber = "Model Number";
static const char *esProtocolVersion = "2.0";

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

#define SSID_LEN    15

static double temp_C = 5.0, min_C = 0.0, max_C = 100.0, min_K = 273.15,
              max_K = 373.15, min_F = 32, max_F = 212;
typedef enum { C = 100, F, K } units_t;

/**
 * @var gIsSecured
 * @brief Variable to check if secure mode is enabled or not.
 */
static bool gIsSecured = false;

static sc_properties g_SCProperties;

static sec_provisioning_info g_provisioninginfo_resource;

void SetProvInfo() {
  // Set prov info properties
  int target_size = 1;
  char uuid[37];
  memset(&g_provisioninginfo_resource, 0, sizeof(g_provisioninginfo_resource));
  oc_get_device_id(0, uuid, 37);
  g_provisioninginfo_resource.targets = (sec_provisioning_info_targets *)malloc(
      target_size * sizeof(sec_provisioning_info_targets));
  if(g_provisioninginfo_resource.targets == NULL)
  {
    printf("[ES App] Memory allocation failed for provisioning resource targets \n");
    return;
  }
  for (int i = 0; i < target_size; i++) {
    oc_new_string(&g_provisioninginfo_resource.targets[i].target_di, uuid,
                  strlen(uuid));
    oc_new_string(&g_provisioninginfo_resource.targets[i].target_rt, "oic.d.tv",
                  9);
    g_provisioninginfo_resource.targets[i].published = false;
  }
  g_provisioninginfo_resource.targets_size = target_size;
  g_provisioninginfo_resource.owned = false;
  oc_new_string(&g_provisioninginfo_resource.easysetup_di, uuid, strlen(uuid));

  if (set_sec_prov_info(&g_provisioninginfo_resource) == ES_ERROR)
    PRINT("SetProvInfo Error\n");

  PRINT("[ES App] SetProvInfo OUT\n");
}

static int app_init(void) {
  int err = oc_init_platform("Samsung", NULL, NULL);

  err |= oc_add_device("/oic/d", "oic.d.airconditioner", "[Floor A/C] Samsung",
                       "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
  return err;
}

static void get_temp(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data) {
  (void)user_data;
  PRINT("[ES App] GET_temp:\n");
  bool invalid_query = false;
  double temp = temp_C;
  units_t temp_units = C;
  char *units;
  int units_len = oc_get_query_value(request, "units", &units);
  if (units_len != -1) {
    if (units[0] == 'K') {
      temp = temp_C + 273.15;
      temp_units = K;
    } else if (units[0] == 'F') {
      temp = (temp_C / 100) * 180 + 32;
      temp_units = F;
    } else if (units[0] != 'C')
      invalid_query = true;
  }

  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    oc_rep_set_text_string(root, id, "home_thermostat");
  /* fall through */
  case OC_IF_A:
  case OC_IF_S:
    oc_rep_set_double(root, temperature, temp);
    switch (temp_units) {
    case C:
      oc_rep_set_text_string(root, units, "C");
      break;
    case F:
      oc_rep_set_text_string(root, units, "F");
      break;
    case K:
      oc_rep_set_text_string(root, units, "K");
      break;
    }
    break;
  default:
    break;
  }

  if (!invalid_query) {
    oc_rep_set_array(root, range);
    switch (temp_units) {
    case C:
      oc_rep_add_double(range, min_C);
      oc_rep_add_double(range, max_C);
      break;
    case K:
      oc_rep_add_double(range, min_K);
      oc_rep_add_double(range, max_K);
      break;
    case F:
      oc_rep_add_double(range, min_F);
      oc_rep_add_double(range, max_F);
      break;
    }
    oc_rep_close_array(root, range);
  }

  oc_rep_end_root_object();

  if (invalid_query)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_OK);
}

static void post_temp(oc_request_t *request, oc_interface_mask_t interface,
                      void *user_data) {
  (void)interface;
  (void)user_data;
  PRINT("[ES App] POST_temp:\n");
  bool out_of_range = false;
  double temp = -1;

  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_DOUBLE:
      temp = rep->value.double_p;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (temp < min_C || temp > max_C)
    out_of_range = true;

  temp_C = temp;

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, id, "home_thermostat");
  oc_rep_set_double(root, temperature, temp_C);
  oc_rep_set_text_string(root, units, "C");
  oc_rep_set_array(root, range);
  oc_rep_add_double(range, min_C);
  oc_rep_add_double(range, max_C);
  oc_rep_close_array(root, range);
  oc_rep_end_root_object();

  if (out_of_range)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_CHANGED);
}

void WiFiProvCbInApp(es_wifi_conf_data *eventData) {
  printf("WiFiProvCbInApp IN\n");

  if (eventData == NULL) {
    printf("ESWiFiProvData is NULL\n");
    return;
  }

  printf("SSID : %s\n", oc_string(eventData->ssid));
  printf("Password : %s\n", oc_string(eventData->pwd));
  printf("AuthType : %d\n", eventData->authtype);
  printf("EncType : %d\n", eventData->enctype);

  if (eventData->userdata != NULL) {
    sc_wifi_conf_properties *data = eventData->userdata;
    printf("[SC] DiscoveryChannel : %d\n", data->disc_channel);
  }

  printf("WiFiProvCbInApp OUT\n");
}

void DevConfProvCbInApp(es_dev_conf_data *eventData) {
  printf("[ES App] DevConfProvCbInApp IN\n");

  if (eventData == NULL) {
    printf("[ES App] ESDevConfProvData is NULL\n");
    return;
  }

  if (eventData->userdata != NULL) {
    sc_dev_conf_properties *data = eventData->userdata;
    for (uint8_t i = 0; i < oc_string_array_get_allocated_size(data->location);
         ++i) {
      printf("[SC] Location : %s\n",
             oc_string_array_get_item(data->location, i));
    }
    printf("[SC] Register Mobile Device : %s\n",
           oc_string(data->reg_mobile_dev));
    printf("[SC] Country : %s\n", oc_string(data->country));
    printf("[SC] Language : %s\n", oc_string(data->language));
    printf("[SC] GPS Location : %s\n", oc_string(data->gps_location));
    printf("[SC] UTC Date time : %s\n", oc_string(data->utc_date_time));
    printf("[SC] Regional time : %s\n", oc_string(data->regional_date_time));
    printf("[SC] SSO List : %s\n", oc_string(data->sso_list));
  }

  printf("[ES App] DevConfProvCbInApp OUT\n");
}

void CloudDataProvCbInApp(es_coap_cloud_conf_data *eventData) {
  printf("[ES App] cloud_conf_prov_cb_in_app in\n");

  if (eventData == NULL) {
    printf("es_coap_cloud_conf_data is NULL\n");
    return;
  }

  if (oc_string(eventData->auth_code)) {
    printf("AuthCode : %s\n", oc_string(eventData->auth_code));
  }

  if (oc_string(eventData->access_token)) {
    printf("Access Token : %s\n", oc_string(eventData->access_token));
  }

  if (oc_string(eventData->auth_provider)) {
    printf("AuthProvider : %s\n", oc_string(eventData->auth_provider));
  }

  if (oc_string(eventData->ci_server)) {
    printf("CI Server : %s\n", oc_string(eventData->ci_server));
  }

  if (eventData->userdata != NULL) {
    sc_cloud_server_conf_properties *data =
        (sc_cloud_server_conf_properties *)eventData->userdata;
    printf("[SC] ClientID : %s\n", data->client_id);
  }

  printf("[ES App] CloudDataProvCbInApp OUT\n");
}

es_provisioning_callbacks_s gCallbacks = {
    .wifi_prov_cb = &WiFiProvCbInApp,
    .dev_conf_prov_cb = &DevConfProvCbInApp,
    .cloud_data_prov_cb = &CloudDataProvCbInApp};

void StartEasySetup() {
  printf("[ES App] StartEasySetup IN\n");

  es_connect_type resourcemMask =
      ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE | ES_DEVCONF_RESOURCE;
  if (es_init_enrollee(gIsSecured, resourcemMask, gCallbacks) != ES_OK) {
    printf("[ES App] Easy Setup Enrollee init error!!\n");
    return;
  }

  printf("[ES App] ESInitEnrollee Success\n");

  // Set callbacks for Vendor Specific Properties
  es_set_callback_for_userdata(&sc_read_userdata_cb, &sc_write_userdata_cb,
                               &sc_free_userdata);
  printf("[ES App] StartEasySetup OUT\n");
}

void SetDeviceInfo() {
  printf("[ES App] SetDeviceInfo IN\n");
  char *device_name = "TEST_DEVICE";

  es_device_property deviceProperty = {
      .WiFi = {{WIFI_11G, WIFI_11N, WIFI_11AC, WiFi_EOF}, WIFI_5G},
      .DevConf = {{0}}};

  oc_new_string(&deviceProperty.DevConf.device_name, device_name,
                strlen(device_name));

  if (es_set_device_property(&deviceProperty) == ES_ERROR)
    printf("[ES App] ESSetDeviceProperty Error\n");

  // Set user properties if needed

  memset(&g_SCProperties, 0, sizeof(sc_properties));

  oc_new_string(&g_SCProperties.device_type, deviceType, strlen(deviceType));
  oc_new_string(&g_SCProperties.device_sub_type, deviceSubType,
                strlen(deviceSubType));
  g_SCProperties.net_conn_state = NET_STATE_INIT;
  g_SCProperties.disc_channel = WIFI_DISCOVERY_CHANNEL_INIT;
  oc_new_string(&g_SCProperties.reg_set_dev, regSetDev, strlen(regSetDev));
  oc_new_string(&g_SCProperties.net_prov_info, nwProvInfo, strlen(nwProvInfo));
  oc_new_string(&g_SCProperties.pnp_pin, pnpPin, strlen(pnpPin));
  oc_new_string(&g_SCProperties.model, modelNumber, strlen(modelNumber));
  oc_new_string(&g_SCProperties.es_protocol_ver, esProtocolVersion,
                strlen(esProtocolVersion));

  if (set_sc_properties(&g_SCProperties) == ES_ERROR)
    printf("SetSCProperties Error\n");

  printf("[ES App] SetDeviceInfo OUT\n");
}

void StopEasySetup() {
  printf("[ES App] StopEasySetup IN\n");
  if (reset_sc_properties() == ES_ERROR) {
    printf("Reset Properties Failed!!\n");
    return;
  }
  if (es_terminate_enrollee() == ES_ERROR) {
    printf("ESTerminateEnrollee Failed!!\n");
    return;
  }

  printf("[ES App] StopEasySetup OUT\n");
}

static void
scan_access_points(sec_accesspoint **ap_list) {
  if (!ap_list) {
    return;
  }

  // Fill scanned access points list
  sec_accesspoint *list_tail = NULL;
  int cnt=0;
  *ap_list = NULL;
  while(cnt++ < 3) {
    sec_accesspoint *ap = (sec_accesspoint *) calloc(1, sizeof(sec_accesspoint));

    char name[SSID_LEN];
    snprintf(name, SSID_LEN, "iot_home_%d", cnt);
    oc_new_string(&(ap->ssid), name, strlen(name));
    oc_new_string(&(ap->channel), "15", strlen("15"));
    oc_new_string(&(ap->enc_type), "AES", strlen("AES"));
    oc_new_string(&(ap->mac_address), "00:11:22:33:44:55", strlen("00:11:22:33:44:55"));
    oc_new_string(&(ap->max_rate), "0", strlen("0"));
    oc_new_string(&(ap->rssi), "33", strlen("33"));
    oc_new_string(&(ap->security_type), "WPA2-PSK", strlen("WPA2-PSK"));

    if (!*ap_list) {
      *ap_list = ap;
    } else {
      list_tail->next = ap;
    }
    list_tail = ap;
  }
}

static void register_resources(void) {
  printf("[ES App] register_resources IN\n");

  oc_resource_t *temp = oc_new_resource("tempsensor", "/temp", 1, 0);
  oc_resource_bind_resource_type(temp, "oic.r.temperature");
  oc_resource_bind_resource_interface(temp, OC_IF_A);
  oc_resource_bind_resource_interface(temp, OC_IF_S);
  oc_resource_set_default_interface(temp, OC_IF_A);
  oc_resource_set_discoverable(temp, true);
  oc_resource_set_periodic_observable(temp, 1);
  oc_resource_set_request_handler(temp, OC_GET, get_temp, NULL);
  oc_resource_set_request_handler(temp, OC_POST, post_temp, NULL);
  oc_add_resource(temp);

#ifdef OC_SECURITY
  gIsSecured = true;
#else
  gIsSecured = false;
#endif
  init_provisioning_info_resource(NULL);
  init_accesspointlist_resource(scan_access_points);
  StartEasySetup();
  SetDeviceInfo();
  SetProvInfo();
  printf("[ES App] register_resources OUT\n");
}

static void signal_event_loop(void) {
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void handle_signal(int signal) {
  (void)signal;
  signal_event_loop();
  quit = 1;
}

int main(void) {
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cv, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                           register_resources};

  oc_clock_time_t next_event;

  oc_set_mtu_size(2048);
  oc_set_max_app_data_size(8192);

#ifdef OC_SECURITY
  oc_storage_config("./smart_home_server_linux_creds");
#endif /* OC_SECURITY */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

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
  printf("[ES App] StopEasySetup..\n");
  StopEasySetup();
  deinit_provisioning_info_resource();
  deinit_accesspointlist_resource();
  printf("[ES App] StopEasySetup done\n");

  oc_main_shutdown();

  printf("[ES App] Exit..\n");
  return 0;
}
