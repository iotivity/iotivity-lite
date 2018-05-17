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

#include "st_easy_setup.h"
#include "oc_network_monitor.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

/** Note: Comment below line to test without Soft AP and automatic Wi-Fi
 * Connection. */
#define WITH_SOFTAP

typedef enum {
  ST_EASY_SETUP_DEV_PROV = 1 << 0,
  ST_EASY_SETUP_WIFI_PROV = 1 << 1,
  ST_EASY_SETUP_CLOUD_PROV = 1 << 2
} st_prov_step_t;

/**
 * @var g_is_secured
 * @brief Variable to check if secure mode is enabled or not.
 */
#ifdef OC_SECURITY
static bool g_is_secured = true;
#else  /* OC_SECURITY */
static bool g_is_secured = false;
#endif /* !OC_SECURITY */

static pthread_t soft_ap_thread;

static bool is_soft_ap_on = false;

static st_easy_setup_cb_t g_callback = NULL;

static st_easy_setup_status_t g_easy_setup_status = EASY_SETUP_INITIALIZE;

static es_coap_cloud_conf_data g_cloud_info;

static sc_coap_cloud_server_conf_properties g_st_cloud_info;

static bool is_have_st_cloud_info = false;

static sc_properties g_vendor_properties;

static st_prov_step_t g_prov_step_check;

static es_wifi_conf_data g_wifi_conf_data;

static void soft_ap_handler(void);
static void wifi_prov_cb(es_wifi_conf_data *event_data);
static void dev_conf_prov_cb(es_dev_conf_data *event_data);
static void cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data);
static bool is_easy_setup_step_done(void);
#ifdef WITH_SOFTAP
static void wifi_connection_handler(void *data);
#endif /* WITH_SOFTAP */

static es_provisioning_callbacks_s g_callbacks = {.wifi_prov_cb = wifi_prov_cb,
                                                  .dev_conf_prov_cb =
                                                    dev_conf_prov_cb,
                                                  .cloud_data_prov_cb =
                                                    cloud_conf_prov_cb };

bool
st_easy_setup_start(sc_properties *vendor_props, st_easy_setup_cb_t cb)
{
  printf("[Easy_Setup] st_easy_setup_start in\n");

  if (!cb) {
    return false;
  }

  es_connect_type resourcemMask =
    ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE | ES_DEVCONF_RESOURCE;
  if (es_init_enrollee(g_is_secured, resourcemMask, g_callbacks) != ES_OK) {
    printf("[Easy_Setup] es_init_enrollee error!\n");
    return false;
  }

  g_callback = cb;
  memset(&g_wifi_conf_data, 0, sizeof(es_wifi_conf_data));
  memset(&g_cloud_info, 0, sizeof(es_coap_cloud_conf_data));
  memset(&g_st_cloud_info, 0, sizeof(sc_coap_cloud_server_conf_properties));
  is_have_st_cloud_info = false;
  g_easy_setup_status = EASY_SETUP_PROGRESSING;
  printf("[Easy_Setup] es_init_enrollee Success\n");

#ifdef WITH_SOFTAP
  soft_ap_handler();
#endif /*WITH_SOFTAP */

  if (vendor_props) {
    memcpy(&g_vendor_properties, vendor_props, sizeof(sc_properties));
    if (set_sc_properties(&g_vendor_properties) == ES_ERROR) {
      printf("SetSCProperties Error\n");
      return false;
    }
  }

  // Set callbacks for Vendor Specific Properties
  es_set_callback_for_userdata(ReadUserdataCb, WriteUserdataCb, FreeUserdataCb);
  printf("[Easy_Setup] st_easy_setup_start out\n");

  return true;
}

void
st_easy_setup_stop(void)
{
  printf("[Easy_Setup] st_easy_setup_stop in\n");

  if (es_terminate_enrollee() == ES_ERROR) {
    printf("es_terminate_enrollee failed!\n");
    return;
  }

  g_callback = NULL;
  g_easy_setup_status = EASY_SETUP_INITIALIZE;
  g_prov_step_check = 0;
  es_set_state(ES_STATE_INIT);

  printf("[Easy_Setup] st_easy_setup_stop out\n");
}

st_easy_setup_status_t
get_easy_setup_status(void)
{
  return g_easy_setup_status;
}

es_coap_cloud_conf_data *
get_cloud_informations(void)
{
  if (g_easy_setup_status != EASY_SETUP_FINISH)
    return NULL;

  return &g_cloud_info;
}

sc_coap_cloud_server_conf_properties *
get_st_cloud_informations(void)
{
  if (g_easy_setup_status != EASY_SETUP_FINISH ||
      is_have_st_cloud_info == false)
    return NULL;

  return &g_st_cloud_info;
}

static oc_event_callback_retval_t
callback_handler(void *data)
{
  (void)data;
  if (g_callback)
    g_callback(g_easy_setup_status);
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
easy_setup_finish_handler(void *data)
{
  (void)data;
  if (is_easy_setup_step_done()) {
#ifdef WITH_SOFTAP
    printf("[Easy_Setup] Terminate Soft AP thread.\n");
    if (is_soft_ap_on) {
      pthread_cancel(soft_ap_thread);
      pthread_join(soft_ap_thread, NULL);
      is_soft_ap_on = false;
    }
    wifi_connection_handler(&g_wifi_conf_data);
#endif /* WITH_SOFTAP */
    g_easy_setup_status = EASY_SETUP_FINISH;
    oc_set_delayed_callback(NULL, callback_handler, 0);
  }
  return OC_EVENT_DONE;
}

static void
wifi_prov_cb(es_wifi_conf_data *event_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_WIFI_PROV)
    return;

  printf("[Easy_Setup] wifi_prov_cb in\n");

  es_set_state(ES_STATE_CONNECTING_TO_ENROLLER);

  if (event_data == NULL) {
    printf("[Easy_Setup] es_wifi_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  printf("[Easy_Setup] SSID : %s\n", oc_string(event_data->ssid));
  printf("[Easy_Setup] Password : %s\n", oc_string(event_data->pwd));
  printf("[Easy_Setup] AuthType : %d\n", event_data->authtype);
  printf("[Easy_Setup] EncType : %d\n", event_data->enctype);

  if (event_data->userdata) {
    sc_wifi_conf_properties *data = event_data->userdata;
    printf("[Easy_Setup] DiscoveryChannel : %d\n", data->discoveryChannel);
  }

  memcpy(&g_wifi_conf_data, event_data, sizeof(es_wifi_conf_data));
  oc_new_string(&g_wifi_conf_data.ssid,oc_string(event_data->ssid),oc_string_len(event_data->ssid));
  oc_new_string(&g_wifi_conf_data.pwd,oc_string(event_data->pwd),oc_string_len(event_data->pwd));

  g_prov_step_check |= ST_EASY_SETUP_WIFI_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  printf("[Easy_Setup] wifi_prov_cb out\n");
}

static void
dev_conf_prov_cb(es_dev_conf_data *event_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_DEV_PROV)
    return;

  printf("[Easy_Setup] dev_conf_prov_cb in\n");

  if (event_data == NULL) {
    printf("[Easy_Setup] es_dev_conf_data is NULL\n");
    return;
  }

  if (event_data->userdata) {
    sc_dev_conf_properties *data = event_data->userdata;

    if (!oc_string(data->country))
      return;

    for (uint8_t i = 0; i < oc_string_array_get_allocated_size(data->location); ++i) {
      printf("[Easy_Setup] Location : %s\n",
             oc_string_array_get_item(data->location, i));
    }
    printf("[Easy_Setup] Register Mobile Device : %s\n",
           oc_string(data->regMobileDev));
    printf("[Easy_Setup] Country : %s\n", oc_string(data->country));
    printf("[Easy_Setup] Language : %s\n", oc_string(data->language));
    printf("[Easy_Setup] GPS Location : %s\n", oc_string(data->gpsLocation));
    printf("[Easy_Setup] UTC Date time : %s\n", oc_string(data->utcDateTime));
    printf("[Easy_Setup] Regional time : %s\n",
           oc_string(data->regionalDateTime));
    printf("[Easy_Setup] SSO List : %s\n", oc_string(data->ssoList));
  }

  g_prov_step_check |= ST_EASY_SETUP_DEV_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  printf("[Easy_Setup] dev_conf_prov_cb out\n");
}

static void
cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_CLOUD_PROV)
    return;

  printf("[Easy_Setup] cloud_conf_prov_cb in\n");

  if (event_data == NULL) {
    printf("es_coap_cloud_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  if (oc_string(event_data->auth_code)) {
    printf("[Easy_Setup] AuthCode : %s\n", event_data->auth_code);
  }

  if (oc_string(event_data->access_token)) {
    printf("[Easy_Setup] Access Token : %s\n", event_data->access_token);
  }

  if (oc_string(event_data->auth_provider)) {
    printf("[Easy_Setup] AuthProvider : %s\n", event_data->auth_provider);
  }

  if (oc_string(event_data->ci_server)) {
    printf("[Easy_Setup] CI Server : %s\n", event_data->ci_server);
  }

  if (event_data->userdata) {
    sc_coap_cloud_server_conf_properties *data = event_data->userdata;
    printf("[Easy_Setup] ClientID : %s\n", oc_string(data->clientID));
    printf("[Easy_Setup] uid : %s\n", oc_string(data->uid));
    printf("[Easy_Setup] Refresh token : %s\n", oc_string(data->refreshToken));
    memcpy(&g_st_cloud_info, data,
           sizeof(sc_coap_cloud_server_conf_properties));
    is_have_st_cloud_info = true;
  }

  memcpy(&g_cloud_info, event_data, sizeof(es_coap_cloud_conf_data));

  g_prov_step_check |= ST_EASY_SETUP_CLOUD_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  printf("[Easy_Setup] cloud_conf_prov_cb out\n");
}

static bool
is_easy_setup_step_done(void)
{
  if (g_prov_step_check & ST_EASY_SETUP_DEV_PROV &&
      g_prov_step_check & ST_EASY_SETUP_WIFI_PROV &&
      g_prov_step_check & ST_EASY_SETUP_CLOUD_PROV) {
    return true;
  }
  return false;
}

#ifdef WITH_SOFTAP
static bool
execute_command(const char *cmd, char *result, int result_len)
{
  char buffer[128];
  FILE *fp = popen(cmd, "r");

  if (!fp) {
    return false;
  }

  int add_len = 0;
  while (!feof(fp)) {
    if (fgets(buffer, 128, fp) != NULL) {
      add_len += strlen(buffer);

      if (add_len < result_len) {
        strcat(result, buffer);
      }
    }
  }

  fclose(fp);
  return true;
}

static void
wifi_connection_handler(void *data)
{
  printf("[Easy_Setup] wifi_connection_handler in\n");
  es_wifi_conf_data *wifi_data = (es_wifi_conf_data *)data;
  char *ssid = oc_string(wifi_data->ssid);
  char *pwd = oc_string(wifi_data->pwd);

  /** Sleep to allow response sending from post_callback thread before turning
   * Off Soft AP. */
  sleep(1);

  printf("[Easy_Setup] target ap ssid: %s\n", ssid);
  printf("[Easy_Setup] password: %s\n", pwd);

  char result[256];

  /** Stop Soft AP */
  printf("[Easy_Setup] Stopping Soft AP\n");
  execute_command("sudo service hostapd stop", result, 256);
  printf("[Easy_Setup] result : %s\n", result);

  /** Turn On Wi-Fi */
  printf("[Easy_Setup] Turn on the AP\n");
  execute_command("sudo nmcli radio wifi on", result, 256);
  printf("[Easy_Setup] result : %s\n", result);

  /** On some systems it may take time for Wi-Fi to turn ON. */
  sleep(3);

  /** Connect to Target Wi-Fi AP */
  printf("[Easy_Setup] connect to %s AP.\n", ssid);
  char nmcli_command[256];
  sprintf(nmcli_command, "nmcli d wifi connect %s password %s", ssid, pwd);
  printf("[Easy_Setup] $ %s\n", nmcli_command);
  execute_command(nmcli_command, result, 256);
  printf("[Easy_Setup] result : %s\n", result);

  if (strlen(result) == 0) {
    es_set_state(ES_STATE_CONNECTED_TO_ENROLLER);
    es_set_error_code(ES_ERRCODE_NO_ERROR);
  }

  printf("[Easy_Setup] wifi_connection_handler out\n");
}

static void *
soft_ap_process_routine(void *data)
{
  (void)data;

  printf("[Easy_Setup] soft_ap_handler in\n");
  char result[256];

  /** Stop AP */
  printf("[Easy_Setup] Stopping AP\n");
  execute_command("sudo nmcli radio wifi off", result, 256);
  execute_command("sudo rfkill unblock wlan", result, 256);
  printf("[Easy_Setup] result : %s\n", result);

  /** Turn On Wi-Fi interface */
  printf("[Easy_Setup] Turn on the wifi interface\n");
  execute_command("sudo ifconfig wlx00259ce05a49 10.0.0.2/24 up", result, 256);
  printf("[Easy_Setup] result : %s\n", result);

  /** On some systems it may take time for Wi-Fi to turn ON. */
  sleep(1);
  printf("[Easy_Setup] $ sudo service dnsmasq restart\n");
  execute_command("sudo service dnsmasq restart", result, 256);
  printf("[Easy_Setup] result : %s\n", result);
  sleep(1);
  printf("[Easy_Setup] $ sudo service radvd restart\n");
  execute_command("sudo service radvd restart", result, 256);
  printf("[Easy_Setup] result : %s\n", result);
  sleep(1);
  printf("[Easy_Setup] $ sudo service hostapd start\n");
  execute_command("sudo service hostapd start", result, 256);
  printf("[Easy_Setup] result : %s\n", result);
  sleep(1);
  printf("[Easy_Setup] $ sudo hostapd /etc/hostapd/hostapd.conf\n");
  execute_command("sudo hostapd /etc/hostapd/hostapd.conf", result, 256);

  printf("[Easy_Setup] $ Soft ap is off\n");
  is_soft_ap_on = false;

  pthread_exit(NULL);
}

static void
soft_ap_handler(void)
{
  printf("soft_ap_handler IN\n");
  is_soft_ap_on = true;
  pthread_create(&soft_ap_thread, NULL, soft_ap_process_routine, NULL);
}
#endif /* WITH_SOFTAP */
