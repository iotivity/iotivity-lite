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
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

/** Note: Comment below line to test without Soft AP and automatic Wi-Fi
 * Connection. */
#define WITH_SOFTAP

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

static void soft_ap_handler(void);
static void wifi_prov_cb(es_wifi_conf_data *event_data);
static void dev_conf_prov_cb(es_dev_conf_data *event_data);
static void cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data);
static void read_user_data_cb(oc_rep_t *payload, char *resourceType,
                              void **userdata);
static void write_user_data_cb(oc_rep_t *payload, char *resourceType);
#ifdef WITH_SOFTAP
static oc_event_callback_retval_t wifi_connection_handler(void *data);
#endif /* WITH_SOFTAP */

static es_provisioning_callbacks_s g_callbacks = {.wifi_prov_cb = wifi_prov_cb,
                                                  .dev_conf_prov_cb =
                                                    dev_conf_prov_cb,
                                                  .cloud_data_prov_cb =
                                                    cloud_conf_prov_cb };

bool
st_easy_setup_start(st_easy_setup_cb_t cb)
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
  memset(&g_cloud_info, 0, sizeof(es_coap_cloud_conf_data));
  g_easy_setup_status = EASY_SETUP_PROGRESSING;
  printf("[Easy_Setup] es_init_enrollee Success\n");

#ifdef WITH_SOFTAP
  soft_ap_handler();
#endif /*WITH_SOFTAP */

  // Set callbacks for Vendor Specific Properties
  es_set_callback_for_userdata(read_user_data_cb, write_user_data_cb);
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

static oc_event_callback_retval_t
callback_handler(void *data)
{
  (void)data;
  if (g_callback)
    g_callback(g_easy_setup_status);
  return OC_EVENT_DONE;
}

static void
wifi_prov_cb(es_wifi_conf_data *event_data)
{
  printf("[Easy_Setup] wifi_prov_cb in\n");

  es_set_state(ES_STATE_CONNECTING_TO_ENROLLER);

  if (event_data == NULL) {
    printf("[Easy_Setup] es_wifi_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  printf("SSID : %s\n", event_data->ssid);
  printf("Password : %s\n", event_data->pwd);
  printf("AuthType : %d\n", event_data->authtype);
  printf("EncType : %d\n", event_data->enctype);

#ifdef WITH_SOFTAP
  printf("Terminate Soft AP thread.\n");
  if (is_soft_ap_on) {
    pthread_cancel(soft_ap_thread);
    pthread_join(soft_ap_thread, NULL);
    is_soft_ap_on = false;
  }
  es_wifi_conf_data *wifi_conf_data =
    (es_wifi_conf_data *)calloc(1, sizeof(es_wifi_conf_data));

  memcpy(wifi_conf_data, event_data, sizeof(es_wifi_conf_data));

  oc_set_delayed_callback(wifi_conf_data, wifi_connection_handler, 0);
#endif /* WITH_SOFTAP */

  printf("[Easy_Setup] wifi_prov_cb out\n");
}

static void
dev_conf_prov_cb(es_dev_conf_data *event_data)
{
  printf("[Easy_Setup] dev_conf_prov_cb in\n");

  if (event_data == NULL) {
    printf("[Easy_Setup] es_dev_conf_data is NULL\n");
    return;
  }

  printf("[Easy_Setup] dev_conf_prov_cb out\n");
}

static void
cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data)
{
  printf("[Easy_Setup] cloud_conf_prov_cb in\n");

  if (event_data == NULL) {
    printf("es_coap_cloud_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  if (event_data->auth_code) {
    printf("AuthCode : %s\n", event_data->auth_code);
  }

  if (event_data->access_token) {
    printf("Access Token : %s\n", event_data->access_token);
  }

  if (event_data->auth_provider) {
    printf("AuthProvider : %s\n", event_data->auth_provider);
  }

  if (event_data->ci_server) {
    printf("CI Server : %s\n", event_data->ci_server);
  }

  memcpy(&g_cloud_info, event_data, sizeof(es_coap_cloud_conf_data));
  g_easy_setup_status = EASY_SETUP_FINISH;
  oc_set_delayed_callback(NULL, callback_handler, 0);

  printf("[Easy_Setup] cloud_conf_prov_cb out\n");
}

static void
read_user_data_cb(oc_rep_t *payload, char *resourceType, void **userdata)
{
  (void)payload;
  (void)resourceType;
  (void)userdata;
}

static void
write_user_data_cb(oc_rep_t *payload, char *resourceType)
{
  (void)resourceType;
  (void)payload;
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

static oc_event_callback_retval_t
wifi_connection_handler(void *data)
{
  printf("[Easy_Setup] wifi_connection_handler in\n");
  es_wifi_conf_data *wifi_data = (es_wifi_conf_data *)data;
  char *ssid = wifi_data->ssid;
  char *pwd = wifi_data->pwd;

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
  sleep(1);

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

  free(wifi_data);
  wifi_data = NULL;

  printf("[Easy_Setup] wifi_connection_handler out\n");
  return OC_EVENT_DONE;
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