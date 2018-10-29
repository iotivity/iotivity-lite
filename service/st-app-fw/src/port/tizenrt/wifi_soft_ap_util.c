/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#include <stdio.h>
#include "wifi_soft_ap_util.h"

static wifi_manager_softap_config_s g_ap_config;
static wifi_manager_ap_config_s g_homeap_info;

wifi_manager_softap_config_s *get_softap_wifi_config(char *ssid, char *passwd)
{
  char easysetup_softap_ssid[34];

  /* TODO: Changed the logic to use the values from JSON file */
  char easysetup_tag[] = "E1";
  char manufacturer_name[] = "fAMt";
  char setup_id[] = "001";
  int ssid_type = 0;
  int easysetup_softap_channel = 1;

  char ext_value[9] = { 0, };
  memset(ext_value, 0, sizeof(ext_value));

  wifi_manager_info_s st_wifi_info;
  wifi_manager_get_info(&st_wifi_info);

  snprintf(ext_value, sizeof(ext_value), "%02X%02X", st_wifi_info.mac_address[4], st_wifi_info.mac_address[5]);

  snprintf(easysetup_softap_ssid, sizeof(easysetup_softap_ssid), "%s_%s%s%s%d%s", ssid, easysetup_tag, manufacturer_name, setup_id, ssid_type, ext_value);
  st_print_log("SoftAP SSID : %s\n", easysetup_softap_ssid);

  snprintf(g_ap_config.ssid, sizeof(g_ap_config.ssid), "%s", easysetup_softap_ssid);
  snprintf(g_ap_config.passphrase, sizeof(g_ap_config.passphrase), "%s", passwd);
  g_ap_config.channel = easysetup_softap_channel;

  return &g_ap_config;
}

int
es_create_softap(const char *ssid, const char *passwd)
{
  st_print_log("es_create_softap in\n");
  wifi_manager_info_s info;
  wifi_manager_get_info(&info);
  wifi_manager_remove_config();
  if (info.mode != SOFTAP_MODE) {
    wifi_manager_softap_config_s *ap_config = get_softap_wifi_config(ssid, passwd);
    if (wifi_manager_set_mode(SOFTAP_MODE, ap_config) != WIFI_MANAGER_SUCCESS) {
      printf("Failed to change to SOFTAP mode\n");
      return false;
    }
  }
  st_print_log("In SOFTAP mode\n");

  st_print_log("es_create_softap out\n");
  return 0;
}

int
es_stop_softap(void)
{
  st_print_log("es_stop_softap in\n");
  wifi_manager_result_e result = WIFI_MANAGER_SUCCESS;
  wifi_manager_info_s info;
  wifi_manager_get_info(&info);

  if (info.mode == SOFTAP_MODE) {
    if (wifi_manager_set_mode(STA_MODE, NULL) != WIFI_MANAGER_SUCCESS) {
      st_print_log("Failed to change to STA mode\n");
      return -1;
    }
    usleep(100000);
  }
  st_print_log("es_stop_softap out\n");
  return 0;
}

wifi_manager_ap_config_s *get_homeap_wifi_config(void)
{
  wifi_manager_result_e res = wifi_manager_get_config(&g_homeap_info);

  if (res != WIFI_MANAGER_SUCCESS) {
    st_print_log("Get AP configuration failed [error code : %d]\n", res);
  } else {
    st_print_log("[WIFI] Saved SSID : %s\n", g_homeap_info.ssid);
  }
  return &g_homeap_info;
}

bool try_connect_home_ap(wifi_manager_ap_config_s *connect_config)
{
  if (connect_config != NULL && connect_config->ssid != NULL) {
    st_print_log("Try_connect_home_ap [ssid : %s]\n", connect_config->ssid);
  }

  wifi_manager_result_e result = WIFI_MANAGER_SUCCESS;
  int retry_count = 0;
  for (; retry_count < 3; retry_count++) {
    result = wifi_manager_connect_ap(connect_config);

    if (result == WIFI_MANAGER_SUCCESS) {
      break;
    } else {
      st_print_log("Failed to connect WiFi [Error Code : %d, Retry count : %d]\n", result, retry_count);
    }
  }

  if (retry_count == 3) {
    st_print_log("Failed to connect WiFi 3 times\n");
    return false;
  }

  return true;
}

int
wifi_join(const char *ssid, const char *auth_type, const char *enc_type, const char *passwd)
{
  st_print_log("wifi_join in\n");
  wifi_manager_ap_config_s connect_config;

  strncpy(connect_config.ssid, ssid, sizeof(connect_config.ssid));
  connect_config.ssid_length = strlen(connect_config.ssid);
  strncpy(connect_config.passphrase, passwd, sizeof(connect_config.passphrase));

  connect_config.passphrase_length = strlen(connect_config.passphrase);

  st_print_log("[%s] ssid : %s\n", __FUNCTION__, connect_config.ssid);

  // set auth type
  if (strncmp(auth_type, "WEP", strlen("WEP")) == 0) {
    connect_config.ap_auth_type = WIFI_MANAGER_AUTH_WEP_SHARED;
  } else if (strncmp(auth_type, "WPA-PSK", strlen("WPA-PSK")) == 0) {
    connect_config.ap_auth_type = WIFI_MANAGER_AUTH_WPA_PSK;
  } else if (strncmp(auth_type, "WPA2-PSK", strlen("WPA2-PSK")) == 0) {
    connect_config.ap_auth_type = WIFI_MANAGER_AUTH_WPA2_PSK;
  }

  // set encryption crypto type
  if (strncmp(enc_type, "WEP-64", strlen("WEP-64")) == 0) {
    connect_config.ap_crypto_type = WIFI_MANAGER_CRYPTO_WEP_64;
  } else if (strncmp(enc_type, "WEP-128", strlen("WEP-128")) == 0) {
    connect_config.ap_crypto_type = WIFI_MANAGER_CRYPTO_WEP_128;
  } else if (strncmp(enc_type, "TKIP", strlen("TKIP")) == 0) {
    connect_config.ap_crypto_type = WIFI_MANAGER_CRYPTO_TKIP;
  } else if (strncmp(enc_type, "AES", strlen("AES")) == 0) {
    connect_config.ap_crypto_type = WIFI_MANAGER_CRYPTO_AES;
  } else if (strncmp(enc_type, "TKIP_AES", strlen("TKIP_AES")) == 0) {
    connect_config.ap_crypto_type = WIFI_MANAGER_CRYPTO_TKIP_AND_AES;
  }

  wifi_manager_result_e res = wifi_manager_save_config(&connect_config);

  if (res != WIFI_MANAGER_SUCCESS) {
    st_print_log("Failed to save AP configuration : [%d]\n", res);
    return -1;
  } else {
    st_print_log("Success to save AP configuration\n");
  }

  wifi_manager_ap_config_s *ap_config = get_homeap_wifi_config();
  if (!try_connect_home_ap(ap_config)) {
    return -1;
  }

  st_print_log("wifi_join out\n");
  return 0;
}
