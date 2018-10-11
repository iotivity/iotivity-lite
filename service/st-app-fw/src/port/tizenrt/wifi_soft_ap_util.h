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

#ifndef ST_WIFI_SOFT_AP_UTIL_H
#define ST_WIFI_SOFT_AP_UTIL_H

#include <slsi_wifi/slsi_wifi_api.h>
#include <stdint.h>

int es_create_softap(const char *ssid, const char *passwd);

void es_stop_softap(void);

int dhcpserver_start(void);
int wifi_start_station(void);
int wifi_join(const char *ssid, const char *security, const char *passwd);
int dhcpc_start(void);

#define SLSI_WIFI_SECURITY_OPEN "open"
#define SLSI_WIFI_SECURITY_WEP_OPEN "wep"
#define SLSI_WIFI_SECURITY_WEP_SHARED "wep_shared"
#define SLSI_WIFI_SECURITY_WPA_MIXED "wpa_mixed"
#define SLSI_WIFI_SECURITY_WPA_TKIP "wpa_tkip"
#define SLSI_WIFI_SECURITY_WPA_AES "wpa_aes"
#define SLSI_WIFI_SECURITY_WPA2_MIXED "wpa2_mixed"
#define SLSI_WIFI_SECURITY_WPA2_TKIP "wpa2_tkip"
#define SLSI_WIFI_SECURITY_WPA2_AES "wpa2_aes"
#define SLSI_WIFI_SECURITY_WPA_PSK "wpa_psk"
#define SLSI_WIFI_SECURITY_WPA2_PSK "wpa2_psk"

enum wifi_state
{
  WIFI_CONNECTED,
  WIFI_DISCONNECTED,
};

#endif /* ST_WIFI_SOFT_AP_UTIL_H */
