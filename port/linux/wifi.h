/****************************************************************************
 *
 * Copyright (c) 2019-2020 Samsung Electronics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#ifndef _WIFI_H_
#define _WIFI_H_

#define MAX_LEN_SSID 32
#define MAX_LEN_PSK 32

struct wpa_ssid {
  char ssid[MAX_LEN_SSID];
  char psk[MAX_LEN_PSK];
  enum wpas_mode {
          WPAS_MODE_INFRA = 0,
          WPAS_MODE_IBSS = 1,
          WPAS_MODE_AP = 2,
          WPAS_MODE_P2P_GO = 3,
          WPAS_MODE_P2P_GROUP_FORMATION = 4,
          WPAS_MODE_MESH = 5,
  } mode;
  char *key_mgmt;
};

#ifdef LIB_DBUS_GLIB
int wifi_start_station(void);
int wifi_stop_station(void);
int wifi_start_softap(char *ssid, char *psk);
int wifi_stop_softap();
int wifi_join(char *ssid, char *password);
int wifi_start_dhcp_client();
int wifi_stop_dhcp_client();
int wifi_start_dhcp_server();
int wifi_stop_dhcp_server();
#else
static inline int wifi_start_station(void){
  return 0;
}
static inline int wifi_stop_station(void){
  return 0;
}
static inline int wifi_start_softap(char *ssid, char *psk){
  (void)(*ssid);
  (void)(*psk);
  return 0;
}
static inline int wifi_stop_softap(){
  return 0;
}
static inline int wifi_join(char *ssid, char *password){
  (void)(*ssid);
  (void)(*password);
  return 0;
}
static inline int wifi_start_dhcp_client(){
  return 0;
}
static inline int wifi_stop_dhcp_client(){
  return 0;
}
static inline int wifi_start_dhcp_server(){
  return 0;
}
static inline int wifi_stop_dhcp_server(){
  return 0;
}
#endif //LIB_DBUS_GLIB

#endif //_WIFI_H_
