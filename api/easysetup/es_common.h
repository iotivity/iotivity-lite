/****************************************************************************
 *
 * Copyright (c) 2019 Samsung Electronics
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
#ifndef _ES_COMMON_H_
#define _ES_COMMON_H_

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif


#define OC_STRING_MAX_VALUE 64
#define OC_URI_STRING_MAX_VALUE 256
#define MAX_WEBLINKLEN 3
#define NUM_WIFIMODE 10
#define NUM_WIFIFREQ 5
#define NUM_CONNECT_TYPE 4
#define NUM_WIFIAUTHTYPE 4
#define NUM_WIFIENCTYPE 6

/**
 * Attributes used to form a proper easysetup conforming JSON message.
 */
 // Easy Setup
#define OC_RSRVD_ES_PROVSTATUS "ps"
#define OC_RSRVD_ES_LAST_ERRORCODE "lec"
#define OC_RSRVD_ES_CONNECT "cn"
#define OC_RSRVD_ES_LINKS "links"
// WiFi Conf
#define OC_RSRVD_ES_SUPPORTEDWIFIMODE "swmt"
#define OC_RSRVD_ES_SUPPORTEDWIFIFREQ "swf"
#define OC_RSRVD_ES_SSID "tnn"
#define OC_RSRVD_ES_CRED "cd"
#define OC_RSRVD_ES_AUTHTYPE "wat"
#define OC_RSRVD_ES_ENCTYPE "wet"
#define OC_RSRVD_ES_SUPPORTEDWIFIAUTHTYPE "swat"
#define OC_RSRVD_ES_SUPPORTEDWIFIENCTYPE "swet"
// Device Conf
#define OC_RSRVD_ES_DEVNAME "dn"
// RSP Conf
#define OC_RSRVD_ES_ACTIVATIONCODE "ac"
// RSP Cap Conf
#define OC_RSRVD_ES_EUICCINFO "euiccinfo"
#define OC_RSRVD_ES_DEVICEINFO "deviceinfo"

/**
 * @brief  Supported WI-FI frequency like 2.4G and 5G.
 */
typedef enum {
  WIFI_24G = 0,  // 2.4G
  WIFI_5G,       // 5G
  WIFI_BOTH,     // 2.4G and 5G
  WIFI_FREQ_NONE // EOF
} wifi_freq;

/**
 * @brief  Supported WI-FI mode like 802.11g and 802.11n.
 */
typedef enum {
  WIFI_11A = 0, // 802.11a
  WIFI_11B,     // 802.11b
  WIFI_11G,     // 802.11g
  WIFI_11N,     // 802.11n
  WIFI_11AC,    // 802.11ac
  WIFI_11AD,    // 802.11ad
  WiFi_EOF = 999
} wifi_mode;

/**
 * @brief  WI-FI Authentication tlype of the Enroller.
 */
typedef enum {
  NONE_AUTH = 0, // NO authentication
  WEP,           // WEP
  WPA_PSK,       // WPA-PSK
  WPA2_PSK       // WPA2-PSK
} wifi_authtype;

/**
 * @brief  WI-FI encryption type of the Enroller.
 */
typedef enum {
  NONE_ENC = 0, // NO encryption
  WEP_64,       // WEP-64
  WEP_128,      // WEP-128
  TKIP,         // TKIP
  AES,          // AES
  TKIP_AES      // TKIP-AES
} wifi_enctype;

/**
 * Easysetup defined resoruce types and uris.
 */
#define OC_RSRVD_ES_RES_TYPE_EASYSETUP "oic.r.easysetup"
#define OC_RSRVD_ES_URI_EASYSETUP "/EasySetupResURI"
// For Wi-Fi provisioning
#define OC_RSRVD_ES_RES_TYPE_WIFICONF "oic.r.wificonf"
#define OC_RSRVD_ES_URI_WIFICONF "/WiFiConfResURI"
#define OC_RSRVD_ES_RES_TYPE_DEVCONF "oic.r.devconf"
#define OC_RSRVD_ES_URI_DEVCONF "/DevConfResURI"
// for eSIM provisioning
#define OC_RSRVD_ES_RES_TYPE_RSPCONF "oic.r.rspconf"
#define OC_RSRVD_ES_URI_RSPCONF "/RSPConfResURI"
#define OC_RSRVD_ES_RES_TYPE_RSPCAPCONF "oic.r.rspcapabilityconf"
#define OC_RSRVD_ES_URI_RSPCAPCONF "/RSPCapabilityConfResURI"

#ifdef __cplusplus
}
#endif

#endif /* _ES_COMMON_H_ */
