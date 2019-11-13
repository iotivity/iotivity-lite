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
#ifndef _ES_COMMON_H_
#define _ES_COMMON_H_

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif


#define OC_STRING_MAX_VALUE 128
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
 // WiFi Easy Setup
#define OC_RSRVD_WES_PROVSTATUS "ps"
#define OC_RSRVD_WES_LAST_ERRORCODE "lec"
#define OC_RSRVD_WES_CONNECT "cn"
#define OC_RSRVD_WES_LINKS "links"
// WiFi Conf
#define OC_RSRVD_WES_SUPPORTEDWIFIMODE "swmt"
#define OC_RSRVD_WES_SUPPORTEDWIFIFREQ "swf"
#define OC_RSRVD_WES_SSID "tnn"
#define OC_RSRVD_WES_CRED "cd"
#define OC_RSRVD_WES_AUTHTYPE "wat"
#define OC_RSRVD_WES_ENCTYPE "wet"
#define OC_RSRVD_WES_SUPPORTEDWIFIAUTHTYPE "swat"
#define OC_RSRVD_WES_SUPPORTEDWIFIENCTYPE "swet"
// Device Conf
#define OC_RSRVD_WES_DEVNAME "dn"

 // Esim Easy Setup
#define OC_RSRVD_EES_PROVSTATUS "ps"
#define OC_RSRVD_EES_LASTERRORREASON "ler"
#define OC_RSRVD_EES_LASTERRORCODE "lec"
#define OC_RSRVD_EES_LASTERRORRDESCRIPTION "led"
#define OC_RSRVD_EES_ENDUSERCONFIRMATION "euc"
#define OC_RSRVD_EES_LINKS "links"
// RSP Conf
#define OC_RSRVD_EES_ACTIVATIONCODE "ac"
#define OC_RSRVD_EES_PROFMETADATA "pm"
#define OC_RSRVD_EES_CONFIRMATIONCODE "cc"
#define OC_RSRVD_EES_CONFIRMATIONCODEREQUIRED "ccr"
// RSP Cap Conf
#define OC_RSRVD_EES_EUICCINFO "euiccinfo"
#define OC_RSRVD_EES_DEVICEINFO "deviceinfo"

// Esim Easysetup procedure status
#define EES_PS_NONE "None"
#define EES_PS_INITED "Inited"
#define EES_PS_USER_CONF_PENDING "User_Confirmation_Pending"
#define EES_PS_CONFIRM_RECEIVED "User_Confirmation_Received"
#define EES_PS_DOWNLOADED "Profile_Downloaded"
#define EES_PS_INSTALLED "Profile_Installed"
#define EES_PS_ERROR "Error"

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
  WIFI_EOF = 999
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

typedef enum {
  RSP_NONE = 0,
  RSP_INITIATED,
  USER_CONF_PENDING,
  PROFILE_DOWNLOADED,
  PROFILE_INSTALLED,
  RSP_ERROR
} rsp_state;

typedef enum {
  EUC_NONE = 0,
  NO_INPUT,
  DOWNLOAD_REJECTED,
  DONALOAD_POSTPONED,
  DOWNLOAD_OK,
  DOWNLOAD_ENABLE_OK
} user_confirmation;

/**
 * Easysetup defined resoruce types and uris.
 */
#define OC_RSRVD_WES_RES_TYPE_EASYSETUP "oic.r.easysetup"
#define OC_RSRVD_WES_URI_EASYSETUP "/EasySetupResURI"
#define OC_RSRVD_WES_RES_TYPE_WIFICONF "oic.r.wificonf"
#define OC_RSRVD_WES_URI_WIFICONF "/WiFiConfResURI"
#define OC_RSRVD_WES_RES_TYPE_DEVCONF "oic.r.devconf"
#define OC_RSRVD_WES_URI_DEVCONF "/DevConfResURI"

#define OC_RSRVD_EES_RES_TYPE_ESIMEASYSETUP "oic.r.esimeasysetup"
#define OC_RSRVD_EES_URI_ESIMEASYSETUP "/EsimEasySetupResURI"
#define OC_RSRVD_EES_RES_TYPE_RSPCONF "oic.r.rspconf"
#define OC_RSRVD_EES_URI_RSPCONF "/RSPConfResURI"
#define OC_RSRVD_EES_RES_TYPE_RSPCAPCONF "oic.r.rspcapabilityconf"
#define OC_RSRVD_EES_URI_RSPCAPCONF "/RSPCapabilityConfResURI"

#ifdef __cplusplus
}
#endif

#endif /* _ES_COMMON_H_ */
