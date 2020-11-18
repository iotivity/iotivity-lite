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

// Length defined as per GSMA LS to OCF
#define PROFILE_METADATA_LEN 2048
#define EUICC_INFO_LEN 1024
#define DEVICE_INFO_LEN 128

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

// WiFI Easy Setup Property Values
#define WES_EMPTY ""
#define WES_NONE "None"
#define WES_WIFI_MODE_A "A"
#define WES_WIFI_MODE_B "B"
#define WES_WIFI_MODE_G "G"
#define WES_WIFI_MODE_N "N"
#define WES_WIFI_MODE_AC "AC"
#define WES_WIFI_MODE_AD "AD"

#define WES_WIFI_FREQ_24G "2.4G"
#define WES_WIFI_FREQ_5G "5G"

#define WES_AUTH_NONE "None"
#define WES_AUTH_WEP "WEP"
#define WES_AUTH_WPA_PSK "WPA_PSK"
#define WES_AUTH_WPA2_PSK "WPA2_PSK"

#define WES_ENCRYPT_NONE "None"
#define WES_ENCRYPT_WEP_64 "WEP_64"
#define WES_ENCRYPT_WEP_128 "WEP_128"
#define WES_ENCRYPT_TKIP "TKIP"
#define WES_ENCRYPT_AES "AES"
#define WES_ENCRYPT_TKIP_AES "TKIP_AES"

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

#define EES_EMPTY ""
// Esim Easysetup procedure status
#define EES_PS_UNDEFINED "Undefined"
#define EES_PS_INITIATED "Initiated"
#define EES_PS_USER_CONF_PENDING "User confirmation pending"
#define EES_PS_USER_CONF_RECEIVED "Confirmation received"
#define EES_PS_DOWNLOADED "Downloaded"
#define EES_PS_INSTALLED "Installed"
#define EES_PS_ERROR "Error"
// Length of "User confirmation pending"
#define EES_MAX_NOTI_LEN 26

// End user confirmation status
#define EES_EUC_UNDEFINED "Undefined"
#define EES_EUC_TIMEOUT "Timeout"
#define EES_EUC_DOWNLOAD_REJECT "Download Reject"
#define EES_EUC_DOWNLOAD_POSTPONED "Download Postponed"
#define EES_EUC_DOWNLOAD_OK "Download OK"
#define EES_EUC_DOWNLOAD_ENABLE_OK "Download and Enable OK"

/**
 * @brief  Supported WI-FI frequency like 2.4G and 5G.
 */
typedef enum {
  WIFI_24G = 0,  // 2.4G
  WIFI_5G,       // 5G
  WIFI_FREQ_MAX = 2
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
  WIFI_MODE_MAX = 6
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
#define OC_RSRVD_WES_URI_EASYSETUP "/easysetup"
#define OC_RSRVD_WES_RES_TYPE_WIFICONF "oic.r.wificonf"
#define OC_RSRVD_WES_URI_WIFICONF "/wificonf"
#define OC_RSRVD_WES_RES_TYPE_DEVCONF "oic.r.devconf"
#define OC_RSRVD_WES_URI_DEVCONF "/devconf"

#define OC_RSRVD_EES_RES_TYPE_ESIMEASYSETUP "oic.r.esimeasysetup"
#define OC_RSRVD_EES_URI_ESIMEASYSETUP "/esimeasysetup"
#define OC_RSRVD_EES_RES_TYPE_RSPCONF "oic.r.rspconf"
#define OC_RSRVD_EES_URI_RSPCONF "/rspconf"
#define OC_RSRVD_EES_RES_TYPE_RSPCAP "oic.r.rspcapability"
#define OC_RSRVD_EES_URI_RSPCAP "/rspcapability"

#ifdef __cplusplus
}
#endif

#endif /* _ES_COMMON_H_ */
