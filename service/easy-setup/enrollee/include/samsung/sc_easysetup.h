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

#include "easysetup.h"
#include "es_common.h"

#ifndef EASYSETUPX_ENROLLEE_H__
#define EASYSETUPX_ENROLLEE_H__

#define MAXLEN_STRING 1000
#define MAXNUM_LOCATION 20
#define MAXLEN_DATE_TIME 33


#define STR_SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE  "x.com.samsung.ncs"
#define STR_SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL    "x.com.samsung.chn"
#define STR_SC_RSRVD_ES_VENDOR_DEVICE_TYPE          "x.com.samsung.dt"
#define STR_SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE       "x.com.samsung.sdt"
#define STR_SC_RSRVD_ES_VENDOR_LOCATION             "x.com.samsung.location"
#define STR_SC_RSRVD_ES_VENDOR_CLIENTID             "x.com.samsung.clientid"
#define STR_SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV  "x.com.samsung.rmd"
#define STR_SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV     "x.com.samsung.rsd"
#define STR_SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO    "x.com.samsung.npi"
#define STR_SC_RSRVD_ES_VENDOR_ACCOUNT              "x.com.samsung.account"
#define STR_SC_RSRVD_ES_VENDOR_SSO_LIST             "x.com.samsung.ssolist"
#define STR_SC_RSRVD_ES_VENDOR_AAC                  "x.com.samsung.aac"
#define STR_SC_RSRVD_ES_VENDOR_TNC_HEADER           "x.com.samsung.tcheader"
#define STR_SC_RSRVD_ES_VENDOR_TNC_VERSION          "x.com.samsung.tcversion"
#define STR_SC_RSRVD_ES_VENDOR_TNC_RESULT           "x.com.samsung.tcresult"
#define STR_SC_RSRVD_ES_VENDOR_TNC_STATUS           "x.com.samsung.tcstatus"
#define STR_SC_RSRVD_ES_VENDOR_REFRESH_TOKEN        "x.com.samsung.refreshtoken"
#define STR_SC_RSRVD_ES_VENDOR_UID                  "x.com.samsung.uid"
#define STR_SC_RSRVD_ES_VENDOR_BSSID                "x.com.samsung.bssid"
#define STR_SC_RSRVD_ES_VENDOR_PNP_PIN              "x.com.samsung.pnppin"
#define STR_SC_RSRVD_ES_VENDOR_MODEL_NUMBER         "x.com.samsung.modelnumber"
#define STR_SC_RSRVD_ES_VENDOR_LANGUAGE             "x.com.samsung.language"
#define STR_SC_RSRVD_ES_VENDOR_COUNTRY              "x.com.samsung.country"
#define STR_SC_RSRVD_ES_VENDOR_GPSLOCATION          "x.com.samsung.gpslocation"
#define STR_SC_RSRVD_ES_VENDOR_UTC_DATE_TIME        "x.com.samsung.datetime"
#define STR_SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME   "x.com.samsung.regionaldatetime"
#define STR_SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION  "x.com.samsung.espv"

#define SC_RSRVD_ES_RES_TYPE_PROVISIONING_INFO                   "x.com.samsung.provisioninginfo"
#define SC_RSRVD_ES_URI_PROVISIONING_INFO                        "/sec/provisioninginfo"

#define WIFI_DISCOVERY_CHANNEL_INIT             -1
#define MAXIMUM_TARGETS                          20
/**
 * @brief  Supported WIFI frequency like 2.4G and 5G
 */
typedef enum
{
    NET_STATE_INIT = -1,                /**< Init state **/
    NET_STATE_WIRED_CONNECTED = 0,      /**< Wired connected **/
    NET_STATE_WIRELESS_CONNECTED,       /**< Wireless connected **/
    NET_STATE_NOT_CONNECTED             /**< Not connected, at all **/
} NETCONNECTION_STATE;

typedef struct sc_wifi_conf_properties
{
  /**< Wi-Fi AP Channel used for fast discovery **/
  int discoveryChannel;
  /**< Wi-Fi bssid information. **/
  oc_string_t bssid;
} sc_wifi_conf_properties;

typedef struct sc_tnc_info
{
  /**< Terms & Conditions header **/
  oc_string_t header;
  /**< Terms & Conditions version **/
  oc_string_t version;
} sc_tnc_info;

typedef struct sc_dev_conf_properties
{
  /**< Samsung-specific location-related information **/
  oc_string_array_t location;
  /**< Samsung-specific mobile device information for 'register TV' **/
  oc_string_t regMobileDev;
  /**< Samsung-specific account-related information **/
  oc_string_t account;
  /**< Samsung-specific SSO list information which is registered in device **/
  oc_string_t ssoList;
  /**< Samsung-specific Terms & Conditions information **/
  sc_tnc_info scTnCInfo;
  /**< Samsung-specific model number **/
  oc_string_t modelNumber;
  /**< IETF language tag using ISO 639X **/
  oc_string_t language;
  /**< ISO Country Code (ISO 3166-1 Alpha-2) **/
  oc_string_t country;
  /**< GPS information of device. Longitude and latitude in json format **/
  oc_string_t gpsLocation;
  /**< UTC date time **/
  oc_string_t utcDateTime;
  /**< Regional date time **/
  oc_string_t regionalDateTime;
} sc_dev_conf_properties;

typedef struct sc_coap_cloud_server_conf_properties
{
  /**< Samsung-specific clientId for sign-up to IoT Cloud **/
  oc_string_t clientID;
  /**< Samsung-specific aac information **/
  oc_string_t aac;
  /**< Samsung-specific Terms & Conditions result **/
  oc_string_t tncResult;
  /**
   * < Samsung-specific refreshToken information.
   * Indicate refresh token to be used if the access token is expired
   */
  oc_string_t refreshToken;
  /**
   * < Samsung-specific aac information.
   * Indicate user ID corresponding to user account
   */
  oc_string_t uid;
} sc_coap_cloud_server_conf_properties;

typedef struct sc_properties
{
  /**< A state of network connection **/
  NETCONNECTION_STATE netConnectionState;
  /**< Wi-Fi AP Channel used for fast discovery **/
  int discoveryChannel;
  /**< Generated with Device Type + Icon Type **/
  oc_string_t deviceType;
  /**< Device Sub Category **/
  oc_string_t deviceSubType;
  /**< Samsung-specific location-related information **/
  oc_string_array_t location;
  /**< Samsung-specific clientId for sign-up to IoT Cloud **/
  oc_string_t clientID;
  /**< Samsung-specific mobile device information for 'register TV' **/
  oc_string_t regMobileDev;
  /**< Samsung-specific set device information for 'register TV' **/
  oc_string_t regSetDev;
  /**< Samsung-specific network provisioning information for cellular network
   * vendor **/
  oc_string_t nwProvInfo;
  /**< Samsung-specific account-related information **/
  oc_string_t account;
  /**< Samsung-specific SSO list information which is registered in device **/
  oc_string_t ssoList;
  /**< Samsung-specific aac information **/
  oc_string_t aac;
  /**< Samsung-specific Terms & Conditions information **/
  sc_tnc_info tncInfo;
  /**< Samsung-specific Terms & Conditions result **/
  oc_string_t tncResult;
  /**< Samsung-specific Terms & Conditions status **/
  int tncStatus;
  /**
   * < Samsung-specific refreshToken information.
   * Indicate refresh token to be used if the access token is expired
   */
  oc_string_t refreshToken;
  /**< Samsung-specific aac information. Indicate user ID corresponding to user
   * account **/
  oc_string_t uid;
  /**< Samsung-specific Wi-Fi bssid information. **/
  oc_string_t bssid;
  /**< Samsung-specific PnP Pin **/
  oc_string_t pnpPin;
  /**< Samsung-specific model number **/
  oc_string_t modelNumber;
  /**< IETF language tag using ISO 639X **/
  oc_string_t language;
  /**< ISO Country Code (ISO 3166-1 Alpha-2) **/
  oc_string_t country;
  /**< GPS information of device. Longitude and latitude in json format **/
  oc_string_t gpsLocation;
  /**< UTC date time **/
  oc_string_t utcDateTime;
  /**< Regional date time **/
  oc_string_t regionalDateTime;
  /**< Samsung Easy Setup Protocol Version **/
  oc_string_t esProtocolVersion;
} sc_properties;

typedef struct
{
  oc_string_t targetDi;
  oc_string_t targetRt;
  bool published;
}provisioning_info_targets;

typedef struct
{
  oc_resource_t *handle;
  int targets_size;
  provisioning_info_targets *targets;
  bool owned;
  oc_string_t easysetupdi;
} provisioning_info_resource;

void  ReadUserdataCb(oc_rep_t* payload, char* resourceType, void** userdata);
void WriteUserdataCb(oc_rep_t* payload, char* resourceType);

es_result_e set_sc_properties(const sc_properties *prop);

es_result_e set_register_set_device(const char *regSetDevice);
es_result_e set_network_prov_info(const char *nwProvInfo);
es_result_e set_sc_tnc_info(sc_tnc_info *tncInfo);
es_result_e set_sc_tnc_status(int status);
es_result_e set_sc_net_connection_state(NETCONNECTION_STATE netConnectionState);
es_result_e set_sc_pnp_pin(const char *pnp);

es_result_e set_es_version_info(const char *esVersionInfo);
es_result_e register_sc_provisioning_info_resource(void);
es_result_e set_properties_for_sc_prov_info(const provisioning_info_resource *prop);
es_result_e reset_sc_properties(const sc_properties *prop);

#endif /* EASYSETUPX_ENROLLEE_H__ */
