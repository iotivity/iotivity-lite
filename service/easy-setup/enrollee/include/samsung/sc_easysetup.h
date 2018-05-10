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
    int discoveryChannel;                   /**< Wi-Fi AP Channel used for fast discovery **/
    char bssid[MAXLEN_STRING];              /**< Wi-Fi bssid information. **/
} sc_wifi_conf_properties;

typedef struct sc_tnc_info
{
    char header[MAXLEN_STRING];     /**< Terms & Conditions header **/
    char version[MAXLEN_STRING];    /**< Terms & Conditions version **/
}sc_tnc_info;

typedef struct sc_dev_conf_properties
{
    int numLocation;
    char location[MAXNUM_LOCATION][MAXLEN_STRING];  /**< Samsung-specific location-related information **/
    char regMobileDev[MAXLEN_STRING];               /**< Samsung-specific mobile device information for 'register TV' **/
    char account[MAXLEN_STRING];                    /**< Samsung-specific account-related information **/
    char ssoList[MAXLEN_STRING];                    /**< Samsung-specific SSO list information which is registered in device **/
    sc_tnc_info scTnCInfo;                          /**< Samsung-specific Terms & Conditions information **/
    char modelNumber[MAXLEN_STRING];                /**< Samsung-specific model number **/
    char language[MAXLEN_STRING];                   /**< IETF language tag using ISO 639X **/
    char country[MAXLEN_STRING];                    /**< ISO Country Code (ISO 3166-1 Alpha-2) **/
    char gpsLocation[MAXLEN_STRING];                /**< GPS information of device. Longitude and latitude in json format **/
    char utcDateTime[MAXLEN_DATE_TIME];             /**< UTC date time **/
    char regionalDateTime[MAXLEN_DATE_TIME];        /**< Regional date time **/
} sc_dev_conf_properties;

typedef struct sc_coap_cloud_server_conf_properties
{
    char clientID[MAXLEN_STRING];                   /**< Samsung-specific clientId for sign-up to IoT Cloud **/
    char aac[MAXLEN_STRING];                        /**< Samsung-specific aac information **/
    char tncResult[MAXLEN_STRING];                  /**< Samsung-specific Terms & Conditions result **/
    char refreshToken[MAXLEN_STRING];               /**< Samsung-specific refreshToken information. Indicate refresh token to be used if the access token is expired**/
    char uid[MAXLEN_STRING];                        /**< Samsung-specific aac information. Indicate user ID corresponding to user account **/
} sc_coap_cloud_server_conf_properties;

typedef struct sc_properties
{
    NETCONNECTION_STATE netConnectionState;         /**< A state of network connection **/
    int discoveryChannel;                           /**< Wi-Fi AP Channel used for fast discovery **/
    char deviceType[MAXLEN_STRING];                 /**< Generated with Device Type + Icon Type **/
    char deviceSubType[MAXLEN_STRING];              /**< Device Sub Category **/
    int numLocation;
    char location[MAXNUM_LOCATION][MAXLEN_STRING];  /**< Samsung-specific location-related information **/
    char clientID[MAXLEN_STRING];                   /**< Samsung-specific clientId for sign-up to IoT Cloud **/
    char regMobileDev[MAXLEN_STRING];               /**< Samsung-specific mobile device information for 'register TV' **/
    char regSetDev[MAXLEN_STRING];                  /**< Samsung-specific set device information for 'register TV' **/
    char nwProvInfo[MAXLEN_STRING];                 /**< Samsung-specific network provisioning information for cellular network vendor **/
    char account[MAXLEN_STRING];                    /**< Samsung-specific account-related information **/
    char ssoList[MAXLEN_STRING];                    /**< Samsung-specific SSO list information which is registered in device **/
    char aac[MAXLEN_STRING];                        /**< Samsung-specific aac information **/
    sc_tnc_info tncInfo;                            /**< Samsung-specific Terms & Conditions information **/
    char tncResult[MAXLEN_STRING];                  /**< Samsung-specific Terms & Conditions result **/
    int tncStatus;                                  /**< Samsung-specific Terms & Conditions status **/
    char refreshToken[MAXLEN_STRING];               /**< Samsung-specific refreshToken information. Indicate refresh token to be used if the access token is expired**/
    char uid[MAXLEN_STRING];                        /**< Samsung-specific aac information. Indicate user ID corresponding to user account **/
    char bssid[MAXLEN_STRING];                      /**< Samsung-specific Wi-Fi bssid information. **/
    char pnpPin[MAXLEN_STRING];                     /**< Samsung-specific PnP Pin **/
    char modelNumber[MAXLEN_STRING];                /**< Samsung-specific model number **/
    char language[MAXLEN_STRING];                   /**< IETF language tag using ISO 639X **/
    char country[MAXLEN_STRING];                    /**< ISO Country Code (ISO 3166-1 Alpha-2) **/
    char gpsLocation[MAXLEN_STRING];                /**< GPS information of device. Longitude and latitude in json format **/
    char utcDateTime[MAXLEN_DATE_TIME];             /**< UTC date time **/
    char regionalDateTime[MAXLEN_DATE_TIME];        /**< Regional date time **/
    char esProtocolVersion[MAXLEN_STRING];          /**< Samsung Easy Setup Protocol Version **/
} sc_properties;

typedef struct
{
  oc_resource_t *handle;
  char targets[MAXLEN_STRING];
  bool owned;
  char easysetupdi[MAXLEN_STRING];
} provisioning_info_resource;

typedef struct
{
  char targetDi[MAXLEN_STRING];
  char targetRt[MAXLEN_STRING];
  bool published;
}provisioning_info_targets;

typedef struct
{
 int targets_size;
  provisioning_info_targets targets[MAXIMUM_TARGETS];
  bool owned;
  char easysetupdi[MAXLEN_STRING];
} provisioning_info_properties;

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
es_result_e register_provisioning_info_resource();
es_result_e set_properties_for_prov_info(const provisioning_info_properties *prop);

#endif /* EASYSETUPX_ENROLLEE_H__ */
