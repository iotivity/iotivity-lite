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


/**
 * @brief  A target configuration type to be connected (or executed).
 */
typedef enum {
  ES_CONNECT_NONE = 0,     // Init value
  ES_CONNECT_WIFI = 1,     // WiFi Conf resource
  ES_CONNECT_CELLULAR = 2, // RSP Conf rsource
  ES_CONNECT_COAPCLOUD = 3 // Coap Cloud Conf resource
} es_connect_type;

/**
 * @brief Indicate which resource is created in Enrollee.
 */
typedef enum {
  ES_WIFICONF_RESOURCE = 0x01,
  ES_DEVCONF_RESOURCE = 0x02,
  ES_RSPCONF_RESOURCE = 0x04,
  ES_RSPCAPCONF_RESOURCE = 0x08
} es_resource_mask_e;

/**
 * @brief Indicate enrollee and provisioning status. Provisioning status is
 * shown in "provisioning
 *        status" property in easysetup resource.
 */
typedef enum {
  /**
   * Default state of the device.
   */
  ES_STATE_INIT = 0,
  /**
   * Status indicating being connecting to target network.
   */
  ES_STATE_CONNECTING_TO_ENROLLER,
  /**
   * Status indicating successful conection to target network.
   */
  ES_STATE_CONNECTED_TO_ENROLLER,
  /**
   * Status indicating connection failure to target network.
   */
  ES_STATE_FAILED_TO_CONNECT_TO_ENROLLER,
  /**
   * Status indicating being registering to cloud.
   */
  ES_STATE_REGISTERING_TO_CLOUD,
  /**
   * Status indicating successful registration to cloud.
   */
  ES_STATE_REGISTERED_TO_CLOUD,
  /**
   * Status indicating registeration failure to cloud.
   */
  ES_STATE_FAILED_TO_REGISTER_TO_CLOUD,
  /**
   * Status indicating being publishing resources to cloud.
   */
  ES_STATE_PUBLISHING_RESOURCES_TO_CLOUD,
  /**
   * Status indicating successful resource publish to cloud.
   */
  ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD,
  /**
   * Status indicating resource publish failure to cloud.
   */
  ES_STATE_FAILED_TO_PUBLISH_RESOURCES_TO_CLOUD,
  /**
   * End of Easy setup status.
   */
  ES_STATE_EOF = 255
} es_enrollee_state,
  prov_status;

typedef enum {
  /**
   * Provisioning succeeds.
   */
  ES_OK = 0,
  /**
   * Secure resource is discovered.
   */
  ES_SECURE_RESOURCE_IS_DISCOVERED = 1,
  /**
   * Enrollee discovery fails in cloud provisioning.
   */
  ES_ENROLLEE_DISCOVERY_FAILURE = 11,
  /**
   * Valid GET or POST request fails for some reason.
   * This failure may happen when it failed to receive any response from
   * Enrollee by a timeout
   * threshold.
   */
  ES_COMMUNICATION_ERROR,
  /**
   * Security opertion is not supported because Mediator is built as unsecured
   * mode.
   */
  ES_SEC_OPERATION_IS_NOT_SUPPORTED,
  /**
   * Security resource discovery fails due to loss of discovery packet or
   * absence of the resource
   * in a network.
   */
  ES_SECURE_RESOURCE_DISCOVERY_FAILURE,
  /**
   * Ownership transfer fails due to one of unexpected reasons.
   * E.g. A packet loss even with retransmission happens during ownership
   * transfer.
   * E.g. Mediator's owned status is 'unowned'
   * E.g. A user confirmation for random pin-based or certificate-based OT fails
   */
  ES_OWNERSHIP_TRANSFER_FAILURE = 20,
  /**
   * Ownership transfer which is cert-based method fails due to user
   * confirmation is denied.
   */
  ES_USER_DENIED_CONFIRMATION_REQ,
  /**
   * Ownership transfer which is cert-based method fails due to wrong
   * certificate.
   */
  ES_AUTHENTICATION_FAILURE_WITH_WRONG_CERT,
  /**
   * Ownership transfer which is random-pin method fails due to wrong pin.
   */
  ES_AUTHENTICATION_FAILURE_WITH_WRONG_PIN,
  /**
   * Ownership information is not synchronized between Mediator and Enrollee.
   * e.g. A mediator's PDM DB has an ownership information to the found enrollee
   *      but it is actually owned by other mediator.
   *      That can happen where the found enrollee is reset and performed in
   * easy setup without
   *      any inform to the first mediator.
   * e.g. A list of owned devices managed in mediator's PMD db has no element
   * for the found
   *      enrollee.
   *      That can happen where only mediator is reset without any inform to the
   * enrollee.
   * To proceed an ownership transfer to the enrollee, it needs to reset the
   * enrollee's SVR DB for
   * its owner, i.e. the mediator.
   */
  ES_OWNERSHIP_IS_NOT_SYNCHRONIZED,
  /**
   * MOT is not supported at the target Enrollee device.
   *
   * @note This ESResult values will be returned ONLY IF a mediator is a first
   * owner to an
   * Enrollee.
   * @note If the mediator gets this values, it means OT has been successfully
   * done
   * (or already took an ownership, before), but failed MOT configuration.
   */
  ES_MOT_NOT_SUPPORTED = 30,
  /**
   * MOT enabling is failed.
   *
   * @note This ESResult values will be returned ONLY IF a mediator is a first
   * owner to an
   * Enrollee.
   * @note If the mediator gets this values, it means OT has been successfully
   * done
   * (or already took an ownership, before), but failed MOT configuration.
   */
  ES_MOT_ENABLING_FAILURE,
  /**
   * MOT method selection is failed.
   *
   * @note This ESResult values will be returned ONLY IF a mediator is a first
   * owner to an
   * Enrollee.
   * @note If the mediator gets this values, it means OT has been successfully
   * done
   * (or already took an ownership, before), but failed MOT configuration.
   */
  ES_MOT_METHOD_SELECTION_FAILURE,
  /**
   * A provisioning of Pre-configured pin number for MOT is failed.
   *
   * @note This ESResult values will be returned ONLY IF a mediator is a first
   * owner to an
   * Enrollee.
   * @note If the mediator gets this values, it means OT has been successfully
   * done
   * (or already took an ownership, before), but failed MOT configuration.
   */
  ES_PRE_CONFIG_PIN_PROVISIONING_FAILURE,
  /**
   * ACL provisioning fails in cloud provisioning.
   * It could be that UUID format of cloud server is wrong.
   * Or any response for the provisioning request is not arrived at Mediator
   */
  ES_ACL_PROVISIONING_FAILURE = 40,
  /**
   * Cert. provisioning fails in cloud provisioning.
   * It could be that you put a wrong cred ID of which the corresponding
   * certificate does not
   * exist in SVR DB.
   * Or any response for the provisioning request is not arrived at Mediator
   */
  ES_CERT_PROVISIONING_FAILURE,
  /**
   * Provisioning fails for some reason.
   */

  ES_ERROR = 255
} es_result_e;

/**
 * @brief Indicate last error code to describe a reason of error during easy
 * setup.
 */
typedef enum {
  /**
   * Init Error Code.
   */
  ES_ERRCODE_NO_ERROR = 0,
  /**
   * WiFi's SSID is not found.
   */
  ES_ERRCODE_SSID_NOT_FOUND,
  /**
   * WiFi's Password is wrong.
   */
  ES_ERRCODE_PW_WRONG,
  /**
   * IP address is not allocated.
   */
  ES_ERRCODE_IP_NOT_ALLOCATED,
  /**
   * There is no Internet connection.
   */
  ES_ERRCODE_NO_INTERNETCONNECTION,
  /**
   * Timeout occured.
   */
  ES_ERRCODE_TIMEOUT,
  /**
   * Auth type is not supported by the Enrollee.
   */
  ES_ERRCODE_AUTH_TYPE_NOT_SUPPORTED,
  /**
   * Enc type is not supported by the Enrollee.
   */
  ES_ERRCODE_ENC_TYPE_NOT_SUPPORTED,
  /**
   * Auth type is not supported by the Enroller.
   */
  ES_ERRCODE_AUTH_TYPE_INVALID,
  /**
   * Enc type is not supported by the Enroller.
   */
  ES_ERRCODE_ENC_TYPE_INVALID,
  /**
   * Cloud server is not reachable due to wrong URL of cloud server, for
   * example.
   */
  ES_ERRCODE_FAILED_TO_ACCESS_CLOUD_SERVER,
  /**
   * No response from cloud server.
   */
  ES_ERRCODE_NO_RESPONSE_FROM_CLOUD_SERVER,
  /**
   * Delivered authcode is not valid.
   */
  ES_ERRCODE_INVALID_AUTHCODE,
  /**
   * Access token is not valid due to its expiration, for example.
   */
  ES_ERRCODE_INVALID_ACCESSTOKEN,
  /**
   * Refresh of expired access token is failed due to some reasons.
   */
  ES_ERRCODE_FAILED_TO_REFRESH_ACCESSTOKEN,
  /**
   * Target device is not discovered in cloud server.
   */
  ES_ERRCODE_FAILED_TO_FIND_REGISTERED_DEVICE_IN_CLOUD,
  /**
   * Target user does not exist in cloud server.
   */
  ES_ERRCODE_FAILED_TO_FIND_REGISTERED_USER_IN_CLOUD,
  /**
   * Enrollee can not connect to a target WiFi AP because the AP resides in
   * an unsupported WiFi frequency.
   */
  ES_ERRCODE_UNSUPPORTED_WIFI_FREQUENCY,
  /**
   * Unknown error occured.
   */
  ES_ERRCODE_UNKNOWN = 255
} es_error_code;

/**
 * @brief Data structure for connect request from Mediator.
 */
typedef struct
{
  es_connect_type connect[NUM_CONNECT_TYPE]; /**< Connection type(s) sent by Mediator. */
  int num_request;                           /**< Size of connect array. */
} es_connect_request;


/**
 * @brief Data structure delivered from Mediator, which provides Wi-Fi
 * information.
 */
typedef struct
{
  oc_string_t ssid;       /**< SSID of the Enroller. */
  oc_string_t pwd;        /**< Passphrase of the Enroller. */
  wifi_authtype authtype; /**< Auth Type of the Enroller. */
  wifi_enctype enctype;   /**< Encryption Type of the Enroller. */
  void *userdata;         /**< Vender Specific data. */
} es_wifi_conf_data;

/**
 * @brief Data structure delivered from Mediator, which provides device
 * configuration information.
 */
typedef struct
{
  void *userdata; /**< Vender Specific data. */
} es_dev_conf_data;

//cs.bhargava,, TODO
typedef struct
{
  void *userdata; /**< Vender Specific data. */
} es_rsp_conf_data;

//cs.bhargava,, TODO
typedef struct
{
  void *userdata; /**< Vender Specific data. */
} es_rspcap_conf_data;

/**
 * A set of functions pointers for callback functions which are called after
 * provisioning data is received from Mediator.
 */
typedef struct
{
  void (*connect_request_cb)(es_connect_request *);  /**< Callback to direct Enrollee for initiating connection. */
  void (*wifi_conf_prov_cb)(es_wifi_conf_data *);         /**< Callback to receive wifi configuaration. */
  void (*dev_conf_prov_cb)(es_dev_conf_data *);      /**< Callback to receive device configuaration. */
  void (*rsp_conf_prov_cb)(es_rsp_conf_data *);         /**< Callback to receive rsp configuaration. */
  void (*rspcap_conf_prov_cb)(es_rspcap_conf_data *);      /**< Callback to receive rsp capability configuaration. */  
} es_provisioning_callbacks_s;


#ifdef __cplusplus
}
#endif

#endif /* _ES_COMMON_H_ */
