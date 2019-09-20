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

#ifndef _OC_EASYSETUP_ENROLLEE_H_
#define _OC_EASYSETUP_ENROLLEE_H_

/**
 * @file
 *
 * This file contains Enrollee APIs.
 */
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "es_common.h"

/**
 * @brief Indicate last error code to describe a reason of error during easy
 * setup.
 */
typedef enum {
  /**
   * Init Error Code.
   */
  OC_ES_ERRCODE_NO_ERROR = 0,
  /**
   * WiFi's SSID is not found.
   */
  OC_ES_ERRCODE_SSID_NOT_FOUND,
  /**
   * WiFi's Password is wrong.
   */
  OC_ES_ERRCODE_PW_WRONG,
  /**
   * IP address is not allocated.
   */
  OC_ES_ERRCODE_IP_NOT_ALLOCATED,
  /**
   * There is no Internet connection.
   */
  OC_ES_ERRCODE_NO_INTERNETCONNECTION,
  /**
   * Timeout occured.
   */
  OC_ES_ERRCODE_TIMEOUT,
  /**
   * Auth type is not supported by the Enrollee.
   */
  OC_ES_ERRCODE_AUTH_TYPE_NOT_SUPPORTED,
  /**
   * Enc type is not supported by the Enrollee.
   */
  OC_ES_ERRCODE_ENC_TYPE_NOT_SUPPORTED,
  /**
   * Auth type is not supported by the Enroller.
   */
  OC_ES_ERRCODE_AUTH_TYPE_INVALID,
  /**
   * Enc type is not supported by the Enroller.
   */
  OC_ES_ERRCODE_ENC_TYPE_INVALID,
  /**
   * Cloud server is not reachable due to wrong URL of cloud server, for
   * example.
   */
  OC_ES_ERRCODE_FAILED_TO_ACCESS_CLOUD_SERVER,
  /**
   * No response from cloud server.
   */
  OC_ES_ERRCODE_NO_RESPONSE_FROM_CLOUD_SERVER,
  /**
   * Delivered authcode is not valid.
   */
  OC_ES_ERRCODE_INVALID_AUTHCODE,
  /**
   * Access token is not valid due to its expiration, for example.
   */
  OC_ES_ERRCODE_INVALID_ACCESSTOKEN,
  /**
   * Refresh of expired access token is failed due to some reasons.
   */
  OC_ES_ERRCODE_FAILED_TO_REFRESH_ACCESSTOKEN,
  /**
   * Target device is not discovered in cloud server.
   */
  OC_ES_ERRCODE_FAILED_TO_FIND_REGISTERED_DEVICE_IN_CLOUD,
  /**
   * Target user does not exist in cloud server.
   */
  OC_ES_ERRCODE_FAILED_TO_FIND_REGISTERED_USER_IN_CLOUD,
  /**
   * Enrollee can not connect to a target WiFi AP because the AP resides in
   * an unsupported WiFi frequency.
   */
  OC_ES_ERRCODE_UNSUPPORTED_WIFI_FREQUENCY,
  /**
   * Unknown error occured.
   */
  OC_ES_ERRCODE_UNKNOWN = 255
} oc_es_error_code;

/**
 * @brief Indicate enrollee and provisioning status. Provisioning status is
 * shown in "provisioning
 *        status" property in easysetup resource.
 */
typedef enum {
  /**
   * Default state of the device.
   */
  OC_ES_STATE_INIT = 0,
  /**
   * Status indicating being connecting to target network.
   */
  OC_ES_STATE_CONNECTING_TO_ENROLLER,
  /**
   * Status indicating successful conection to target network.
   */
  OC_ES_STATE_CONNECTED_TO_ENROLLER,
  /**
   * Status indicating connection failure to target network.
   */
  OC_ES_STATE_FAILED_TO_CONNECT_TO_ENROLLER,
  /**
   * Status indicating being registering to cloud.
   */
  OC_ES_STATE_REGISTERING_TO_CLOUD,
  /**
   * Status indicating successful registration to cloud.
   */
  OC_ES_STATE_REGISTERED_TO_CLOUD,
  /**
   * Status indicating registeration failure to cloud.
   */
  OC_ES_STATE_FAILED_TO_REGISTER_TO_CLOUD,
  /**
   * Status indicating being publishing resources to cloud.
   */
  OC_ES_STATE_PUBLISHING_RESOURCES_TO_CLOUD,
  /**
   * Status indicating successful resource publish to cloud.
   */
  OC_ES_STATE_PUBLISHED_RESOURCES_TO_CLOUD,
  /**
   * Status indicating resource publish failure to cloud.
   */
  OC_ES_STATE_FAILED_TO_PUBLISH_RESOURCES_TO_CLOUD,
  /**
   * End of Easy setup status.
   */
  OC_ES_STATE_EOF = 255
} oc_es_enrollee_state;


typedef enum {
  /**
   * Provisioning succeeds.
   */
  OC_ES_OK = 0,
  /**
   * Secure resource is discovered.
   */
  OC_ES_SECURE_RESOURCE_IS_DISCOVERED = 1,
  /**
   * Enrollee discovery fails in cloud provisioning.
   */
  OC_ES_ENROLLEE_DISCOVERY_FAILURE = 11,
  /**
   * Valid GET or POST request fails for some reason.
   * This failure may happen when it failed to receive any response from
   * Enrollee by a timeout
   * threshold.
   */
  OC_ES_COMMUNICATION_ERROR,
  /**
   * Security opertion is not supported because Mediator is built as unsecured
   * mode.
   */
  OC_ES_SEC_OPERATION_IS_NOT_SUPPORTED,
  /**
   * Security resource discovery fails due to loss of discovery packet or
   * absence of the resource
   * in a network.
   */
  OC_ES_SECURE_RESOURCE_DISCOVERY_FAILURE,
  /**
   * Ownership transfer fails due to one of unexpected reasons.
   * E.g. A packet loss even with retransmission happens during ownership
   * transfer.
   * E.g. Mediator's owned status is 'unowned'
   * E.g. A user confirmation for random pin-based or certificate-based OT fails
   */
  OC_ES_OWNERSHIP_TRANSFER_FAILURE = 20,
  /**
   * Ownership transfer which is cert-based method fails due to user
   * confirmation is denied.
   */
  OC_ES_USER_DENIED_CONFIRMATION_REQ,
  /**
   * Ownership transfer which is cert-based method fails due to wrong
   * certificate.
   */
  OC_ES_AUTHENTICATION_FAILURE_WITH_WRONG_CERT,
  /**
   * Ownership transfer which is random-pin method fails due to wrong pin.
   */
  OC_ES_AUTHENTICATION_FAILURE_WITH_WRONG_PIN,
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
  OC_ES_OWNERSHIP_IS_NOT_SYNCHRONIZED,
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
  OC_ES_MOT_NOT_SUPPORTED = 30,
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
  OC_ES_MOT_ENABLING_FAILURE,
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
  OC_ES_MOT_METHOD_SELECTION_FAILURE,
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
  OC_ES_PRE_CONFIG_PIN_PROVISIONING_FAILURE,
  /**
   * ACL provisioning fails in cloud provisioning.
   * It could be that UUID format of cloud server is wrong.
   * Or any response for the provisioning request is not arrived at Mediator
   */
  OC_ES_ACL_PROVISIONING_FAILURE = 40,
  /**
   * Cert. provisioning fails in cloud provisioning.
   * It could be that you put a wrong cred ID of which the corresponding
   * certificate does not
   * exist in SVR DB.
   * Or any response for the provisioning request is not arrived at Mediator
   */
  OC_ES_CERT_PROVISIONING_FAILURE,
  /**
   * Provisioning fails for some reason.
   */

  OC_ES_ERROR = 255
} oc_es_result_t;

/**
 * @brief Indicate which resource is created in Enrollee.
 */
typedef enum {
  OC_ES_WIFICONF_RESOURCE = 0x01,
  OC_ES_DEVCONF_RESOURCE = 0x02,
  OC_ES_RSPCONF_RESOURCE = 0x04,
  OC_ES_RSPCAPCONF_RESOURCE = 0x08
} oc_es_resource_mask_t;

/**
 * @brief  A target configuration type to be connected (or executed).
 */
typedef enum {
  ES_CONNECT_NONE = 0,     // Init value
  ES_CONNECT_WIFI = 1,     // WiFi Conf resource
  ES_CONNECT_CELLULAR = 2, // RSP Conf rsource
  ES_CONNECT_COAPCLOUD = 3 // Coap Cloud Conf resource
} oc_es_connect_type_t;

/**
 * @brief Data structure for connect request from Mediator.
 */
typedef struct
{
  oc_es_connect_type_t connect[NUM_CONNECT_TYPE]; /**< Connection type(s) sent by Mediator. */
  int num_request;                           /**< Size of connect array. */
} oc_es_connect_request;


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
} oc_es_wifi_conf_data;

/**
 * @brief Data structure delivered from Mediator, which provides device
 * configuration information.
 */
typedef struct
{
  void *userdata; /**< Vender Specific data. */
} oc_es_dev_conf_data;

//cs.bhargava,, TODO
typedef struct
{
  void *userdata; /**< Vender Specific data. */
} oc_es_rsp_conf_data;

//cs.bhargava,, TODO
typedef struct
{
  void *userdata; /**< Vender Specific data. */
} oc_es_rspcap_conf_data;

/**
 * A set of functions pointers for callback functions which are called after
 * provisioning data is received from Mediator.
 */
typedef struct
{
  void (*connect_request_cb)(oc_es_connect_request *);  /**< Callback to direct Enrollee for initiating connection. */
  void (*wifi_conf_prov_cb)(oc_es_wifi_conf_data *);         /**< Callback to receive wifi configuaration. */
  void (*dev_conf_prov_cb)(oc_es_dev_conf_data *);      /**< Callback to receive device configuaration. */
  void (*rsp_conf_prov_cb)(oc_es_rsp_conf_data *);         /**< Callback to receive rsp configuaration. */
  void (*rspcap_conf_prov_cb)(oc_es_rspcap_conf_data *);      /**< Callback to receive rsp capability configuaration. */
} oc_es_provisioning_callbacks;

/**
 * @brief Data structure stored for Device property which includes a WiFi and
 * device configuration.
 */
typedef struct
{
  /**
   * @brief Data structure indicating Wi-Fi configuration of Enrollee.
   */
  struct
  {
    wifi_mode supported_mode[NUM_WIFIMODE];  /**< Supported Wi-Fi modes e.g. 802.11 A / B / G / N etc. */
    wifi_freq supported_freq;                /**< supported Wi-Fi frequency e.g. 2.4G, 5G etc. */
  } WiFi;

  /**
   * @brief Data structure indicating device configuration of Enrollee.
   */
  struct
  {
    oc_string_t device_name;                 /**< Device friendly name. */
  } DevConf;
} oc_es_device_info;


/**
 * A function pointer for registering a user-defined function to set
 * user-specific properties to a
 * response going back to a client.
 * @param payload Represents a response. You can set a specific value with
 * specific property key
 * to the payload. If a client receives the response and know the property key,
 * then it can
 * extract the value.
 * @param resource_type Used to distinguish which resource the received property
 * belongs to.
 */
typedef void (*oc_es_write_userdata_cb_t)(oc_rep_t *payload, char *resource_type);

/**
 * A function pointer for registering a user-defined function to parse
 * user-specific properties
 * from received POST request.
 * @param payload Represents a received POST request. If you know user-specific
 * property key,
 * then you can extract a corresponding value if it exists.
 * @param resource_type Used to distinguish which resource the received property
 * belongs to
 * @param user_data User-specific data you want to deliver to desired users,
 * i.e.
 * application.
 * The user should know a data structure of passed userdata.
 */
typedef void (*oc_es_read_userdata_cb_t)(oc_rep_t *payload, char *resource_type,
                                    void **user_data);

/**
 * A callback function to clean up user data created in oc_es_wifi_conf_data,
 * oc_es_dev_conf_data and es_coap_cloud_conf_data.
 *
 * @param user_data User-specific data free up it's memory.
 * @param resource_type Used to distinguish which resource user data
 * beongs to.
 */
typedef void (*oc_es_free_userdata_t)(void *user_data, char *resource_type);

/**
 * This function initializes the EasySetup. This API must be called prior to
 * invoking any other API.
 *
 * @param resource_mask     Easy Setup Resource Type which application wants to
 * create.
 *                          OC_ES_WIFICONF_RESOURCE = 0x01,
 *                          OC_ES_DEVCONF_RESOURCE = 0x02
 *				   OC_ES_RSPCONF_RESOURCE = 0x04,
 *				   OC_ES_RSPCAPCONF_RESOURCE = 0x08
 * @param callbacks         ESProvisioningCallbacks for updating Easy setup
 * Resources' data to the
 *                          application
 * @return ::OC_ES_OK on success, some other value upon failure.
 */
oc_es_result_t oc_es_init_enrollee(oc_es_resource_mask_t resource_mask,
                             oc_es_provisioning_callbacks callbacks);

/**
 * This function performs termination of all Easy Setup Resources.
 *
 * @return ::void
 */
void oc_es_terminate_enrollee(void);

/**
 * This function is to set two function pointer to handle user-specific
 * properties in in-comming
 * POST request and to out-going response for GET or POST request.
 * If you register certain functions with this API, you have to handle oc_rep_t
 * structure to
 * set and get properties you want.
 *
 * @param readcb a callback for parsing properties from POST request
 * @param writecb a callback for putting properties to a response to be sent
 * @param free_userdata callback to free allocated memory of user data in
 * s_wifi_conf_data, es_dev_conf_data and es_coap_cloud_conf_data.
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_es_read_userdata_cb_t
 * @see oc_es_write_userdata_cb_t
 */
oc_es_result_t oc_es_set_userdata_callbacks(oc_es_read_userdata_cb_t readcb,
                                         oc_es_write_userdata_cb_t writecb,
                                         oc_es_free_userdata_t free_userdata);

/**
 * This function sets Device information.
 *
 * @param device_info Contains device information composed of WiFiConf
 * Structure & DevConf Structure
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_es_device_info
 */
oc_es_result_t oc_es_set_device_info(oc_es_device_info *device_info);

/**
 * This function Sets Enrollee's Error Code.
 *
 * @param es_err_code Contains Enrollee's error code.
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_es_error_code
 */
oc_es_result_t oc_es_set_error_code(oc_es_error_code err_code);

/**
 * This function sets Enrollee's State.
 *
 * @param es_state   Contains current enrollee's state.
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_es_enrollee_state
 */
oc_es_result_t oc_es_set_state(oc_es_enrollee_state es_state);

/**
 * This function gets Enrollee's State.
 *
 * @return ::oc_es_enrollee_state
 *
 * @see oc_es_enrollee_state
 */
oc_es_enrollee_state oc_es_get_state(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* _OC_EASYSETUP_ENROLLEE_H_ */

