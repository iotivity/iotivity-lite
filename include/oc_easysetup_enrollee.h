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
 * @brief Indicate the result of function call which is
 * common for WiFi Easysetup and Esim Easysetup
 */
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
 * @brief  A target configuration type to be connected (or executed).
 */
typedef enum {
  OC_ES_CONNECT_NONE = 0,     // Init value
  OC_ES_CONNECT_WIFI = 1,     // WiFi Conf resource
  OC_ES_CONNECT_COAPCLOUD = 2 // Coap Cloud Conf resource
} oc_es_connect_type_t;

/**
 * @brief Indicate enrollee and provisioning status. Provisioning status is
 * shown in "provisioning status" property in easysetup resource.
 * common for WiFi Easysetup and Esim Easysetup
 */
typedef enum {
  /**
   * Default state of the device.
   */
  OC_WES_INIT = 0,
  /**
   * Status indicating being connecting to target network.
   */
  OC_WES_CONNECTING_TO_ENROLLER,
  /**
   * Status indicating successful conection to target network.
   */
  OC_WES_CONNECTED_TO_ENROLLER,
  /**
   * Status indicating connection failure to target network.
   */
  OC_WES_FAILED_TO_CONNECT_TO_ENROLLER,
  /**
   * Status indicating being registering to cloud.
   */
  OC_WES_REGISTERING_TO_CLOUD,
  /**
   * Status indicating successful registration to cloud.
   */
  OC_WES_REGISTERED_TO_CLOUD,
  /**
   * Status indicating registeration failure to cloud.
   */
  OC_WES_FAILED_TO_REGISTER_TO_CLOUD,
  /**
   * Status indicating being publishing resources to cloud.
   */
  OC_WES_PUBLISHING_RESOURCES_TO_CLOUD,
  /**
   * Status indicating successful resource publish to cloud.
   */
  OC_WES_PUBLISHED_RESOURCES_TO_CLOUD,
  /**
   * Status indicating resource publish failure to cloud.
   */
  OC_WES_FAILED_TO_PUBLISH_RESOURCES_TO_CLOUD,
  /**
   * End of Easy setup status.
   */
  OC_WES_EOF = 255
} oc_wes_enrollee_state_t;

/**
 * @brief Indicate last error code to describe a reason of error during WiFi easy
 * setup.
 */
typedef enum {
  /**
   * Init Error Code.
   */
  OC_WES_NO_ERROR = 0,
  /**
   * WiFi's SSID is not found.
   */
  OC_WES_SSID_NOT_FOUND,
  /**
   * WiFi's Password is wrong.
   */
  OC_WES_PW_WRONG,
  /**
   * IP address is not allocated.
   */
  OC_WES_IP_NOT_ALLOCATED,
  /**
   * There is no Internet connection.
   */
  OC_WES_NO_INTERNETCONNECTION,
  /**
   * Timeout occured.
   */
  OC_WES_TIMEOUT,
  /**
   * Auth type is not supported by the Enrollee.
   */
  OC_WES_AUTH_TYPE_NOT_SUPPORTED,
  /**
   * Enc type is not supported by the Enrollee.
   */
  OC_WES_ENC_TYPE_NOT_SUPPORTED,
  /**
   * Auth type is not supported by the Enroller.
   */
  OC_WES_AUTH_TYPE_INVALID,
  /**
   * Enc type is not supported by the Enroller.
   */
  OC_WES_ENC_TYPE_INVALID,
  /**
   * Cloud server is not reachable due to wrong URL of cloud server, for
   * example.
   */
  OC_WES_FAILED_TO_ACCESS_CLOUD_SERVER,
  /**
   * No response from cloud server.
   */
  OC_WES_NO_RESPONSE_FROM_CLOUD_SERVER,
  /**
   * Delivered authcode is not valid.
   */
  OC_WES_INVALID_AUTHCODE,
  /**
   * Access token is not valid due to its expiration, for example.
   */
  OC_WES_INVALID_ACCESSTOKEN,
  /**
   * Refresh of expired access token is failed due to some reasons.
   */
  OC_WES_FAILED_TO_REFRESH_ACCESSTOKEN,
  /**
   * Target device is not discovered in cloud server.
   */
  OC_WES_FAILED_TO_FIND_REGISTERED_DEVICE_IN_CLOUD,
  /**
   * Target user does not exist in cloud server.
   */
  OC_WES_FAILED_TO_FIND_REGISTERED_USER_IN_CLOUD,
  /**
   * Enrollee can not connect to a target WiFi AP because the AP resides in
   * an unsupported WiFi frequency.
   */
  OC_WES_UNSUPPORTED_WIFI_FREQUENCY,
  /**
   * Unknown error occured.
   */
  OC_WES_UNKNOWN_ERROR = 255
} oc_wes_error_code_t;

/**
 * @brief Data structure for connect request from Mediator.
 */
typedef struct
{
  oc_es_connect_type_t connect[NUM_CONNECT_TYPE]; /**< Connection type(s) sent by Mediator. */
  int num_request;       /**< Size of connect array. */
  oc_wes_enrollee_state_t state;
  oc_wes_error_code_t last_err_code;
  void *userdata;         /**< Vender Specific data. */
} oc_wes_data_t;

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
} oc_wes_wifi_data_t;

/**
 * @brief Data structure delivered from Mediator, which provides device
 * configuration information.
 */
typedef struct
{
  oc_string_t device_name; /**< Device friendly name. */
  void *userdata; /**< Vender Specific data. */
} oc_wes_device_data_t;

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
  } Device;
} oc_wes_device_info_t;

/**
 * @brief Indicate last error code to describe a reason of error during eSIM easy
 * setup.
 */
typedef enum {
  /**
   * Init Error Code.
   */
  OC_EES_NO_ERROR = 0,
  /**
   * Fialed to read eUICC Info by LPA
   */
  OC_EES_EUICC_INFO_READ_FAILED,
  /**
   * Fialed to read Device Info by LPA
   */
  OC_EES_DEVICE_INFO_READ_FAILED,
  /**
   * Failed to install eUICC profile
   */
  OC_EES_INSTALL_PROFILE_FAILED,
  /**
   * Invalid Activation Code
   */
  OC_EES_ACTIVATION_CODE_INVALID,
  /**
   * Unknown error occured.
   */
  OC_EES_UNKNOWN_ERROR = 255
} oc_ees_error_code_t;

/**
 * @brief Data structure for eSIM Easyset up collection.
 */
typedef struct
{
  oc_string_t rsp_status;
  oc_string_t last_err_reason;
  oc_string_t last_err_code;
  oc_string_t last_err_desc;
  oc_string_t end_user_conf;
  void *userdata; /**< Vender Specific data. */
} oc_ees_data_t;

/**
 * @brief Data structure for remote SIM provisioning
 * request from Mediator.
 */
typedef struct
{
  oc_string_t activation_code;  /**< Activation code for eSIM profile. */
  oc_string_t profile_metadata;
  oc_string_t confirm_code;
  bool confirm_code_required;
  void *userdata; /**< Vender Specific data. */
} oc_ees_rsp_data_t;

/**
 * @brief Data structure for device info
 * read by Mediator.
 */
 typedef struct
{
  oc_string_t euicc_info;
  oc_string_t device_info;
  void *userdata; /**< Vender Specific data. */
} oc_ees_rspcap_data_t;

/**
 * @brief Data structure stored for Device property which includes a WiFi and
 * device configuration.
 */
typedef struct
{
  /**
   * @brief Data structure indicating device configuration of Enrollee.
   */
  struct
  {
    oc_string_t euicc_info;
    oc_string_t device_info;
  } LPA;
} oc_ees_device_info_t;

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
 * A callback function to clean up user data created in oc_wes_wifi_data_t,
 * oc_wes_device_data_t and es_coap_cloud_conf_data.
 *
 * @param user_data User-specific data free up it's memory.
 * @param resource_type Used to distinguish which resource user data
 * beongs to.
 */
typedef void (*oc_es_free_userdata_cb_t)(void *user_data, char *resource_type);

/**
 * A function pointer for registering wifi easysetup callback
 * @param payload Represents the data written to wes resource
 */
typedef void (*oc_wes_prov_cb_t)(oc_wes_data_t *);

/**
 * A function pointer for registering wifi callback
 * @param payload Represents the data written to wifi conf resource
 */
typedef void (*oc_wes_wifi_prov_cb_t)(oc_wes_wifi_data_t *);

/**
 * A function pointer for registering device callback
 * @param payload Represents the data written to device conf resource
 */
typedef void (*oc_wes_dev_prov_cb_t)(oc_wes_device_data_t *);

/**
 * This function populates WiFi EasySetup resources when application call
 * oc_add_device
 * This function will be invoked from IoT core when device configuration
 * resources are populated.
 *
 * @param device	Index of the the device application created
 *
 * @return ::OC_WES_OK on success, some other value upon failure.
 */
void oc_create_wifi_easysetup_resource(size_t device);

/**
 * This function performs termination of all WiFi Easy Setup Resources
 * populated for device
 *
 * @param device	Index of the the device application created
 *
 * @return ::void
 */
void oc_delete_wifi_easysetup_resource(size_t device);

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
 * @param free_cb callback to free allocated memory of user data in
 * oc_wes_wifi_data_t, oc_wes_device_data_t.
 *
 * @return ::OC_WES_OK on success, some other value upon failure.
 *
 * @see oc_es_read_userdata_cb_t
 * @see oc_es_write_userdata_cb_t
 */
oc_es_result_t oc_wes_set_resource_callbacks(size_t device, oc_wes_prov_cb_t wes_prov_cb,
	oc_wes_wifi_prov_cb_t wifi_prov_cb, oc_wes_dev_prov_cb_t dev_prov_cb);

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
 * @param freecb callback to free allocated memory of user data in
 * oc_wes_data_t, oc_wes_wifi_data_t, oc_wes_device_data_t.
 *
 * @return ::OC_WES_OK on success, some other value upon failure.
 *
 * @see oc_es_read_userdata_cb_t
 * @see oc_es_write_userdata_cb_t
 */
oc_es_result_t oc_wes_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
                                         oc_es_write_userdata_cb_t writecb,
                                         oc_es_free_userdata_cb_t freecb);

/**
 * This function sets Device information.
 *
 * @param device_info Contains device information composed of WiFiConf
 * Structure & Device Structure
 *
 * @return ::OC_WES_OK on success, some other value upon failure.
 *
 * @see oc_wes_device_info_t
 */
oc_es_result_t oc_wes_set_device_info(size_t device, oc_wes_device_info_t *device_info);

/**
 * This function Sets Enrollee's Error Code.
 *
 * @param wes_err_code Contains Enrollee's error code.
 * @return ::OC_WES_OK on success, some other value upon failure.
 *
 * @see oc_wes_error_code_t
 */
oc_es_result_t oc_wes_set_error_code(size_t device, oc_wes_error_code_t err_code);

/**
 * This function sets WiFi Enrollee's State.
 *
 * @param es_state   Contains current enrollee's state.
 * @return ::OC_WES_OK on success, some other value upon failure.
 *
 * @see oc_wes_enrollee_state_t
 */
oc_es_result_t oc_wes_set_state(size_t device, oc_wes_enrollee_state_t es_state);

/**
 * This function gets WiFi Enrollee's State.
 *
 * @return ::oc_wes_enrollee_state_t
 *
 * @see oc_wes_enrollee_state_t
 */
oc_wes_enrollee_state_t oc_wes_get_state(size_t device);

/**
 * A function pointer for registering esim easysetup callback
 * @param payload Represents the data written to ees resource
 */
typedef void (*oc_ees_prov_cb_t)(oc_ees_data_t *);

/**
 * A function pointer for registering rsp callback
 * @param payload Represents the data written to rsp conf resource
 */
typedef void (*oc_ees_rsp_prov_cb_t)(oc_ees_rsp_data_t *);

/**
 * A function pointer for registering rsp capability callback
 * @param payload Represents the data written to rspcap conf resource
 */
typedef void (*oc_ees_rspcap_prov_cb_t)(oc_ees_rspcap_data_t *);

/**
 * This function populates ESIM EasySetup resources when application call
 * oc_add_device
 * This function will be invoked from IoT core when device configuration
 * resources are populated.
 *
 * @param device	Index of the the device application created
 *
 * @return ::OC_EES_OK on success, some other value upon failure.
 */
void oc_create_esim_easysetup_resource(size_t device);

/**
 * This function performs termination of all ESIM Easy Setup Resources
 * populated for device
 *
 * @param device	Index of the the device application created
 *
 * @return ::void
 */
void oc_delete_esim_easysetup_resource(size_t device);

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
 * oc_wes_data_t, oc_wes_wifi_data_t, oc_wes_device_data_t.
 *
 * @return ::OC_EES_OK on success, some other value upon failure.
 *
 * @see oc_es_read_userdata_cb_t
 * @see oc_es_write_userdata_cb_t
 */
 oc_es_result_t oc_ees_set_resource_callbacks(size_t device, oc_ees_prov_cb_t ees_prov_cb,
	oc_ees_rsp_prov_cb_t rsp_prov_cb, oc_ees_rspcap_prov_cb_t rspcap_prov_cb);

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
 * @param freecb callback to free allocated memory of user data in
 * oc_ees_data_t, oc_ees_rsp_data_t and oc_ees_rspcap_data_t.
 *
 * @return ::OC_EES_OK on success, some other value upon failure.
 *
 * @see oc_es_read_userdata_cb_t
 * @see oc_es_write_userdata_cb_t
 */
oc_es_result_t oc_ees_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
                                         oc_es_write_userdata_cb_t writecb,
                                         oc_es_free_userdata_cb_t freecb);

/**
 * This function sets Device information.
 *
 * @param device_info Contains device information composed of
 * RspCapabilityConf Structure
 *
 * @return ::OC_EES_OK on success, some other value upon failure.
 *
 * @see oc_wes_device_info_t
 */
oc_es_result_t oc_ees_set_device_info(size_t device, oc_ees_device_info_t *device_info);

/**
 * This function Sets Enrollee's Error Code.
 *
 * @param ees_err_code Contains Enrollee's error code.
 * @return ::OC_EES_OK on success, some other value upon failure.
 *
 * @see oc_ees_error_code_t
 */
oc_es_result_t oc_ees_set_error_code(size_t device, oc_string_t err_code);

/**
 * This function sets Esim Enrollee's State.
 *
 * @param es_state   Contains current enrollee's state.
 * @return ::OC_EES_OK on success, some other value upon failure.
 *
 * @see oc_ees_enrollee_state
 */
oc_es_result_t oc_ees_set_state(size_t device, oc_string_t es_state);

/**
 * This function gets Esim Enrollee's State.
 *
 * @return ::oc_ees_enrollee_state
 *
 * @see oc_ees_enrollee_state
 */
oc_string_t oc_ees_get_state(size_t device);

/**
 * A set of functions pointers for callback functions which are called after
 * Wi-Fi Easysetup provisioning data is received from Mediator.
 */
typedef struct
{
	void (*oc_wes_prov_cb_t)(oc_wes_data_t *);
	void (*oc_wes_wifi_prov_cb_t)(oc_wes_wifi_data_t *);
	void (*oc_wes_dev_prov_cb_t)(oc_wes_device_data_t *);
} wes_device_callbacks_s;

/**
 * A set of functions pointers for callback functions which are called after
 * ESIM Easysetup provisioning data is received from Mediator.
 */
typedef struct
{
	void (*oc_ees_prov_cb_t)(oc_ees_data_t *);
	void (*oc_ees_rsp_prov_cb_t)(oc_ees_rsp_data_t *);
	void (*oc_ees_rspcap_prov_cb_t)(oc_ees_rspcap_data_t *);
} ees_device_callbacks_s;

typedef struct
{
	void (*oc_es_write_userdata_cb_t)(oc_rep_t *, char *);
	void (*oc_es_read_userdata_cb_t)(oc_rep_t *, char *, void **);
	void (*oc_es_free_userdata_cb_t)(void *, char *);
} es_userdata_callbacks_s;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* _OC_EASYSETUP_ENROLLEE_H_ */

