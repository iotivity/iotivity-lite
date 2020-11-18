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
    oc_es_connect_type_t connect[NUM_CONNECT_TYPE];
    int num_request;
    oc_wes_enrollee_state_t state;
    oc_wes_error_code_t last_err_code;
} oc_wes_data_t;

/**
 * @brief Data structure delivered from Mediator, which provides Wi-Fi
 * information.
 */
typedef struct
{
    oc_string_t ssid;
    oc_string_t cred;
    oc_string_t auth_type;
    oc_string_t enc_type;
    oc_string_t supported_mode[NUM_WIFIMODE];
    uint8_t num_mode;
    oc_string_t supported_freq[NUM_WIFIFREQ];
    uint8_t num_freq;
    oc_string_t supported_authtype[NUM_WIFIAUTHTYPE];
    uint8_t num_supported_authtype;
    oc_string_t supported_enctype[NUM_WIFIENCTYPE];
    uint8_t num_supported_enctype;
} oc_wes_wifi_data_t;

/**
 * @brief Data structure delivered from Mediator, which provides device
 * configuration information.
 */
typedef struct
{
    oc_string_t dev_name;
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
    oc_string_t supported_mode[NUM_WIFIMODE];  /**< Supported Wi-Fi modes e.g. 802.11 A / B / G / N etc. */
    oc_string_t supported_freq[NUM_WIFIFREQ];   /**< supported Wi-Fi frequency e.g. 2.4G, 5G etc. */
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
    oc_string_t end_user_consent;
} oc_ees_data_t;

/**
 * @brief Data structure for remote SIM provisioning
 * request from Mediator.
 */
typedef struct
{
    oc_string_t activation_code;
    oc_string_t profile_metadata;
    oc_string_t confirm_code;
    bool confirm_code_required;
} oc_ees_rsp_data_t;

/**
 * @brief Data structure for device info
 * read by Mediator.
 */
 typedef struct
{
    oc_string_t euicc_info;
    oc_string_t device_info;
} oc_ees_rspcap_data_t;

/**
 * A function pointer for registering wifi easysetup callback
 *
 * @param payload Represents the data written to wes resource
 * @param user_data User-specific data free up it's memory.
 *
 * @see oc_wes_data_t
 */
typedef void (*oc_wes_prov_cb_t)(oc_wes_data_t *wes_prov_data, void *user_data);

/**
 * A function pointer for registering wifi callback
 *
 * @param payload Represents the data written to wifi conf resource
 * @param user_data User-specific data free up it's memory.
 *
 * @see oc_wes_wifi_data_t
 */
typedef void (*oc_wes_wifi_prov_cb_t)(oc_wes_wifi_data_t *wifi_prov_data,  void *user_data);

/**
 * A function pointer for registering device callback
 *
 * @param payload Represents the data written to device conf resource
 * @param user_data User-specific data free up it's memory.
 *
 * @see oc_wes_device_data_t
 */
typedef void (*oc_wes_dev_prov_cb_t)(oc_wes_device_data_t *device_prov_data,  void *user_data);

/**
 * This function populates WiFi EasySetup resources when application call
 * oc_add_device
 * This function will be invoked from IoT core when device configuration
 * resources are populated.
 *
 * @param device	Index of the the device application created
 * @param user_data User-specific data you want to deliver to application
 * The user should know a data structure of passed userdata.
 */
void oc_create_wifi_easysetup_resource(size_t device, void *user_data);

/**
 * This function performs termination of all WiFi Easy Setup Resources
 * populated for device
 *
 * @param device	Index of the the device application created
 */
void oc_delete_wifi_easysetup_resource(size_t device);

/**
 * This function resets all the properties of all WiFi Easy Setup Resources
 * populated for device
 *
 * @param device	Index of the the device application created
 */
void oc_wes_reset_resources(size_t device);

/**
 * This function is to set three function pointers to handle updates on
 * WiFi Easysetup resources
 *
 * @param device	Index of the the device application created
 * @param wes_prov_cb a callback for passing wes resource data and user context
 * @param wifi_prov_cb a callback for passing wificonf resource data and user context
 * @param dev_prov_cb callback for passing deviceconf resource data and user context
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_wes_prov_cb_t
 * @see oc_wes_wifi_prov_cb_t
 * @see oc_wes_dev_prov_cb_t
 */
oc_es_result_t oc_wes_set_resource_callbacks(size_t device, oc_wes_prov_cb_t wes_prov_cb,
	oc_wes_wifi_prov_cb_t wifi_prov_cb, oc_wes_dev_prov_cb_t dev_prov_cb);

/**
 * This function sets Device information.
 *
 * @param device	Index of the the device application created
 * @param supported_mode[] indicates supported wifi models
 * @param supported_freq indicates supported wifi frequencies
 * @param device_name indicates name of the device
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see wifi_mode
 * @see wifi_freq
 */
oc_es_result_t oc_wes_set_device_info(size_t device, wifi_mode supported_mode[],
						wifi_freq supported_freq[], char *device_name);

/**
 * This function Sets Enrollee's Error Code.
 *
 * @param device	Index of the the device application created
 * @param err_code Contains Enrollee's error code.
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_wes_error_code_t
 */
oc_es_result_t oc_wes_set_error_code(size_t device, oc_wes_error_code_t err_code);

/**
 * This function sets WiFi Enrollee's State.
 *
 * @param device	Index of the the device application created
 * @param es_state   Contains current enrollee's state.
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_wes_enrollee_state_t
 */
oc_es_result_t oc_wes_set_state(size_t device, oc_wes_enrollee_state_t es_state);

/**
 * This function gets WiFi Enrollee's State.
 *
 * @param device	Index of the the device application created
 *
 * @return wifi enrolee onboarding status
 *
 * @see oc_wes_enrollee_state_t
 */
oc_wes_enrollee_state_t oc_wes_get_state(size_t device);

/**
 * A function pointer for registering esim easysetup callback
 *
 * @param payload Represents the data written to ees resource
 * @param user_data User-specific data free up it's memory.
 *
 * @see oc_ees_data_t
 */
typedef void (*oc_ees_prov_cb_t)(oc_ees_data_t *ees_prov_data, void *user_data);

/**
 * A function pointer for registering rsp callback
 *
 * @param payload Represents the data written to rsp conf resource
 * @param user_data User-specific data free up it's memory.
 *
 * @see oc_ees_rsp_data_t
 */
typedef void (*oc_ees_rsp_prov_cb_t)(oc_ees_rsp_data_t *rsp_prov_data, void *user_data);

/**
 * A function pointer for registering rsp capability callback
 *
 * @param payload Represents the data written to rspcapability resource
 * @param user_data User-specific data free up it's memory.
 *
 * @see oc_ees_rspcap_data_t
 */
typedef void (*oc_ees_rspcap_prov_cb_t)(oc_ees_rspcap_data_t *rspcap_prov_data, void *user_data);

/**
 * This function populates ESIM EasySetup resources when application call
 * oc_add_device
 * This function will be invoked from IoT core when device configuration
 * resources are populated.
 *
 * @param device	Index of the the device application created
 * @param user_data User-specific data you want to deliver to applicatoin
 * The user should know a data structure of passed userdata.
 */
void oc_create_esim_easysetup_resource(size_t device, void *user_data);

/**
 * This function performs termination of all ESIM Easy Setup Resources
 * populated for device
 *
 * @param device	Index of the the device application created
 */
void oc_delete_esim_easysetup_resource(size_t device);

/**
 * This function resets all the properties of all ESIM Easy Setup Resources
 * populated for device
 *
 * @param device	Index of the the device application created
 */
void oc_ees_reset_resources(size_t device);

/**
 * This function is to set three function pointers to handle updates on
 * eSIM Easysetup resources
 *
 * @param device	Index of the the device application created
 * @param ees_prov_cb a callback for passing ees resource data and user context
 * @param rsp_prov_cb a callback for passing rspconf resource data and user context
 * @param rspcap_prov_cb callback for passing rspcapability resource data and user context
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 *
 * @see oc_ees_prov_cb_t
 * @see oc_ees_rsp_prov_cb_t
 * @see oc_ees_rspcap_prov_cb_t
 */
 oc_es_result_t oc_ees_set_resource_callbacks(size_t device, oc_ees_prov_cb_t ees_prov_cb,
	oc_ees_rsp_prov_cb_t rsp_prov_cb, oc_ees_rspcap_prov_cb_t rspcap_prov_cb);

/**
 * This function sets Device information.
 *
 * @param device	Index of the the device application created
 * @param euicc_info contains eSIM information as per GSMA EUICCInfo2 data structure
 * @param device_info Contains device information
 * @param profile_metadata Contains eSIM Profile meatadata
 * RspCapabilityConf Structure
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 */
oc_es_result_t oc_ees_set_device_info(size_t device, char *euicc_info, char *device_info,
	char *profile_metadata);

/**
 * This function Sets User Confirmation required for profile dwnload.
 *
 * @param device	Index of the the device application created
 * @param ccr User Confirmation Code required
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 */
oc_es_result_t oc_ees_set_confirmation_code_required(size_t device, bool ccr);

/**
 * This function Sets Enrollee's Error Code.
 *
 * @param device	Index of the the device application created
 * @param err_code Contains Enrollee's error code.
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 */
oc_es_result_t oc_ees_set_error_code(size_t device, char *err_code);

/**
 * This function sets Esim Enrollee's State.
 *
 * @param device	Index of the the device application created
 * @param es_state  Contains current enrollee's state.
 *
 * @return ::OC_ES_OK on success, some other value upon failure.
 */
oc_es_result_t oc_ees_set_state(size_t device, char *es_state);

/**
 * This function gets Esim Enrollee's State.
 *
 * @param device	Index of the the device application created
 *
 * @return :: string representing esim enrollee status
 */
char *oc_ees_get_state(size_t device);

/**
 * A set of functions pointers for callback functions which are called after
 * Wi-Fi Easysetup provisioning data is received from Mediator.
 */
typedef struct
{
	void (*oc_wes_prov_cb_t)(oc_wes_data_t *, void *);
	void (*oc_wes_wifi_prov_cb_t)(oc_wes_wifi_data_t *, void *);
	void (*oc_wes_dev_prov_cb_t)(oc_wes_device_data_t *, void *);
} wes_device_callbacks_s;

/**
 * A set of functions pointers for callback functions which are called after
 * ESIM Easysetup provisioning data is received from Mediator.
 */
typedef struct
{
	void (*oc_ees_prov_cb_t)(oc_ees_data_t *, void *);
	void (*oc_ees_rsp_prov_cb_t)(oc_ees_rsp_data_t *, void *);
	void (*oc_ees_rspcap_prov_cb_t)(oc_ees_rspcap_data_t *, void *);
	void (*oc_wes_wifi_prov_cb_t)(oc_wes_wifi_data_t *, void *);
} ees_device_callbacks_s;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* _OC_EASYSETUP_ENROLLEE_H_ */
