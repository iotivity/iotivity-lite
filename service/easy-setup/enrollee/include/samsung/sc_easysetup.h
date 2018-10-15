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

/**
  @brief Samsung Specfic Enrollee APIs of Iotivity-constrained.
  @file
 */

#ifndef SC_EASYSETUP_H
#define SC_EASYSETUP_H

#include "es_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *@brief  WIFI discovery channel init value.
 */
#define WIFI_DISCOVERY_CHANNEL_INIT -1

/**
 * @brief  Supported WIFI frequency like 2.4G and 5G
 */
typedef enum {
  NET_STATE_INIT = -1,           /**< Init state **/
  NET_STATE_WIRED_CONNECTED = 0, /**< Wired connected **/
  NET_STATE_WIRELESS_CONNECTED,  /**< Wireless connected **/
  NET_STATE_NOT_CONNECTED        /**< Not connected, at all **/
} sc_networkstate_t;

/**
 *@brief Structure to store samsung specific wifi configuration properties.
 */
typedef struct
{
  /**< Wi-Fi AP Channel used for fast discovery **/
  int disc_channel;
  /**< Wi-Fi bssid information. **/
  oc_string_t bssid;
} sc_wifi_conf_properties;

/**
 *@brief Structure to store terms and conditions information.
 */
typedef struct
{
  /**< Terms & Conditions header **/
  oc_string_t header;
  /**< Terms & Conditions version **/
  oc_string_t version;
} sc_tnc_info;

/**
 *@brief Structure to store samsung specific device configuration properties.
 */
typedef struct
{
  /**< Samsung-specific location-related information **/
  oc_string_array_t location;
  /**< Samsung-specific mobile device information for 'register TV' **/
  oc_string_t reg_mobile_dev;
  /**< Samsung-specific account-related information **/
  oc_string_t account;
  /**< Samsung-specific SSO list information which is registered in device **/
  oc_string_t sso_list;
  /**< Samsung-specific Terms & Conditions information **/
  // sc_tnc_info tnc_info;
  /**< Samsung-specific model number **/
  // oc_string_t model;
  /**< IETF language tag using ISO 639X **/
  oc_string_t language;
  /**< ISO Country Code (ISO 3166-1 Alpha-2) **/
  oc_string_t country;
  /**< GPS information of device. Longitude and latitude in json format **/
  oc_string_t gps_location;
  /**< UTC date time **/
  oc_string_t utc_date_time;
  /**< Regional date time **/
  oc_string_t regional_date_time;
} sc_dev_conf_properties;

/**
 *@brief Structure to store samsung specific cloud configuration properties.
 */
typedef struct
{
  /**< Samsung-specific clientId for sign-up to IoT Cloud **/
  oc_string_t client_id;
  /**< Samsung-specific aac information **/
  oc_string_t aac;
  /**< Samsung-specific Terms & Conditions result **/
  oc_string_t tnc_result;
  /**
   * < Samsung-specific refreshToken information.
   * Indicate refresh token to be used if the access token is expired
   */
  oc_string_t refresh_token;
  /**
   * < Samsung-specific aac information.
   * Indicate user ID corresponding to user account
   */
  oc_string_t uid;
} sc_cloud_server_conf_properties;

/**
 *@brief Structure to store samsung specific properties.
 */
typedef struct
{
  /**< A state of network connection **/
  sc_networkstate_t net_conn_state;
  /**< Wi-Fi AP Channel used for fast discovery **/
  int disc_channel;
  /**< Generated with Device Type + Icon Type **/
  oc_string_t device_type;
  /**< Device Sub Category **/
  oc_string_t device_sub_type;
  /**< Samsung-specific location-related information **/
  oc_string_array_t location;
  /**< Samsung-specific clientId for sign-up to IoT Cloud **/
  oc_string_t client_id;
  /**< Samsung-specific mobile device information for 'register TV' **/
  oc_string_t reg_mobile_dev;
  /**< Samsung-specific set device information for 'register TV' **/
  oc_string_t reg_set_dev;
  /**< Samsung-specific network provisioning information for cellular network
   * vendor **/
  oc_string_t net_prov_info;
  /**< Samsung-specific account-related information **/
  oc_string_t account;
  /**< Samsung-specific SSO list information which is registered in device **/
  oc_string_t sso_list;
  /**< Samsung-specific aac information **/
  oc_string_t aac;
  /**< Samsung-specific Terms & Conditions information **/
  sc_tnc_info tnc_info;
  /**< Samsung-specific Terms & Conditions result **/
  oc_string_t tnc_result;
  /**< Samsung-specific Terms & Conditions status **/
  int tnc_status;
  /**
   * < Samsung-specific refreshToken information.
   * Indicate refresh token to be used if the access token is expired
   */
  oc_string_t refresh_token;
  /**< Samsung-specific aac information. Indicate user ID corresponding to user
   * account **/
  oc_string_t uid;
  /**< Samsung-specific Wi-Fi bssid information. **/
  oc_string_t bssid;
  /**< Samsung-specific PnP Pin **/
  oc_string_t pnp_pin;
  /**< Samsung-specific model number **/
  oc_string_t model;
  /**< IETF language tag using ISO 639X **/
  oc_string_t language;
  /**< ISO Country Code (ISO 3166-1 Alpha-2) **/
  oc_string_t country;
  /**< GPS information of device. Longitude and latitude in json format **/
  oc_string_t gps_location;
  /**< UTC date time **/
  oc_string_t utc_date_time;
  /**< Regional date time **/
  oc_string_t regional_date_time;
  /**< Samsung Easy Setup Protocol Version **/
  oc_string_t es_protocol_ver;
} sc_properties;

/**
 *@brief A macro to set network connection state for samsung specific properties.
 *@param state Network Connection State
 */
#define sc_prop_set_net_conn_state(sc_prop, state)                             \
  sc_prop.net_conn_state = state
/**
 *@brief A macro to set registered device for samsung specific properties.
 *@param reg_set_dev Information of registered device
 */
#define sc_prop_set_reg_device(sc_prop, reg_set_dev)                           \
  oc_new_string(&sc_prop.reg_set_dev, reg_set_dev)
/**
 *@brief A macro to set network provisioning information for samsung specific properties.
 *@param net_prov_info Network Provisioning Information
 */
#define sc_prop_set_net_prov_info(sc_prop, net_prov_info)                      \
  oc_new_string(&sc_prop.net_prov_info, net_prov_info)
/**
 *@brief A macro to set terms and conditions information for samsung specific properties.
 *@param tnc_info Terms and conditions information
 */
#define sc_prop_set_tnc_info(sc_prop, tnc_info) sc_prop.tnc_info = tnc_info
/**
 *@brief A macro to set terms and conditions status for samsung specific properties.
 *@param state Status of terms and conditions information which is given to mediator.
 */
#define sc_prop_set_tnc_status(sc_prop, tnc_status)                            \
  sc_prop.tnc_status = tnc_status
/**
 *@brief A macro to set pnp pin for samsung specific properties.
 *@param state Network Connection State
 */
#define sc_prop_set_pnp_pin(sc_prop, pnp_pin)                                  \
  oc_new_string(&sc_prop.pnp_pin, pnp_pin)
/**
 *@brief A macro to set easy setup protocol version for samsung specific properties.
 *@param es_protocol_ver Easy Setup protocol version.
 */
#define sc_prop_set_es_protocol_ver(sc_prop, es_protocol_ver)                  \
  oc_new_string(&sc_prop.es_protocol_ver, es_protocol_ver)

// user data callbacks to set to easysetup
/**
 *@brief A callback funtion for parsing samsung specific user properties from POST request.
 *@param payload Represents a received POST request. If you know user-specific
 *property key,
 *then you can extract a corresponding value if it exists.
 *@param resource_type Used to distinguish which resource the received property
 *belongs to
 *@param user_data User-specific data you want to deliver to desired users,
 *i.e.application.
 */
void sc_read_userdata_cb(oc_rep_t *payload, char *resource_type,
                         void **user_data);
/**
 *@brief A callback funtion for putting samsung specific user properties to a response to be sent.
 *@param payload Represents a response. You can set a specific value with
 *specific property key
 *to the payload. If a client receives the response and know the property key,
 *then it can
 *extract the value.
 *@param resource_type Used to distinguish which resource the received property
 *belongs to.
 */
void sc_write_userdata_cb(oc_rep_t *payload, char *resource_type);
/**
 *@brief A callback funtion for freeing allocated memory of samsung specific user data in
 *s_wifi_conf_data, es_dev_conf_data and es_coap_cloud_conf_data.
 *@param user_data User-specific data free up it's memory.
 *@param resource_type Used to distinguish which resource user data
 *beongs to.
 */
void sc_free_userdata(void *user_data, char *resource_type);

/**
 *@brief A function to get samsung specific properties.
 *@return sc_properties
 */
sc_properties *get_sc_properties(void);
/**
 *@brief A function to set samsung specific properties.
 *@param prop samsung specfic properties structure.
 *@return es_result_e Result of set operation.
 *@retval ES_OK if set is successful.
 *@retval ES_ERROR if input parameter is NULL.
 */
es_result_e set_sc_properties(sc_properties *prop);
/**
 *@brief A function reset samsung specific properties.
 *@return es_result_e Result of reset operation.
 *@retval ES_OK if reset is successful.
 */
es_result_e reset_sc_properties(void);

/**
 *@brief Struture to store provisioning information targets.
 */
typedef struct
{
  oc_string_t target_di;
  oc_string_t target_rt;
  bool published;
} sec_provisioning_info_targets;

/**
 *@brief The "/sec/provisioninginfo" resource data structure node.
 */
typedef struct
{
  sec_provisioning_info_targets *targets;
  int targets_size;
  bool owned;
  oc_string_t easysetup_di;
} sec_provisioning_info;

/**
 *@brief A function to initialize samsung specific provisioning info resource.
 *@param prov_info structure to store provisioning info resource.
 *@return es_result_e Result of init operation.
 *@retval ES_OK if initialization is successful.
 *@retval ES_ERROR if memory allocation failed for resource.
 */
es_result_e init_provisioning_info_resource(sec_provisioning_info *prov_info);
/**
 *@brief A function to set properties for provisioning info resource.
 *@param prov_info provisioning info resource.
 *@return es_result_e Result of set operation.
 *@retval ES_OK if set is successful.
 *@retval ES_ERROR if input parameter is NULL.
 */
es_result_e set_sec_prov_info(sec_provisioning_info *prov_info);
/**
 *@brief A function to deinitialize samsung specific provisioning info resource.
 *@return es_result_e Result of deinit operation.
 *@retval ES_OK if deinit is successful.
 */
es_result_e deinit_provisioning_info_resource(void);

/**
 *@brief The "/sec/accesspointlist" resource data structure node.
 */
typedef struct sec_accesspoint_s
{
  oc_string_t channel;
  oc_string_t enc_type;
  oc_string_t mac_address;
  oc_string_t max_rate;
  oc_string_t rssi;
  oc_string_t security_type;
  oc_string_t ssid;
  struct sec_accesspoint_s *next;
} sec_accesspoint;

/**
 *A function pointer for registering a callback to fetch
 *access point scanned list information.
 * @param ap_list accesspoint resource structure.
 */
typedef void (*get_ap_scan_list)(sec_accesspoint **ap_list);

/**
 *@brief A function to initialize samsung specific accesspointlist resource
 *@param prop .
 *@return es_result_e Result of get operation.
 *@retval ES_OK if set is successful.
 *@retval ES_ERROR if input parameter is NULL
*/
es_result_e init_accesspointlist_resource(get_ap_scan_list cb);
/**
 *@brief A function to deinitialize samsung specific accesspointlist resource
 *@return es_result_e Result of deinit operation.
 *@retval ES_OK if deinit is successful..
 */
es_result_e deinit_accesspointlist_resource(void);

#ifdef __cplusplus
}
#endif

#endif /* SC_EASYSETUP_H */
