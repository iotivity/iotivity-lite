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

#ifndef SC_EASYSETUP_H
#define SC_EASYSETUP_H

#include "es_common.h"

#define WIFI_DISCOVERY_CHANNEL_INIT -1

/**
 * @brief  Supported WIFI frequency like 2.4G and 5G
 */
typedef enum
{
    NET_STATE_INIT = -1,                /**< Init state **/
    NET_STATE_WIRED_CONNECTED = 0,      /**< Wired connected **/
    NET_STATE_WIRELESS_CONNECTED,       /**< Wireless connected **/
    NET_STATE_NOT_CONNECTED             /**< Not connected, at all **/
} sc_networkstate_t;

typedef struct
{
  /**< Wi-Fi AP Channel used for fast discovery **/
  int disc_channel;
  /**< Wi-Fi bssid information. **/
  oc_string_t bssid;
} sc_wifi_conf_properties;

typedef struct
{
  /**< Terms & Conditions header **/
  oc_string_t header;
  /**< Terms & Conditions version **/
  oc_string_t version;
} sc_tnc_info;

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
  //sc_tnc_info tnc_info;
  /**< Samsung-specific model number **/
  //oc_string_t model;
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

#define sc_prop_set_net_conn_state(sc_prop, state) sc_prop.net_conn_state = state
#define sc_prop_set_reg_device(sc_prop, reg_set_dev) oc_new_string(&sc_prop.reg_set_dev, reg_set_dev)
#define sc_prop_set_net_prov_info(sc_prop, net_prov_info) oc_new_string(&sc_prop.net_prov_info, net_prov_info)
#define sc_prop_set_tnc_info(sc_prop, tnc_info) sc_prop.tnc_info = tnc_info
#define sc_prop_set_tnc_status(sc_prop, tnc_status) sc_prop.tnc_status = tnc_status
#define sc_prop_set_pnp_pin(sc_prop, pnp_pin) oc_new_string(&sc_prop.pnp_pin, pnp_pin)
#define sc_prop_set_es_protocol_ver(sc_prop, es_protocol_ver) oc_new_string(&sc_prop.es_protocol_ver, es_protocol_ver)

// user data callbacks to set to easysetup
void sc_read_userdata_cb(oc_rep_t* payload, char* resource_type, void** user_data);
void sc_write_userdata_cb(oc_rep_t* payload, char* resource_type);
void sc_free_userdata(void *user_data, char* resource_type);

sc_properties* get_sc_properties(void);
es_result_e set_sc_properties(sc_properties *prop);
es_result_e reset_sc_properties(void);

// --- "/sec/provisioninginfo" resource related code ----- 
typedef struct
{
  oc_string_t target_di;
  oc_string_t target_rt;
  bool published;
} sec_provisioning_info_targets;

typedef struct
{
  sec_provisioning_info_targets *targets;
  int targets_size;
  bool owned;
  oc_string_t easysetup_di;
} sec_provisioning_info;

es_result_e init_provisioning_info_resource(
  sec_provisioning_info *prov_info);
es_result_e set_sec_prov_info(sec_provisioning_info *prov_info);
es_result_e deinit_provisioning_info_resource(void);

#endif /* SC_EASYSETUP_H */