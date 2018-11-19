/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef ES_ENROLLEE_COMMON_H
#define ES_ENROLLEE_COMMON_H

#include "stdint.h"

#include "es_common.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * @brief Data structure delivered from mediator, which provides Cloud server
 * information.
 */
typedef struct
{
  oc_string_t auth_code;             /**< Auth Code issued by OAuth2.0-compatible account server. */
  oc_string_t access_token;          /**< Access Token resolved with an auth code. */
  oauth_tokentype access_token_type; /**< Access Token Type */
  oc_string_t auth_provider;         /**< Auth Provider ID*/
  oc_string_t ci_server;             /**< Cloud Interface Server URL which an Enrollee is going to registered. */
  oc_string_t sid;                   /**< OCF Cloud Identity as defined in OCF CNC 2.0 Spec. */
  void *userdata;                    /**< Vender Specific data. */
} es_coap_cloud_conf_data;

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
} es_device_property;

/**
 * A set of functions pointers for callback functions which are called after
 * provisioning data is received from Mediator.
 */
typedef struct
{
  void (*connect_request_cb)(es_connect_request *);  /**< Callback to direct Enrollee for initiating connection. */
  void (*wifi_prov_cb)(es_wifi_conf_data *);         /**< Callback to receive wifi configuaration. */
  void (*dev_conf_prov_cb)(es_dev_conf_data *);      /**< Callback to receive device configuaration. */
  void (*cloud_data_prov_cb)(es_coap_cloud_conf_data *); /**< Callback to receive cloud configuaration. */
} es_provisioning_callbacks_s;

#ifdef __cplusplus
}
#endif

#endif /* ES_ENROLLEE_COMMON_H */
