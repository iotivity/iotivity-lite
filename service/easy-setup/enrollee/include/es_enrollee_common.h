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
  es_connect_type connect[NUM_CONNECT_TYPE];
  int num_request;
} es_connect_request;

/**
 * @brief Data structure delivered from Mediator, which provides Wi-Fi
 * information.
 */
typedef struct
{
  oc_string_t ssid;       // ssid of the Enroller
  oc_string_t pwd;        // pwd of the Enroller
  wifi_authtype authtype; // auth type of the Enroller
  wifi_enctype enctype;   // encryption type of the Enroller
  void *userdata;         // vender-specific data
} es_wifi_conf_data;

/**
 * @brief Data structure delivered from Mediator, which provides device
 * configuration information.
 */
typedef struct
{
  void *userdata; // vender-specific data
} es_dev_conf_data;

/**
 * @brief Data structure delivered from mediator, which provides Cloud server
 * information.
 */
typedef struct
{
  oc_string_t auth_code;             // auth code issued by
                                     // OAuth2.0-compatible account server
  oc_string_t access_token;          // access token resolved with an auth
                                     // code
  oauth_tokentype access_token_type; // access token type
  oc_string_t auth_provider;         // auth provider ID
  oc_string_t ci_server;             // cloud interface server URL which
                                     // an Enrollee is
                                     // going to registered
  void *userdata;                    // vender-specific data
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
    wifi_mode supported_mode[NUM_WIFIMODE];
    wifi_freq supported_freq;
  } WiFi;

  /**
   * @brief Data structure indicating device configuration of Enrollee.
   */
  struct
  {
    oc_string_t device_name;
  } DevConf;
} es_device_property;

/**
 * A set of functions pointers for callback functions which are called after
 * provisioning data is
 * received from Mediator.
 */
typedef struct
{
  void (*connect_request_cb)(es_connect_request *);
  void (*wifi_prov_cb)(es_wifi_conf_data *);
  void (*dev_conf_prov_cb)(es_dev_conf_data *);
  void (*cloud_data_prov_cb)(es_coap_cloud_conf_data *);
} es_provisioning_callbacks_s;

#ifdef __cplusplus
}
#endif

#endif /* ES_ENROLLEE_COMMON_H */
