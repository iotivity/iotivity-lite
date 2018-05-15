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

#ifndef ES_RESOURCE_HANDLER_H
#define ES_RESOURCE_HANDLER_H

#include "es_enrollee_common.h"
#include "es_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*es_connect_request_cb)(es_result_e, es_connect_request *);
typedef void (*es_wifi_conf_cb)(es_result_e, es_wifi_conf_data *);
typedef void (*es_coap_cloud_conf_cb)(es_result_e, es_coap_cloud_conf_data *);
typedef void (*es_dev_conf_cb)(es_result_e, es_dev_conf_data *);

#define  es_free_property(property) if(oc_string_len(property) > 0) oc_free_string(&property);
#define set_custom_property_str(object, key, value)                            \
  if (value)                                                                   \
  oc_rep_set_text_string(object, key, value)
#define set_custom_property_int(object, key, value) oc_rep_set_int(object, key, value)
#define set_custom_property_bool(object, key, value) oc_rep_set_boolean(object, key, value)

typedef struct
{
  oc_resource_t *handle;
  prov_status status;
  es_error_code last_err_code;
  es_connect_type connect_request[NUM_CONNECT_TYPE];
  int num_request;
} easy_setup_resource;

typedef struct
{
  oc_resource_t *handle;
  wifi_mode supported_mode[NUM_WIFIMODE];
  uint8_t num_mode;
  wifi_freq supported_freq;
  wifi_authtype supported_authtype[NUM_WIFIAUTHTYPE];
  uint8_t num_supported_authtype;
  wifi_enctype supported_enctype[NUM_WIFIENCTYPE];
  uint8_t num_supported_enctype;
  oc_string_t ssid;
  oc_string_t cred;
  wifi_authtype auth_type;
  wifi_enctype enc_type;
} wifi_conf_resource;

typedef struct
{
  oc_resource_t *handle;
  oc_string_t auth_code;
  oc_string_t access_token;
  oauth_tokentype access_token_type;
  oc_string_t auth_provider;
  oc_string_t ci_server;
} coap_cloud_conf_resource;

typedef struct
{
  oc_resource_t *handle;
  oc_string_t dev_name;
} dev_conf_resource;

es_result_e create_easysetup_resources(bool is_secured,
                                       es_resource_mask_e resource_mask);
es_result_e delete_easysetup_resources(void);

es_result_e set_device_property(es_device_property *device_property);
es_result_e set_enrollee_state(es_enrollee_state es_state);
es_result_e set_enrollee_err_code(es_error_code es_err_code);

void resgister_wifi_rsrc_event_callback(es_wifi_conf_cb);
void register_cloud_rsrc_event_callback(es_coap_cloud_conf_cb);
void register_devconf_rsrc_event_callback(es_dev_conf_cb);
void register_connect_request_event_callback(es_connect_request_cb cb);
void unregister_resource_event_callback(void);
es_result_e set_callback_for_userdata(es_read_userdata_cb readcb,
                                      es_write_userdata_cb writecb);
void oc_allocate_string(oc_string_t *desString, char *srcString);

#ifdef __cplusplus
}
#endif

#endif // ES_RESOURCE_HANDLER_H