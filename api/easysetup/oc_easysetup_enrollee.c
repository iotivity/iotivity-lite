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
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_config.h"
#include "oc_easysetup_enrollee.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_log.h"
#include "es_utils.h"

#ifdef OC_DYNAMIC_ALLOCATION
#define OC_MAX_NUM_DEVICES	10
#endif

#ifdef OC_WIFI_EASYSETUP

typedef struct
{
  oc_resource_t *handle;
  // This structure is synced with oc_wes_data
  struct
  {
    oc_es_connect_type_t connect_request[NUM_CONNECT_TYPE];
    int num_request;
    oc_es_enrollee_state state;
    oc_wes_error_code last_err_code;
  } data;
  oc_wes_prov_cb prov_cb;
} oc_wifi_es_resource_t;

#define es_res_cast(p) (oc_wifi_es_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
  // This structure is synced with oc_wes_wifi_data
  struct
  {
    oc_string_t ssid;
    oc_string_t cred;
    wifi_authtype auth_type;
    wifi_enctype enc_type;
    wifi_mode supported_mode[NUM_WIFIMODE];
    uint8_t num_mode;
    wifi_freq supported_freq;
    wifi_authtype supported_authtype[NUM_WIFIAUTHTYPE];
    uint8_t num_supported_authtype;
    wifi_enctype supported_enctype[NUM_WIFIENCTYPE];
    uint8_t num_supported_enctype;
  } data;
  oc_wes_wifi_prov_cb prov_cb;
} oc_es_wifi_conf_resource_t;

#define wifi_res_cast(p) (oc_es_wifi_conf_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
  struct
  {
    oc_string_t dev_name;
  } data;
  oc_wes_dev_prov_cb prov_cb;
} oc_es_dev_conf_resource_t;

#define dev_res_cast(p) (oc_es_dev_conf_resource_t *)(p)

typedef struct
{
  oc_wifi_es_resource_t wes;
  oc_es_wifi_conf_resource_t wifi;
  oc_es_dev_conf_resource_t device;
  oc_link_t *wifi_link;
  oc_link_t *device_link;
  oc_es_read_userdata_cb_t read_cb;
  oc_es_write_userdata_cb_t write_cb;
  oc_es_free_userdata_t free_cb;
} oc_wifi_enrollee_t;

// Global WiFi Enrolee Instance
oc_wifi_enrollee_t g_wifi_enrollee[OC_MAX_NUM_DEVICES];

oc_wifi_enrollee_t *get_wifi_device_context(size_t device)
{
  return &g_wifi_enrollee[device];
}

oc_es_result_t
oc_wes_set_device_info(size_t device, oc_wes_device_info *device_info)
{
  int modeIdx = 0;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->wifi.data.supported_freq = (device_info->WiFi).supported_freq;

  while ((device_info->WiFi).supported_mode[modeIdx] != WiFi_EOF) {
    dev_cxt->wifi.data.supported_mode[modeIdx] =
      (device_info->WiFi).supported_mode[modeIdx];
    modeIdx++;
  }
 dev_cxt->wifi.data.num_mode = modeIdx;
 oc_notify_observers(dev_cxt->wifi.handle);

 es_new_string(&(dev_cxt->device.data.dev_name),
               oc_string((device_info->DevConf).device_name));

 oc_notify_observers(dev_cxt->device.handle);
 return OC_ES_OK;
 }

oc_es_result_t
oc_wes_set_error_code(size_t device, oc_wes_error_code err_code)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  if (err_code < OC_WES_ERRCODE_NO_ERROR || err_code > OC_WES_ERRCODE_UNKNOWN) {
    OC_ERR("Invalid lec to set: %d", err_code);
    return OC_ES_ERROR;
  }
  dev_cxt->wes.data.last_err_code = err_code;
  oc_notify_observers(dev_cxt->wes.handle);
  return OC_ES_OK;
}

oc_es_result_t
oc_wes_set_state(size_t device, oc_es_enrollee_state es_state)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  if (es_state < OC_ES_STATE_INIT || es_state >= OC_ES_STATE_EOF) {
    OC_ERR("Invalid oc_es_set_state to set: %d", es_state);
    return OC_ES_ERROR;
  }
  dev_cxt->wes.data.state = es_state;
  
  oc_notify_observers( dev_cxt->wes.handle);
  return OC_ES_OK;
}

oc_es_enrollee_state
oc_wes_get_state(size_t device)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);
  return dev_cxt->wes.data.state;
}

oc_es_result_t oc_wes_set_resource_callbacks(size_t device, oc_wes_prov_cb wes_prov_cb,
	oc_wes_wifi_prov_cb wifi_prov_cb, oc_wes_dev_prov_cb dev_prov_cb)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->wes.prov_cb = wes_prov_cb;
  dev_cxt->wifi.prov_cb = wifi_prov_cb;
  dev_cxt->device.prov_cb = dev_prov_cb;
  
  return OC_ES_OK;
}

oc_es_result_t oc_wes_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
	oc_es_write_userdata_cb_t writecb, oc_es_free_userdata_t freecb)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->read_cb = readcb;
  dev_cxt->write_cb = writecb;
  dev_cxt->free_cb = freecb;
  return OC_ES_OK;
}

static void
construct_response_of_wificonf(oc_request_t *request)
{

  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

  oc_rep_start_root_object();
  oc_process_baseline_interface(dev_cxt->wifi.handle);

  oc_rep_set_array(root, swmt);
  for (int i = 0; i < dev_cxt->wifi.data.num_mode; i++) {
#ifdef OC_SPEC_VER_OIC
  // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
  oc_rep_add_int(swmt, (int)dev_cxt->wifi.data.supported_mode[i]);
#else
  // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
  oc_rep_add_text_string(swmt, oc_string(wifi_mode_enum_tostring(dev_cxt->wifi.data.supported_mode[i])));
#endif  // OC_SPEC_VER_OIC
  }

  oc_rep_close_array(root, swmt);

#ifdef OC_SPEC_VER_OIC
  // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
  es_rep_set_int(root, swf, (int)dev_cxt->wifi.data.supported_freq);
#else
  // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
  oc_rep_set_array(root, swf);

  switch(dev_cxt->wifi.data.supported_freq) {
     case WIFI_24G:
     case WIFI_5G :
       oc_rep_add_text_string(swf, oc_string(wifi_freq_enum_tostring(dev_cxt->wifi.data.supported_freq)));
       break;
     case WIFI_BOTH:
       oc_rep_add_text_string(swf, oc_string(wifi_freq_enum_tostring(WIFI_24G)));
       oc_rep_add_text_string(swf, oc_string(wifi_freq_enum_tostring(WIFI_5G)));
       break;
     case WIFI_FREQ_NONE:
       break;
  }
  oc_rep_close_array(root, swf);
#endif  // OC_SPEC_VER_OIC

  es_rep_set_text_string(root, tnn, oc_string(dev_cxt->wifi.data.ssid));
  es_rep_set_text_string(root, cd, oc_string(dev_cxt->wifi.data.cred));

#ifdef OC_SPEC_VER_OIC
  // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
  es_rep_set_int(root, wat, (int)dev_cxt->wifi.data.auth_type);
  es_rep_set_int(root, wet, (int)dev_cxt->wifi.data.enc_type);
#else
  // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
  es_rep_set_text_string(root, wat, oc_string(wifi_authtype_enum_tostring(dev_cxt->wifi.data.auth_type)));
  es_rep_set_text_string(root, wet, oc_string(wifi_enctype_enum_tostring(dev_cxt->wifi.data.enc_type)));

  // new properties in OCF 1.3 - swat and swet.
  oc_rep_set_array(root, swat);
  for (int i = 0; i < dev_cxt->wifi.data.num_supported_authtype; i++) {
    oc_rep_add_text_string(swat, oc_string(wifi_mode_enum_tostring(dev_cxt->wifi.data.supported_authtype[i])));
  }
  oc_rep_close_array(root, swat);

  oc_rep_set_array(root, swet);
  for (int i = 0; i < dev_cxt->wifi.data.num_supported_enctype; i++) {
    oc_rep_add_text_string(swet, oc_string(wifi_mode_enum_tostring(dev_cxt->wifi.data.supported_enctype[i])));
  }
  oc_rep_close_array(root, swet);
#endif  // OC_SPEC_VER_OIC

  // Invoke callback for user defined attributes
  if (dev_cxt->write_cb) {
    dev_cxt->write_cb(NULL, OC_RSRVD_WES_RES_TYPE_WIFICONF);
  }
  oc_rep_end_root_object();
}

static void
wificonf_get_handler(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  construct_response_of_wificonf(request);
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_wifi_conf_resource(oc_request_t *request)
{
  bool changed = false;
  oc_wes_wifi_data wifi_cb_data;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

  {
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_SSID, &str_val,
                          &str_len)) {
      es_new_string(&(dev_cxt->wifi.data.ssid), str_val);
      changed = true;
    }

    str_val = NULL;
    str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_CRED, &str_val,
                          &str_len)) {
      es_new_string(&(dev_cxt->wifi.data.cred), str_val);
      changed = true;
    }
  }

  {
#ifdef OC_SPEC_VER_OIC
    // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
    int64_t int_val = 0;
    if (oc_rep_get_int(request->request_payload, OC_RSRVD_WES_AUTHTYPE,
                       &int_val)) {
      dev_cxt->wifi.data.auth_type = int_val;
      changed = true;
    }

    if (oc_rep_get_int(request->request_payload, OC_RSRVD_WES_ENCTYPE,
                       &int_val)) {
      dev_cxt->wifi.data.enc_type = int_val;
      changed = true;
    }
#else
    // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_AUTHTYPE, &str_val,
                          &str_len)) {
      wifi_authtype_string_toenum(str_val, &dev_cxt->wifi.data.auth_type);
      changed = true;
    }

    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_ENCTYPE, &str_val,
                          &str_len)) {
      wifi_enctype_string_toenum(str_val, &dev_cxt->wifi.data.enc_type);
      changed = true;
    }
#endif  // OC_SPEC_VER_OIC
  }

  // Invoke callback for user defined attributes
  memcpy(&wifi_cb_data, &dev_cxt->wifi.data, sizeof(oc_wes_wifi_data));
  wifi_cb_data.userdata = NULL;
  if (dev_cxt->read_cb) {
    dev_cxt->read_cb(request->request_payload, OC_RSRVD_WES_RES_TYPE_WIFICONF,
                        &wifi_cb_data.userdata);
  }
  
  if (changed) {
    if (dev_cxt->wifi.prov_cb) {
      dev_cxt->wifi.prov_cb(&wifi_cb_data);
    }

    // Notify observers about data change
    oc_notify_observers(dev_cxt->wifi.handle);
  }

  if (dev_cxt->free_cb) {
    dev_cxt->free_cb(wifi_cb_data.userdata, OC_RSRVD_WES_RES_TYPE_WIFICONF);
  }
}

static void
wificonf_post_handler(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_wifi_conf_resource(request);
  construct_response_of_wificonf(request);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
construct_response_of_devconf(oc_request_t *request)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

  oc_rep_start_root_object();
  oc_process_baseline_interface(dev_cxt->device.handle);
  es_rep_set_text_string(root, dn, oc_string(dev_cxt->device.data.dev_name));

  // Invoke callback for user defined attributes
  if (dev_cxt->write_cb) {
    dev_cxt->write_cb(NULL, OC_RSRVD_WES_RES_TYPE_DEVCONF);
  }
  oc_rep_end_root_object();
}

static void
devconf_get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  construct_response_of_devconf(request);
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_devconf_resource(oc_request_t *request)
{
  oc_wes_device_data dev_cb_data;
  dev_cb_data.userdata = NULL;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

   // Invoke callback for user defined attributes
  if (dev_cxt->read_cb) {
    dev_cxt->read_cb(request->request_payload, OC_RSRVD_WES_RES_TYPE_DEVCONF,
                        &dev_cb_data.userdata);
  }
  
  if (dev_cb_data.userdata && dev_cxt->device.prov_cb) {
    dev_cxt->device.prov_cb(&dev_cb_data);
  }
  // Notify observers about data change
  oc_notify_observers(dev_cxt->device.handle);
  
   // Invoke callback for user defined attributes
  if (dev_cxt->free_cb) {
    dev_cxt->free_cb(dev_cb_data.userdata, OC_RSRVD_WES_RES_TYPE_DEVCONF);
  }
}

static void
devconf_post_handler(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_devconf_resource(request);
  construct_response_of_devconf(request);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
wes_get_handler(oc_request_t *request, oc_interface_mask_t interface,
              void *user_data)
{
  (void)request;
  (void)interface;
  (void)user_data;
  OC_DBG("GET request received");

  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

  oc_rep_start_root_object();
  es_rep_set_int(root, ps, dev_cxt->wes.data.state);
  es_rep_set_int(root, lec, dev_cxt->wes.data.last_err_code);
  oc_rep_end_root_object();
}

static void
update_wes_resource(oc_request_t *request)
{
  int64_t *connect_req;
  size_t connect_req_size;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

  if (oc_rep_get_int_array(request->request_payload, OC_RSRVD_WES_CONNECT,
                           &connect_req, &connect_req_size)) {
    memset(dev_cxt->wes.data.connect_request, 0,
           sizeof(dev_cxt->wes.data.connect_request));
    dev_cxt->wes.data.num_request = 0;
    size_t i;
    for (i = 0; i < NUM_CONNECT_TYPE && i < connect_req_size; ++i) {
      if (connect_req[i] == ES_CONNECT_WIFI ||
          connect_req[i] == ES_CONNECT_COAPCLOUD) {
        dev_cxt->wes.data.connect_request[dev_cxt->wes.data.num_request++] =
          connect_req[i];
      }
    }

    if (dev_cxt->wes.data.connect_request[0] != ES_CONNECT_NONE &&
        dev_cxt->wes.prov_cb) {
      oc_wes_data conn_req;
      memcpy(&conn_req, &dev_cxt->wes.data, sizeof(oc_wes_data));
      dev_cxt->wes.prov_cb(&conn_req);
    }
  }
}

static void
wes_post_handler(oc_request_t *request, oc_interface_mask_t interface,
               void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_B && interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_wes_resource(request);
  oc_send_response(request, OC_STATUS_CHANGED);
}

void
oc_create_wifi_easysetup_resource(size_t device)
{
  OC_DBG("oc_create_wifi_easysetup_resource: Initializing WiFi Easysetup Collection");

#ifdef OC_DYNAMIC_ALLOCATION
	assert(device <=  OC_MAX_NUM_DEVICES);
#endif

  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->wes.data.state = OC_ES_STATE_INIT;
  dev_cxt->wes.data.last_err_code = OC_WES_ERRCODE_NO_ERROR;

  for (int i = 0; i < NUM_CONNECT_TYPE; ++i) {
    dev_cxt->wes.data.connect_request[i] = ES_CONNECT_NONE;
  }
  dev_cxt->wes.data.num_request = 0;

  //Easy Setup Resource
  oc_core_populate_resource(
    OCF_ES,
    device,
    OC_RSRVD_WES_URI_EASYSETUP,
    OC_IF_BASELINE | OC_IF_LL | OC_IF_B,
    OC_IF_LL,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
    wes_get_handler,
    0,
    wes_post_handler,
    0,
    2,
    OC_RSRVD_WES_RES_TYPE_EASYSETUP);

  dev_cxt->wes.handle = oc_core_get_resource_by_index(OCF_ES, device);

  dev_cxt->wifi.data.supported_freq = WIFI_BOTH;
  dev_cxt->wifi.data.supported_mode[0] = WIFI_11A;
  dev_cxt->wifi.data.supported_mode[1] = WIFI_11B;
  dev_cxt->wifi.data.supported_mode[2] = WIFI_11G;
  dev_cxt->wifi.data.supported_mode[3] = WIFI_11N;
  dev_cxt->wifi.data.num_mode = 4;
  dev_cxt->wifi.data.auth_type = NONE_AUTH;
  dev_cxt->wifi.data.enc_type = NONE_ENC;

#ifndef OC_SPEC_VER_OIC  // Spec Version is OCF 1.3 or more.
  dev_cxt->wifi.data.num_supported_authtype = NUM_WIFIAUTHTYPE;
  dev_cxt->wifi.data.supported_authtype[0] = NONE_AUTH;
  dev_cxt->wifi.data.supported_authtype[1] = WEP;
  dev_cxt->wifi.data.supported_authtype[2] = WPA_PSK;
  dev_cxt->wifi.data.supported_authtype[3] = WPA2_PSK;

  dev_cxt->wifi.data.num_supported_enctype = NUM_WIFIENCTYPE;
  dev_cxt->wifi.data.supported_enctype[0] = NONE_ENC;
  dev_cxt->wifi.data.supported_enctype[1] = WEP_64;
  dev_cxt->wifi.data.supported_enctype[2] = WEP_128;
  dev_cxt->wifi.data.supported_enctype[3] = TKIP;
  dev_cxt->wifi.data.supported_enctype[4] = AES;
  dev_cxt->wifi.data.supported_enctype[5] = TKIP_AES;
#endif  // OC_SPEC_VER_OIC

  //Wifi Conf Recource
  oc_core_populate_resource(
    OCF_ES_WIFI, 
    device, 
    OC_RSRVD_WES_URI_WIFICONF,
    OC_IF_RW | OC_IF_BASELINE, 
    OC_IF_RW,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE, 
    wificonf_get_handler, 
    0, 
    wificonf_post_handler, 
    0, 
    1,
    OC_RSRVD_WES_RES_TYPE_WIFICONF);

  dev_cxt->wifi.handle  = oc_core_get_resource_by_index(OCF_ES_WIFI, device);

  // Device Conf Resource
    oc_core_populate_resource(
    OCF_ES_DEVICE,
    device,
    OC_RSRVD_WES_URI_DEVCONF,
    OC_IF_RW | OC_IF_BASELINE,
    OC_IF_RW,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
    devconf_get_handler,
    0,
    devconf_post_handler,
    0,
    1,
    OC_RSRVD_WES_RES_TYPE_DEVCONF);

  dev_cxt->device.handle  = oc_core_get_resource_by_index(OCF_ES_DEVICE, device);

  dev_cxt->wifi_link = oc_new_link(dev_cxt->wifi.handle);
  oc_collection_add_link(dev_cxt->wes.handle, dev_cxt->wifi_link);

  dev_cxt->device_link = oc_new_link(dev_cxt->device.handle);
  oc_collection_add_link(dev_cxt->wes.handle, dev_cxt->device_link);
  OC_DBG("oc_create_wifi_easysetup_resource: Done");
}

void
oc_delete_wifi_easysetup_resource(size_t device)
{
  OC_DBG("oc_delete_wifi_easysetup_resource");

  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->wifi.prov_cb = NULL;
  if (dev_cxt->wifi.handle) {
    oc_delete_resource(dev_cxt->wifi.handle);
    dev_cxt->wifi.handle = NULL;
  }
  es_free_string(dev_cxt->wifi.data.ssid);
  es_free_string(dev_cxt->wifi.data.cred);

  dev_cxt->device.prov_cb = NULL; 
  if (dev_cxt->device.handle) {
    oc_delete_resource(dev_cxt->device.handle);
    dev_cxt->device.handle = NULL;
  }
  es_free_string(dev_cxt->device.data.dev_name);

  dev_cxt->wes.prov_cb = NULL;
  if (dev_cxt->wes.handle) {
    oc_delete_resource(dev_cxt->wes.handle);
    dev_cxt->wes.handle = NULL;
  }
}

#endif //OC_WIFI_EASYSETUP

#ifdef OC_ESIM_EASYSETUP

typedef struct
{
  oc_resource_t *handle;
  // This structure is synced with oc_es_connect_request
  struct
  {
    oc_es_connect_type_t connect_request[NUM_CONNECT_TYPE];
    int num_request;
    oc_es_enrollee_state state;
    oc_ees_error_code last_err_code;
  } data;
  oc_ees_prov_cb prov_cb;
} oc_esim_es_resource_t;

#define esim_es_res_cast(p) (oc_esim_es_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
  struct
  {
    oc_string_t activation_code;
  } data;
  oc_ees_rsp_prov_cb prov_cb;
} oc_es_rsp_conf_resource_t;

#define rsp_res_cast(p) (oc_es_rsp_conf_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
  struct
  {
    oc_string_t euicc_info;
    oc_string_t device_info;  
  } data;
  oc_ees_rspcap_prov_cb prov_cb;
} oc_es_rspcap_conf_resource_t;

#define rspcap_res_cast(p) (oc_es_rspcap_conf_resource_t *)(p)

typedef struct
{
  oc_esim_es_resource_t ees;
  oc_es_rsp_conf_resource_t rsp;
  oc_es_rspcap_conf_resource_t rsp_cap;
  oc_link_t *rsp_link;
  oc_link_t *rspcap_link;
  oc_es_read_userdata_cb_t read_cb;
  oc_es_write_userdata_cb_t write_cb;
  oc_es_free_userdata_t free_cb;  
} oc_esim_enrollee_t;

// Global eSIM Enrolee Instance
oc_esim_enrollee_t g_esim_enrollee[OC_MAX_NUM_DEVICES];

oc_esim_enrollee_t *get_esim_device_context(size_t device)
{
  return &g_esim_enrollee[device];
}
	
oc_es_result_t
oc_ees_set_device_info(size_t device, oc_ees_device_info *device_info)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  es_new_string(&(dev_cxt->rsp_cap.data.euicc_info),
                oc_string((device_info->LPA).euicc_info));
  es_new_string(&(dev_cxt->rsp_cap.data.device_info),
                oc_string((device_info->LPA).device_info));

  // Nofity euicc, device details to Mediator. Upon receving these details, Mediator will initiate profile download.
  oc_notify_observers(dev_cxt->rsp_cap.handle);

  return OC_ES_OK;
}

oc_es_result_t
oc_ees_set_error_code(size_t device, oc_ees_error_code err_code)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  if (err_code < OC_EES_ERRCODE_NO_ERROR || err_code > OC_EES_ERRCODE_UNKNOWN) {
    OC_ERR("Invalid lec to set: %d", err_code);
    return OC_ES_ERROR;
  }
  dev_cxt->ees.data.last_err_code = err_code;
  oc_notify_observers(dev_cxt->ees.handle);
  return OC_ES_OK;
}

/* 
    Easy setup states can be reused for WES and EES.
    In case of EES, Operator server plays enroller role 
*/
oc_es_result_t
oc_ees_set_state(size_t device, oc_es_enrollee_state es_state)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  if (es_state < OC_ES_STATE_INIT || es_state >= OC_ES_STATE_EOF) {
    OC_ERR("Invalid oc_es_set_state to set: %d", es_state);
    return OC_ES_ERROR;
  }
  dev_cxt->ees.data.state = es_state;
  
  oc_notify_observers(dev_cxt->ees.handle);
  return OC_ES_OK;
}

oc_es_enrollee_state
oc_ees_get_state(size_t device)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);
  return dev_cxt->ees.data.state;
}

oc_es_result_t oc_ees_set_resource_callbacks(size_t device, oc_ees_prov_cb ees_prov_cb,
	oc_ees_rsp_prov_cb rsp_prov_cb, oc_ees_rspcap_prov_cb rspcap_prov_cb)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  dev_cxt->ees.prov_cb = ees_prov_cb;
  dev_cxt->rsp.prov_cb = rsp_prov_cb;
  dev_cxt->rsp_cap.prov_cb = rspcap_prov_cb;
  
  return OC_ES_OK;
}

oc_es_result_t oc_ees_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
	oc_es_write_userdata_cb_t writecb, oc_es_free_userdata_t freecb)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  dev_cxt->read_cb = readcb;
  dev_cxt->write_cb = writecb;
  dev_cxt->free_cb = freecb;
  return OC_ES_OK;
}

static void
ees_get_handler(oc_request_t *request, oc_interface_mask_t interface,
              void *user_data)
{
  (void)request;
  (void)interface;
  (void)user_data;
  OC_DBG("GET request received");

  oc_rep_start_root_object();
  // TODO based on Sepc update
  //es_rep_set_int(root, ps, g_esim_enrollee.ees.data.state);
  //es_rep_set_int(root, lec, g_esim_enrollee.ees.data.last_err_code);
  oc_rep_end_root_object();
}

static void
update_ees_resource(oc_request_t *request)
{
  int64_t *connect_req;
  size_t connect_req_size;
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  if (oc_rep_get_int_array(request->request_payload, OC_RSRVD_EES_CONNECT,
                           &connect_req, &connect_req_size)) {
    memset(dev_cxt->ees.data.connect_request, 0,
           sizeof(dev_cxt->ees.data.connect_request));
    dev_cxt->ees.data.num_request = 0;
    size_t i;
    for (i = 0; i < NUM_CONNECT_TYPE && i < connect_req_size; ++i) {
      if (connect_req[i] == ES_CONNECT_WIFI ||
          connect_req[i] == ES_CONNECT_COAPCLOUD) {
        dev_cxt->ees.data.connect_request[dev_cxt->ees.data.num_request++] =
          connect_req[i];
      }
    }

    if (dev_cxt->ees.data.connect_request[0] != ES_CONNECT_NONE &&
        dev_cxt->ees.prov_cb) {
      oc_ees_data conn_req;
      memcpy(&conn_req, &dev_cxt->ees.data, sizeof(oc_wes_data));
      dev_cxt->ees.prov_cb(&conn_req);
    }
  }
}

static void
ees_post_handler(oc_request_t *request, oc_interface_mask_t interface,
               void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_B && interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_ees_resource(request);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
construct_response_of_rspconf(oc_request_t *request)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  oc_rep_start_root_object();
  oc_process_baseline_interface(dev_cxt->rsp.handle);
  es_rep_set_text_string(root, ac, oc_string(dev_cxt->rsp.data.activation_code));

  // Invoke callback for user defined attributes
  if (dev_cxt->write_cb) {
    dev_cxt->write_cb(NULL, OC_RSRVD_EES_RES_TYPE_RSPCONF);
  }
  oc_rep_end_root_object();
}

static void
rspconf_get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  construct_response_of_rspconf(request);
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_rspconf_resource(oc_request_t *request)
{
  char *str_val = NULL;
  size_t str_len = 0;
  oc_ees_rsp_data rsp_cb_data;
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_EES_ACTIVATIONCODE, &str_val,
                        &str_len)) {
    es_new_string(&(dev_cxt->rsp.data.activation_code), str_val);
  }

  // Invoke callback for user defined attributes
  memcpy(&rsp_cb_data, &dev_cxt->rsp.data, sizeof(oc_ees_rsp_data));
  rsp_cb_data.userdata = NULL; 
  
  if (dev_cxt->read_cb) {
    dev_cxt->read_cb(request->request_payload, OC_RSRVD_EES_RES_TYPE_RSPCONF,
                        &rsp_cb_data.userdata);
  }

  if (rsp_cb_data.userdata && dev_cxt->rsp.prov_cb) {
    dev_cxt->rsp.prov_cb(&rsp_cb_data);
  }

  // Notify observers about data change
  oc_notify_observers(dev_cxt->rsp.handle);

  if (dev_cxt->free_cb) {
    dev_cxt->free_cb(rsp_cb_data.userdata, OC_RSRVD_EES_RES_TYPE_RSPCONF);
  }  
}

static void
rspconf_post_handler(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_rspconf_resource(request);
  construct_response_of_rspconf(request);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
construct_response_of_rspcapconf(oc_request_t *request)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  oc_rep_start_root_object();
  oc_process_baseline_interface(dev_cxt->rsp.handle);
  es_rep_set_text_string(root, euiccinfo, oc_string(dev_cxt->rsp_cap.data.euicc_info));
  es_rep_set_text_string(root, deviceinfo, oc_string(dev_cxt->rsp_cap.data.device_info));

  // Invoke callback for user defined attributes
  if (dev_cxt->write_cb) {
    dev_cxt->write_cb(NULL, OC_RSRVD_EES_RES_TYPE_RSPCAPCONF);
  }
  oc_rep_end_root_object();
}

static void
rspcapconf_get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  construct_response_of_rspcapconf(request);
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_rspcapconf_resource(oc_request_t *request)
{
  oc_ees_rspcap_data rspcap_cb_data;
  rspcap_cb_data.userdata = NULL;
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  // Invoke callback for user defined attributes
  if (dev_cxt->read_cb) {
    dev_cxt->read_cb(request->request_payload, OC_RSRVD_EES_RES_TYPE_RSPCAPCONF,
                        &rspcap_cb_data.userdata);
  }

  if (rspcap_cb_data.userdata && dev_cxt->rsp_cap.prov_cb) {
    dev_cxt->rsp_cap.prov_cb(&rspcap_cb_data);
  }

  // Notify observers about data change
  oc_notify_observers(dev_cxt->rsp_cap.handle);

  if (dev_cxt->free_cb) {
    dev_cxt->free_cb(rspcap_cb_data.userdata, OC_RSRVD_EES_RES_TYPE_RSPCAPCONF);
  }
}

static void
rspcapconf_post_handler(oc_request_t *request, oc_interface_mask_t interface,
	void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_rspcapconf_resource(request);
  construct_response_of_rspcapconf(request);
  oc_send_response(request, OC_STATUS_CHANGED);
}

void
oc_create_esim_easysetup_resource(size_t device)
{
  OC_DBG("oc_create_esim_easysetup_resource: Device index %d", device);

#ifdef OC_DYNAMIC_ALLOCATION
	assert(device <=  OC_MAX_NUM_DEVICES);
#endif

  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);
  
  dev_cxt->ees.data.state = OC_ES_STATE_INIT;
  dev_cxt->ees.data.last_err_code = OC_EES_ERRCODE_NO_ERROR;

  for (int i = 0; i < NUM_CONNECT_TYPE; ++i) {
    dev_cxt->ees.data.connect_request[i] = ES_CONNECT_NONE;
  }
  dev_cxt->ees.data.num_request = 0;

  OC_DBG("populate OCF_EES resource ");
  //Esim Easy Setup Resource
  oc_core_populate_resource(
    OCF_EES, 
    device, 
    OC_RSRVD_EES_URI_ESIMEASYSETUP,
    OC_IF_BASELINE | OC_IF_LL | OC_IF_B, 
    OC_IF_LL,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE, 
    ees_get_handler, 
    0, 
    ees_post_handler, 
    0, 
    2,
    OC_RSRVD_EES_RES_TYPE_ESIMEASYSETUP);

  dev_cxt->ees.handle = oc_core_get_resource_by_index(OCF_EES, device);

  OC_DBG("populate OCF_EES_RSP resource ");
  //RSP Conf Recource
  oc_core_populate_resource(
    OCF_EES_RSP, 
    device, 
    OC_RSRVD_EES_URI_RSPCONF,
    OC_IF_RW | OC_IF_BASELINE, 
    OC_IF_RW,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE, 
    rspconf_get_handler, 
    0, 
    rspconf_post_handler, 
    0, 
    1,
    OC_RSRVD_EES_RES_TYPE_RSPCONF);
  
  dev_cxt->rsp.handle = oc_core_get_resource_by_index(OCF_EES_RSP, device);

  OC_DBG("populate OCF_EES_RSP_CAP resource ");

  // RSP Capability Conf Resource
    oc_core_populate_resource(
    OCF_EES_RSP_CAP, 
    device, 
    OC_RSRVD_EES_URI_RSPCAPCONF,
    OC_IF_RW | OC_IF_BASELINE, 
    OC_IF_RW,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE, 
    rspcapconf_get_handler, 
    0, 
    rspcapconf_post_handler, 
    0, 
    1,
    OC_RSRVD_EES_RES_TYPE_RSPCAPCONF);

  dev_cxt->rsp_cap.handle = oc_core_get_resource_by_index(OCF_EES_RSP_CAP, device);
  
  dev_cxt->rsp_link = oc_new_link(dev_cxt->rsp.handle);
  oc_collection_add_link(dev_cxt->ees.handle, dev_cxt->rsp_link);

  dev_cxt->rspcap_link = oc_new_link(dev_cxt->rsp_cap.handle);
  oc_collection_add_link(dev_cxt->ees.handle, dev_cxt->rspcap_link);

  OC_DBG("oc_create_esim_easysetup_resource: Done");
}

void
oc_delete_esim_easysetup_resource(size_t device)
{
  OC_DBG("oc_delete_esim_easysetup_resource");
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  dev_cxt->rsp.prov_cb = NULL;
  if (dev_cxt->rsp.handle) {
    oc_delete_resource(dev_cxt->rsp.handle);
    dev_cxt->rsp.handle = NULL;
  }
  es_free_string(dev_cxt->rsp.data.activation_code);
  
  dev_cxt->rsp_cap.prov_cb = NULL;
  if (dev_cxt->rsp_cap.handle) {
    oc_delete_resource(dev_cxt->rsp_cap.handle);
    dev_cxt->rsp_cap.handle = NULL;
  }
  es_free_string(dev_cxt->rsp_cap.data.euicc_info);
  es_free_string(dev_cxt->rsp_cap.data.device_info);
}

#endif // OC_ESIM_EASYSETUP
