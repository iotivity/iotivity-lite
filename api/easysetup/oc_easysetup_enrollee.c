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
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_config.h"
#include "oc_easysetup_enrollee.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_log.h"
#include "es_utils.h"

#define OC_MAX_NUM_DEVICES	10

#ifdef OC_WIFI_EASYSETUP

typedef struct
{
  oc_collection_t *handle;
  struct
  {
    oc_es_connect_type_t connect_request[NUM_CONNECT_TYPE];
    int num_request;
    oc_wes_enrollee_state_t state;
    oc_wes_error_code_t last_err_code;
  } data;
  oc_wes_prov_cb_t prov_cb;
} oc_wes_resource_t;

#define es_res_cast(p) (oc_wes_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
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
  oc_wes_wifi_prov_cb_t prov_cb;
} oc_wes_wifi_conf_resource_t;

#define wifi_res_cast(p) (oc_wes_wifi_conf_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
  struct
  {
    oc_string_t dev_name;
  } data;
  oc_wes_dev_prov_cb_t prov_cb;
} oc_wes_dev_conf_resource_t;

#define dev_res_cast(p) (oc_wes_dev_conf_resource_t *)(p)

typedef struct
{
  oc_wes_resource_t wes;
  oc_wes_wifi_conf_resource_t wifi;
  oc_wes_dev_conf_resource_t device;
  oc_es_read_userdata_cb_t read_cb;
  oc_es_write_userdata_cb_t write_cb;
  oc_es_free_userdata_cb_t free_cb;
} oc_wifi_enrollee_t;

// Global WiFi Enrolee Instance
oc_wifi_enrollee_t g_wifi_enrollee[OC_MAX_NUM_DEVICES];

oc_wifi_enrollee_t *get_wifi_device_context(size_t device)
{
  return &g_wifi_enrollee[device];
}

oc_es_result_t
oc_wes_set_device_info(size_t device, oc_wes_device_info_t *device_info)
{
  int modeIdx = 0;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->wifi.data.supported_freq = (device_info->WiFi).supported_freq;

  while ((device_info->WiFi).supported_mode[modeIdx] != WIFI_EOF) {
    dev_cxt->wifi.data.supported_mode[modeIdx] =
      (device_info->WiFi).supported_mode[modeIdx];
    modeIdx++;
  }

  dev_cxt->wifi.data.num_mode = modeIdx;
  oc_notify_observers(dev_cxt->wifi.handle);

  es_new_string(&(dev_cxt->device.data.dev_name),
               oc_string((device_info->Device).device_name));
  oc_notify_observers(dev_cxt->device.handle);
  return OC_ES_OK;
}

oc_es_result_t
oc_wes_set_error_code(size_t device, oc_wes_error_code_t err_code)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  if (err_code < OC_WES_NO_ERROR || err_code > OC_WES_UNKNOWN_ERROR) {
    OC_ERR("Invalid lec to set: %d", err_code);
    return OC_ES_ERROR;
  }

  dev_cxt->wes.data.last_err_code = err_code;
  oc_notify_observers((oc_resource_t *)dev_cxt->wes.handle);
  return OC_ES_OK;
}

oc_es_result_t
oc_wes_set_state(size_t device, oc_wes_enrollee_state_t es_state)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  if (es_state < OC_WES_INIT || es_state >= OC_WES_EOF) {
    OC_ERR("Invalid oc_es_set_state to set: %d", es_state);
    return OC_ES_ERROR;
  }

  dev_cxt->wes.data.state = es_state;
  oc_notify_observers((oc_resource_t *)dev_cxt->wes.handle);
  return OC_ES_OK;
}

oc_wes_enrollee_state_t
oc_wes_get_state(size_t device)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);
  return dev_cxt->wes.data.state;
}

oc_es_result_t oc_wes_set_resource_callbacks(size_t device, oc_wes_prov_cb_t wes_prov_cb,
	oc_wes_wifi_prov_cb_t wifi_prov_cb, oc_wes_dev_prov_cb_t dev_prov_cb)
{
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->wes.prov_cb = wes_prov_cb;
  dev_cxt->wifi.prov_cb = wifi_prov_cb;
  dev_cxt->device.prov_cb = dev_prov_cb;

  return OC_ES_OK;
}

oc_es_result_t oc_wes_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
	oc_es_write_userdata_cb_t writecb, oc_es_free_userdata_cb_t freecb)
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
  oc_rep_add_text_string(swmt, wifi_mode_enum_tostring(dev_cxt->wifi.data.supported_mode[i]));
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
       oc_rep_add_text_string(swf, wifi_freq_enum_tostring(dev_cxt->wifi.data.supported_freq));
       break;
     case WIFI_BOTH:
       oc_rep_add_text_string(swf, wifi_freq_enum_tostring(WIFI_24G));
       oc_rep_add_text_string(swf, wifi_freq_enum_tostring(WIFI_5G));
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
  es_rep_set_text_string(root, wat, wifi_authtype_enum_tostring(dev_cxt->wifi.data.auth_type));
  es_rep_set_text_string(root, wet, wifi_enctype_enum_tostring(dev_cxt->wifi.data.enc_type));

  // new properties in OCF 1.3 - swat and swet.
  oc_rep_set_array(root, swat);
  for (int i = 0; i < dev_cxt->wifi.data.num_supported_authtype; i++) {
    oc_rep_add_text_string(swat, wifi_mode_enum_tostring(dev_cxt->wifi.data.supported_authtype[i]));
  }
  oc_rep_close_array(root, swat);

  oc_rep_set_array(root, swet);
  for (int i = 0; i < dev_cxt->wifi.data.num_supported_enctype; i++) {
    oc_rep_add_text_string(swet, wifi_mode_enum_tostring(dev_cxt->wifi.data.supported_enctype[i]));
  }
  oc_rep_close_array(root, swet);
#endif  // OC_SPEC_VER_OIC
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
  bool res_changed = false;
  oc_wes_wifi_data_t wifi_cb_data;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

  {
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_SSID, &str_val,
                          &str_len)) {
      es_new_string(&(dev_cxt->wifi.data.ssid), str_val);
      res_changed = true;
    }

    str_val = NULL;
    str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_CRED, &str_val,
                          &str_len)) {
      es_new_string(&(dev_cxt->wifi.data.cred), str_val);
      res_changed = true;
    }
  }

  {
#ifdef OC_SPEC_VER_OIC
    // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
    int64_t int_val = 0;
    if (oc_rep_get_int(request->request_payload, OC_RSRVD_WES_AUTHTYPE,
                       &int_val)) {
      dev_cxt->wifi.data.auth_type = int_val;
      res_changed = true;
    }

    if (oc_rep_get_int(request->request_payload, OC_RSRVD_WES_ENCTYPE,
                       &int_val)) {
      dev_cxt->wifi.data.enc_type = int_val;
      res_changed = true;
    }
#else
    // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_AUTHTYPE, &str_val,
                          &str_len)) {
      wifi_authtype_string_toenum(str_val, &dev_cxt->wifi.data.auth_type);
      res_changed = true;
    }

    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_ENCTYPE, &str_val,
                          &str_len)) {
      wifi_enctype_string_toenum(str_val, &dev_cxt->wifi.data.enc_type);
      res_changed = true;
    }
#endif  // OC_SPEC_VER_OIC
  }

  memcpy(&wifi_cb_data, &dev_cxt->wifi.data, sizeof(oc_wes_wifi_data_t));
  wifi_cb_data.userdata = NULL;

  if (res_changed && dev_cxt->wifi.prov_cb) {
    // Trigger provisioning callback
    dev_cxt->wifi.prov_cb(&wifi_cb_data);
    // Notify observers about data change
    oc_notify_observers(dev_cxt->wifi.handle);
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
  bool res_changed = false;
  char *str_val = NULL;
  size_t str_len = 0;
  oc_wes_device_data_t dev_cb_data;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(request->origin->device);

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_DEVNAME, &str_val,
                        &str_len)) {
    es_new_string(&(dev_cxt->device.data.dev_name), str_val);
    res_changed = true;
  }

  memcpy(&dev_cb_data, &dev_cxt->device.data, sizeof(oc_wes_device_data_t));
  dev_cb_data.userdata = NULL;

  if (res_changed && dev_cxt->device.prov_cb) {
    // Trigger provisioning callback
    dev_cxt->device.prov_cb(&dev_cb_data);
    // Notify observers about data change
    oc_notify_observers(dev_cxt->device.handle);
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

void
get_wes_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                        void *data)
{
  (void)data;
  oc_collection_t *wes = (oc_collection_t *)resource;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(wes->device);

  oc_rep_start_root_object();

  switch (iface_mask) {
  case OC_IF_BASELINE:
    es_rep_set_int(root, ps, dev_cxt->wes.data.state);
    es_rep_set_int(root, lec, dev_cxt->wes.data.last_err_code);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

bool
set_wes_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
  (void)data;
  int64_t int_val = 0;
  int64_t *connect_req;
  size_t connect_req_size;
  oc_wes_data_t cb_data;
  oc_collection_t *wes = (oc_collection_t *)resource;
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(wes->device);

  while (rep != NULL) {
    switch (rep->type) {
      case OC_REP_INT_ARRAY:
        if (oc_rep_get_int_array(rep, OC_RSRVD_WES_CONNECT,
                                 &connect_req, &connect_req_size)) {
          memset(dev_cxt->wes.data.connect_request, 0, sizeof(dev_cxt->wes.data.connect_request));
          dev_cxt->wes.data.num_request = 0;
          size_t i;

          for (i = 0; i < NUM_CONNECT_TYPE && i < connect_req_size; ++i) {
            if (connect_req[i] == OC_ES_CONNECT_WIFI ||
                connect_req[i] == OC_ES_CONNECT_COAPCLOUD) {
              dev_cxt->wes.data.connect_request[dev_cxt->wes.data.num_request++] =
                connect_req[i];
            }
          }
        }
        break;
      case OC_REP_INT:
	  if (oc_rep_get_int(rep, OC_RSRVD_WES_PROVSTATUS, &int_val)) {
	    dev_cxt->wes.data.state = int_val;
	  }
	  if (oc_rep_get_int(rep, OC_RSRVD_WES_LAST_ERRORCODE, &int_val)) {
	    dev_cxt->wes.data.last_err_code = int_val;
	  }
  	  break;
      default:
        break;
    }
    rep = rep->next;
  }

  // Trigger application callback
  if (dev_cxt->wes.prov_cb) {
    memcpy(&cb_data, &dev_cxt->wes.data, sizeof(oc_wes_data_t));
    cb_data.userdata = NULL;
    dev_cxt->wes.prov_cb(&cb_data);
  }
  oc_notify_observers((oc_resource_t *)dev_cxt->wes.handle);
  return true;
}

void
oc_create_wifi_easysetup_resource(size_t device)
{
  OC_DBG("oc_create_wifi_easysetup_resource : %d", device);

#ifdef OC_DYNAMIC_ALLOCATION
  assert(device <  OC_MAX_NUM_DEVICES);
#endif

  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  dev_cxt->wes.data.state = OC_WES_INIT;
  dev_cxt->wes.data.last_err_code = OC_WES_NO_ERROR;

  for (int i = 0; i < NUM_CONNECT_TYPE; ++i) {
    dev_cxt->wes.data.connect_request[i] = OC_ES_CONNECT_NONE;
  }
  dev_cxt->wes.data.num_request = 0;

  //Easy Setup Resource
  oc_core_populate_collection(
    OCF_WES,
    device,
    OC_RSRVD_WES_URI_EASYSETUP,
    OC_DISCOVERABLE | OC_SECURE,
    2,
    OC_RSRVD_WES_RES_TYPE_EASYSETUP,
    "oic.wk.col");

  dev_cxt->wes.handle =
  	 (oc_collection_t *)oc_core_get_resource_by_index(OCF_WES, device);

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

  oc_resource_set_properties_cbs((oc_resource_t *)dev_cxt->wes.handle, get_wes_properties, NULL,
                                 set_wes_properties, NULL);

  //Wifi Conf Recource
  oc_core_populate_resource(
    OCF_WES_WIFI,
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

  dev_cxt->wifi.handle  = oc_core_get_resource_by_index(OCF_WES_WIFI, device);
  oc_link_t *l1 = oc_new_link(dev_cxt->wifi.handle);
  oc_collection_add_link((oc_resource_t *)dev_cxt->wes.handle, l1);

  // Device Conf Resource
  oc_core_populate_resource(
    OCF_WES_DEVICE,
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

  dev_cxt->device.handle  = oc_core_get_resource_by_index(OCF_WES_DEVICE, device);
  oc_link_t *l2 = oc_new_link(dev_cxt->device.handle);
  oc_collection_add_link((oc_resource_t *)dev_cxt->wes.handle, l2);
}

void
oc_delete_wifi_easysetup_resource(size_t device)
{
  OC_DBG("oc_delete_wifi_easysetup_resource : %d", device);
  oc_wifi_enrollee_t *dev_cxt = get_wifi_device_context(device);

  // dev_cxt->wifi.handle freed during core shutdown
  es_free_string(dev_cxt->wifi.data.ssid);
  es_free_string(dev_cxt->wifi.data.cred);
  dev_cxt->wifi.prov_cb = NULL;

  // dev_cxt->device.handle freed during core shutdown
  es_free_string(dev_cxt->device.data.dev_name);
  dev_cxt->device.prov_cb = NULL;

  if (dev_cxt->wes.handle) {
    oc_delete_collection((oc_resource_t *)dev_cxt->wes.handle);
    dev_cxt->wes.handle = NULL;
  }
  dev_cxt->wes.prov_cb = NULL;
}

#endif //OC_WIFI_EASYSETUP

#ifdef OC_ESIM_EASYSETUP

typedef struct
{
  oc_collection_t *handle;
  // This structure is synced with oc_es_connect_request
  struct
  {
    oc_string_t rsp_status;
    oc_string_t last_err_reason;
    oc_string_t last_err_code;
    oc_string_t last_err_desc;
    oc_string_t end_user_conf;
  } data;
  oc_ees_prov_cb_t prov_cb;
} oc_ees_resource_t;

#define ees_res_cast(p) (oc_ees_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
  struct
  {
    oc_string_t activation_code;
    oc_string_t profile_metadata;
    oc_string_t confirm_code;
    bool confirm_code_required;
  } data;
  oc_ees_rsp_prov_cb_t prov_cb;
} oc_ees_rsp_conf_resource_t;

#define rsp_res_cast(p) (oc_ees_rsp_conf_resource_t *)(p)

typedef struct
{
  oc_resource_t *handle;
  struct
  {
    oc_string_t euicc_info;
    oc_string_t device_info;
  } data;
  oc_ees_rspcap_prov_cb_t prov_cb;
} oc_ees_rspcap_conf_resource_t;

#define rspcap_res_cast(p) (oc_ees_rspcap_conf_resource_t *)(p)

typedef struct
{
  oc_ees_resource_t ees;
  oc_ees_rsp_conf_resource_t rsp;
  oc_ees_rspcap_conf_resource_t rsp_cap;
  oc_es_read_userdata_cb_t read_cb;
  oc_es_write_userdata_cb_t write_cb;
  oc_es_free_userdata_cb_t free_cb;
} oc_esim_enrollee_t;

// Global eSIM Enrolee Instance
oc_esim_enrollee_t g_esim_enrollee[OC_MAX_NUM_DEVICES];

oc_esim_enrollee_t *get_esim_device_context(size_t device)
{
  return &g_esim_enrollee[device];
}

oc_es_result_t
oc_ees_set_device_info(size_t device, char *euicc_info, char *device_info)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  es_new_string(&(dev_cxt->rsp_cap.data.euicc_info), euicc_info);
  es_new_string(&(dev_cxt->rsp_cap.data.device_info), device_info);

  // Nofity euicc, device details to Mediator. Upon receving these details, Mediator will read eUICC Info and device info from Enrollee
  oc_notify_observers(dev_cxt->rsp_cap.handle);

  return OC_ES_OK;
}

oc_es_result_t
oc_ees_set_error_code(size_t device, oc_string_t err_code)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  es_new_string(&(dev_cxt->ees.data.last_err_code), oc_string(err_code));
  oc_notify_observers((oc_resource_t *)dev_cxt->ees.handle);

  return OC_ES_OK;
}

/* Easy setup states can be reused for WES and EES.
    In case of EES, Operator server plays enroller role */
oc_es_result_t
oc_ees_set_state(size_t device, oc_string_t es_status)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  es_new_string(&(dev_cxt->ees.data.rsp_status), oc_string(es_status));

  oc_notify_observers((oc_resource_t *)dev_cxt->ees.handle);
  return OC_ES_OK;
}

oc_string_t
oc_ees_get_state(size_t device)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);
  return dev_cxt->ees.data.rsp_status;
}

oc_es_result_t oc_ees_set_resource_callbacks(size_t device, oc_ees_prov_cb_t ees_prov_cb,
	oc_ees_rsp_prov_cb_t rsp_prov_cb, oc_ees_rspcap_prov_cb_t rspcap_prov_cb)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  dev_cxt->ees.prov_cb = ees_prov_cb;
  dev_cxt->rsp.prov_cb = rsp_prov_cb;
  dev_cxt->rsp_cap.prov_cb = rspcap_prov_cb;

  return OC_ES_OK;
}

oc_es_result_t oc_ees_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
	oc_es_write_userdata_cb_t writecb, oc_es_free_userdata_cb_t freecb)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  dev_cxt->read_cb = readcb;
  dev_cxt->write_cb = writecb;
  dev_cxt->free_cb = freecb;

  return OC_ES_OK;
}

static void
construct_response_of_rspconf(oc_request_t *request)
{
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  oc_rep_start_root_object();
  oc_process_baseline_interface(dev_cxt->rsp.handle);
  es_rep_set_text_string(root, ac, oc_string(dev_cxt->rsp.data.activation_code));
  es_rep_set_text_string(root, pm, oc_string(dev_cxt->rsp.data.profile_metadata));
  es_rep_set_text_string(root, cc, oc_string(dev_cxt->rsp.data.confirm_code));
  es_rep_set_boolean(root, ccr, dev_cxt->rsp.data.confirm_code_required);
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
  bool ccr = false;
  bool res_changed = false;
  oc_ees_rsp_data_t rsp_cb_data;
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_EES_ACTIVATIONCODE, &str_val,
                        &str_len)) {
    es_new_string(&(dev_cxt->rsp.data.activation_code), str_val);
    res_changed = true;
  }
  if (oc_rep_get_string(request->request_payload, OC_RSRVD_EES_PROFMETADATA, &str_val,
                        &str_len)) {
    es_new_string(&(dev_cxt->rsp.data.profile_metadata), str_val);
    res_changed = true;
  }
  if (oc_rep_get_string(request->request_payload, OC_RSRVD_EES_CONFIRMATIONCODE, &str_val,
                        &str_len)) {
    es_new_string(&(dev_cxt->rsp.data.confirm_code), str_val);
    res_changed = true;
  }
  if (oc_rep_get_bool(request->request_payload, OC_RSRVD_EES_CONFIRMATIONCODEREQUIRED, &ccr)) {
    dev_cxt->rsp.data.confirm_code_required = ccr;
    res_changed = true;
  }

  memcpy(&rsp_cb_data, &dev_cxt->rsp.data, sizeof(oc_ees_rsp_data_t));
  rsp_cb_data.userdata = NULL;

  if(res_changed && dev_cxt->rsp.prov_cb) {
    // Trigger provisioning callback
    dev_cxt->rsp.prov_cb(&rsp_cb_data);
    //Notify observers about data change
    oc_notify_observers(dev_cxt->rsp.handle);
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
  bool res_changed = false;
  char *str_val = NULL;
  size_t str_len = 0;
  oc_ees_rspcap_data_t rspcap_cb_data;
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(request->origin->device);

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_EES_EUICCINFO, &str_val,
                        &str_len)) {
    es_new_string(&(dev_cxt->rsp_cap.data.euicc_info), str_val);
    res_changed = true;
  }
  if (oc_rep_get_string(request->request_payload, OC_RSRVD_EES_DEVICEINFO, &str_val,
                        &str_len)) {
    es_new_string(&(dev_cxt->rsp_cap.data.device_info), str_val);
    res_changed = true;
  }

  memcpy(&rspcap_cb_data, &dev_cxt->rsp_cap.data, sizeof(oc_ees_rspcap_data_t));
  rspcap_cb_data.userdata = NULL;

  if(res_changed && dev_cxt->rsp_cap.prov_cb) {
    // Trigger provisioning callback
    dev_cxt->rsp_cap.prov_cb(&rspcap_cb_data);
    // Notify observers about data change
    oc_notify_observers(dev_cxt->rsp_cap.handle);
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
get_ees_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                        void *data)
{
  (void)data;
  oc_collection_t *ees = (oc_collection_t *)resource;
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(ees->device);

  oc_rep_start_root_object();

  switch (iface_mask) {
  case OC_IF_BASELINE:
    es_rep_set_text_string(root, ps, oc_string(dev_cxt->ees.data.rsp_status));
    es_rep_set_text_string(root, ler, oc_string(dev_cxt->ees.data.last_err_reason));
    es_rep_set_text_string(root, lec, oc_string(dev_cxt->ees.data.last_err_code));
    es_rep_set_text_string(root, led, oc_string(dev_cxt->ees.data.last_err_desc));
    es_rep_set_text_string(root, euc, oc_string(dev_cxt->ees.data.end_user_conf));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

bool
set_ees_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
  (void)data;
  char *str_val = NULL;
  size_t str_len = 0;
  oc_ees_data_t cb_data;
  oc_collection_t *ees = (oc_collection_t *)resource;
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(ees->device);

  while (rep != NULL) {
    switch (rep->type) {
      case OC_REP_STRING:
        if (oc_rep_get_string(rep, OC_RSRVD_EES_PROVSTATUS,
  	  	&str_val, &str_len)) {
          es_new_string(&(dev_cxt->ees.data.rsp_status), str_val);
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_LASTERRORREASON,
  	  	&str_val, &str_len)) {
          es_new_string(&(dev_cxt->ees.data.last_err_reason), str_val);
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_LASTERRORCODE,
  	  	&str_val, &str_len)) {
          es_new_string(&(dev_cxt->ees.data.last_err_code), str_val);
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_LASTERRORRDESCRIPTION,
  	  	&str_val, &str_len)) {
          es_new_string(&(dev_cxt->ees.data.last_err_desc), str_val);
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_ENDUSERCONFIRMATION,
  	  	&str_val, &str_len)) {
          es_new_string(&(dev_cxt->ees.data.end_user_conf), str_val);
        }
        break;
      default:
        break;
    }
    rep = rep->next;
  }

  if (dev_cxt->ees.prov_cb) {
    memcpy(&cb_data, &dev_cxt->ees.data, sizeof(oc_ees_data_t));
    cb_data.userdata = NULL;
    dev_cxt->ees.prov_cb(&cb_data);
  }
  oc_notify_observers((oc_resource_t *)dev_cxt->ees.handle);
  return true;
}

void
oc_create_esim_easysetup_resource(size_t device)
{
  OC_DBG("oc_create_esim_easysetup_resource : %d", device);

#ifdef OC_DYNAMIC_ALLOCATION
  assert(device <  OC_MAX_NUM_DEVICES);
#endif

  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);
  es_new_string(&(dev_cxt->ees.data.rsp_status), EES_PS_NONE);

  // Esim Easy Setup Resource
  oc_core_populate_collection(
    OCF_EES,
    device,
    OC_RSRVD_EES_URI_ESIMEASYSETUP,
    OC_DISCOVERABLE | OC_SECURE,
    2,
    OC_RSRVD_EES_RES_TYPE_ESIMEASYSETUP,
    "oic.wk.col");

  dev_cxt->ees.handle =
  	 (oc_collection_t *)oc_core_get_resource_by_index(OCF_EES, device);

  oc_resource_set_properties_cbs((oc_resource_t *)dev_cxt->ees.handle, get_ees_properties, NULL,
                                 set_ees_properties, NULL);

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
  oc_link_t *l1 = oc_new_link(dev_cxt->rsp.handle);
  oc_collection_add_link((oc_resource_t *)dev_cxt->ees.handle, l1);

  // RSP Capability Conf Resource
  oc_core_populate_resource(
    OCF_EES_RSPCAP,
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

  dev_cxt->rsp_cap.handle = oc_core_get_resource_by_index(OCF_EES_RSPCAP, device);
  oc_link_t *l2 = oc_new_link(dev_cxt->rsp_cap.handle);
  oc_collection_add_link((oc_resource_t *)dev_cxt->ees.handle, l2);
}

void
oc_delete_esim_easysetup_resource(size_t device)
{
  OC_DBG("oc_delete_esim_easysetup_resource : %d", device);
  oc_esim_enrollee_t *dev_cxt = get_esim_device_context(device);

  // dev_cxt->rsp.handle is freed during core shwtdown
  es_free_string(dev_cxt->rsp.data.activation_code);
  es_free_string(dev_cxt->rsp.data.profile_metadata);
  es_free_string(dev_cxt->rsp.data.confirm_code);
  dev_cxt->rsp.prov_cb = NULL;

  // dev_cxt->rsp_cap.handle is freed during core shwtdown
  es_free_string(dev_cxt->rsp_cap.data.euicc_info);
  es_free_string(dev_cxt->rsp_cap.data.device_info);
  dev_cxt->rsp_cap.prov_cb = NULL;

  // Collection is not freed by default. Free collection here.
  if (dev_cxt->ees.handle) {
    oc_delete_collection((oc_resource_t *)dev_cxt->ees.handle);
    dev_cxt->ees.handle = NULL;
  }
  es_free_string(dev_cxt->ees.data.rsp_status);
  es_free_string(dev_cxt->ees.data.last_err_reason);
  es_free_string(dev_cxt->ees.data.last_err_code);
  es_free_string(dev_cxt->ees.data.last_err_desc);
  es_free_string(dev_cxt->ees.data.end_user_conf);
  dev_cxt->ees.prov_cb = NULL;
}

#endif // OC_ESIM_EASYSETUP
