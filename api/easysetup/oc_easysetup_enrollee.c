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
  oc_wes_data_t data;
  oc_wes_prov_cb_t prov_cb;
} oc_wes_resource_t;

typedef struct
{
  oc_resource_t *handle;
  oc_wes_wifi_data_t data;
  oc_wes_wifi_prov_cb_t prov_cb;
} oc_wes_wifi_conf_resource_t;

typedef struct
{
  oc_resource_t *handle;
  oc_wes_device_data_t data;
  oc_wes_dev_prov_cb_t prov_cb;
} oc_wes_dev_conf_resource_t;

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

oc_wifi_enrollee_t *get_device_wifi_enrollee(size_t device)
{
  return &g_wifi_enrollee[device];
}

oc_es_result_t
oc_wes_set_device_info(size_t device, wifi_mode supported_mode[],
	wifi_freq supported_freq, char *device_name)
{
  int modeIdx = 0;
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);
  OC_DBG("oc_wes_set_device_info\n");

  dev_cxt->wifi.data.supported_freq = supported_freq;

  while (supported_mode[modeIdx] != WIFI_EOF) {
    dev_cxt->wifi.data.supported_mode[modeIdx] = supported_mode[modeIdx];
    modeIdx++;
  }
  dev_cxt->wifi.data.num_mode = modeIdx;
  oc_new_string(&(dev_cxt->device.data.dev_name), device_name, strlen(device_name));

  return OC_ES_OK;
}

oc_es_result_t
oc_wes_set_error_code(size_t device, oc_wes_error_code_t err_code)
{
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);
  OC_DBG("oc_wes_set_error_code %d\n", err_code);

  if (err_code < OC_WES_NO_ERROR || err_code > OC_WES_UNKNOWN_ERROR) {
    OC_ERR("Invalid lec to set: %d", err_code);
    return OC_ES_ERROR;
  }

  dev_cxt->wes.data.last_err_code = err_code;
  return OC_ES_OK;
}

oc_es_result_t
oc_wes_set_state(size_t device, oc_wes_enrollee_state_t es_state)
{
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);
  OC_DBG("oc_wes_set_state %d\n", es_state);

  if (es_state < OC_WES_INIT || es_state >= OC_WES_EOF) {
    OC_ERR("Invalid oc_es_set_state to set: %d", es_state);
    return OC_ES_ERROR;
  }

  dev_cxt->wes.data.state = es_state;
  return OC_ES_OK;
}

oc_wes_enrollee_state_t
oc_wes_get_state(size_t device)
{
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);
  return dev_cxt->wes.data.state;
}

oc_es_result_t oc_wes_set_resource_callbacks(size_t device, oc_wes_prov_cb_t wes_prov_cb,
	oc_wes_wifi_prov_cb_t wifi_prov_cb, oc_wes_dev_prov_cb_t dev_prov_cb)
{
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);
  OC_DBG("oc_wes_set_resource_callbacks\n");

  dev_cxt->wes.prov_cb = wes_prov_cb;
  dev_cxt->wifi.prov_cb = wifi_prov_cb;
  dev_cxt->device.prov_cb = dev_prov_cb;

  return OC_ES_OK;
}

oc_es_result_t oc_wes_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
	oc_es_write_userdata_cb_t writecb, oc_es_free_userdata_cb_t freecb)
{
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);
  OC_DBG("oc_wes_set_userdata_callbacks\n");

  dev_cxt->read_cb = readcb;
  dev_cxt->write_cb = writecb;
  dev_cxt->free_cb = freecb;

  return OC_ES_OK;
}

static void
construct_response_of_wificonf(oc_request_t *request)
{
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(request->origin->device);
  OC_DBG("construct_response_of_wificonf\n");

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
  oc_rep_set_int(root, swf, (int)dev_cxt->wifi.data.supported_freq);
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

  oc_rep_set_text_string(root, tnn, oc_string(dev_cxt->wifi.data.ssid));
  oc_rep_set_text_string(root, cd, oc_string(dev_cxt->wifi.data.cred));

#ifdef OC_SPEC_VER_OIC
  // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
  oc_rep_set_int(root, wat, (int)dev_cxt->wifi.data.auth_type);
  oc_rep_set_int(root, wet, (int)dev_cxt->wifi.data.enc_type);
#else
  // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
  oc_rep_set_text_string(root, wat, wifi_authtype_enum_tostring(dev_cxt->wifi.data.auth_type));
  oc_rep_set_text_string(root, wet, wifi_enctype_enum_tostring(dev_cxt->wifi.data.enc_type));

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
  OC_DBG("wificonf_get_handler %d\n", interface);
  if (interface == OC_IF_BASELINE) {
    construct_response_of_wificonf(request);
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
update_wifi_conf_resource(oc_request_t *request, void *user_data)
{
  bool res_changed = false;
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(request->origin->device);
  OC_DBG("update_wifi_conf_resource\n");

  {
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_SSID, &str_val,
                          &str_len)) {
      oc_new_string(&(dev_cxt->wifi.data.ssid), str_val, str_len);
      res_changed = true;
    }

    str_val = NULL;
    str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_CRED, &str_val,
                          &str_len)) {
      oc_new_string(&(dev_cxt->wifi.data.cred), str_val, str_len);
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

  if (res_changed && dev_cxt->wifi.prov_cb) {
    // Trigger provisioning callback
    dev_cxt->wifi.prov_cb((oc_wes_wifi_data_t *)&(dev_cxt->wifi.data), user_data);
  }
}

static void
wificonf_post_handler(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  OC_DBG("wificonf_post_handler %d\n", interface);

  if (interface == OC_IF_BASELINE) {
    update_wifi_conf_resource(request, user_data);
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
construct_response_of_devconf(oc_request_t *request)
{
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(request->origin->device);
  OC_DBG("construct_response_of_devconf\n");

  oc_rep_start_root_object();
  oc_process_baseline_interface(dev_cxt->device.handle);
  oc_rep_set_text_string(root, dn, oc_string(dev_cxt->device.data.dev_name));

  oc_rep_end_root_object();
}

static void
devconf_get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;
  OC_DBG("devconf_get_handler %d\n", interface);

  if (interface == OC_IF_BASELINE) {
    construct_response_of_devconf(request);
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
update_devconf_resource(oc_request_t *request, void *user_data)
{
  bool res_changed = false;
  char *str_val = NULL;
  size_t str_len = 0;
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(request->origin->device);
  OC_DBG("update_devconf_resource\n");

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_WES_DEVNAME, &str_val,
                        &str_len)) {
    oc_new_string(&(dev_cxt->device.data.dev_name), str_val, str_len);
    res_changed = true;
  }

  if (res_changed && dev_cxt->device.prov_cb) {
    // Trigger provisioning callback
    dev_cxt->device.prov_cb((oc_wes_device_data_t *) &(dev_cxt->device.data), user_data);
  }
}

static void
devconf_post_handler(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  OC_DBG("devconf_post_handler %d\n", interface);

  if (interface == OC_IF_BASELINE) {
    update_devconf_resource(request, user_data);
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

void
get_wes_properties(oc_resource_t *resource, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)user_data;
  oc_collection_t *wes = (oc_collection_t *)resource;
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(wes->device);
  OC_DBG("get_wes_properties %d\n", interface);

  oc_rep_start_root_object();

  switch (interface) {
  case OC_IF_BASELINE:
  case OC_IF_B:
  case OC_IF_LL:
    oc_rep_set_int(root, ps, dev_cxt->wes.data.state);
    oc_rep_set_int(root, lec, dev_cxt->wes.data.last_err_code);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

bool
set_wes_properties(oc_resource_t *resource, oc_rep_t *rep, void *user_data)
{
  bool res_changed = false;
  int64_t int_val = 0;
  int64_t *connect_req;
  size_t connect_req_size;
  oc_collection_t *wes = (oc_collection_t *)resource;
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(wes->device);
  OC_DBG("set_wes_properties\n");

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
              res_changed = true;
            }
          }
        }
        break;
      case OC_REP_INT:
	  if (oc_rep_get_int(rep, OC_RSRVD_WES_PROVSTATUS, &int_val)) {
	    dev_cxt->wes.data.state = int_val;
          res_changed = true;
	  }
	  if (oc_rep_get_int(rep, OC_RSRVD_WES_LAST_ERRORCODE, &int_val)) {
	    dev_cxt->wes.data.last_err_code = int_val;
          res_changed = true;
	  }
        break;
      default:
        break;
    }
    rep = rep->next;
  }

  // Trigger application callback
  if (res_changed && dev_cxt->wes.prov_cb) {
    dev_cxt->wes.prov_cb((oc_wes_data_t *) &(dev_cxt->wes.data), user_data);
  }
  return true;
}

static void
wes_get_handler(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  (void)user_data;
  OC_DBG("wes_get_handler : %d", interface);
  if ((interface == OC_IF_BASELINE)||(interface == OC_IF_LL) || (interface == OC_IF_B)) {
    oc_handle_collection_request(OC_GET, request, interface, NULL);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
wes_post_handler(oc_request_t *request, oc_interface_mask_t interface,
              void *user_data)
{
  (void)user_data;
  OC_DBG("wes_post_handler : %d", interface);
  if ((interface == OC_IF_BASELINE)||(interface == OC_IF_B)) {
    oc_handle_collection_request(OC_POST, request, interface, NULL);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

void
oc_create_wifi_easysetup_resource(size_t device, void *user_data)
{
  OC_DBG("oc_create_wifi_easysetup_resource : %d", device);

#ifdef OC_DYNAMIC_ALLOCATION
  assert(device <  OC_MAX_NUM_DEVICES);
#endif

  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);

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
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
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

  // Add Self link to WES resource
  oc_link_t *self = oc_new_link((oc_resource_t *)dev_cxt->wes.handle);
  oc_collection_add_link((oc_resource_t *)dev_cxt->wes.handle, self);

  //Enables RETRIEVEs/UPDATEs to Collection properties
  oc_resource_set_request_handler((oc_resource_t *)dev_cxt->wes.handle,
                                OC_GET, wes_get_handler, user_data);
  oc_resource_set_request_handler((oc_resource_t *)dev_cxt->wes.handle,
                                OC_POST, wes_post_handler, user_data);
  oc_resource_set_properties_cbs((oc_resource_t *)dev_cxt->wes.handle, get_wes_properties, user_data,
                                set_wes_properties, user_data);

  //Wifi Conf Recource
  oc_core_populate_resource(
    OCF_WES_WIFI,
    device,
    OC_RSRVD_WES_URI_WIFICONF,
    OC_IF_RW | OC_IF_BASELINE,
    OC_IF_BASELINE,
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
    OC_IF_BASELINE,
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
  oc_wifi_enrollee_t *dev_cxt = get_device_wifi_enrollee(device);

  // dev_cxt->wifi.handle freed during core shutdown
  oc_free_string(&dev_cxt->wifi.data.ssid);
  oc_free_string(&dev_cxt->wifi.data.cred);
  dev_cxt->wifi.prov_cb = NULL;

  // dev_cxt->device.handle freed during core shutdown
  oc_free_string(&dev_cxt->device.data.dev_name);
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
  oc_ees_data_t data;
  oc_ees_prov_cb_t prov_cb;
} oc_ees_resource_t;

typedef struct
{
  oc_resource_t *handle;
  oc_ees_rsp_data_t data;
  oc_ees_rsp_prov_cb_t prov_cb;
} oc_ees_rsp_conf_resource_t;

typedef struct
{
  oc_resource_t *handle;
  oc_ees_rspcap_data_t data;
  oc_ees_rspcap_prov_cb_t prov_cb;
} oc_ees_rspcap_conf_resource_t;

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

oc_esim_enrollee_t *get_device_esim_enrollee(size_t device)
{
  return &g_esim_enrollee[device];
}

oc_es_result_t
oc_ees_set_device_info(size_t device, char *euicc_info, char *device_info)
{
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  oc_new_string(&(dev_cxt->rsp_cap.data.euicc_info), euicc_info, strlen(euicc_info));
  oc_new_string(&(dev_cxt->rsp_cap.data.device_info), device_info, strlen(device_info));

  return OC_ES_OK;
}

oc_es_result_t
oc_ees_set_error_code(size_t device, char *err_code)
{
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  oc_new_string(&(dev_cxt->ees.data.last_err_code), err_code, strlen(err_code));

  return OC_ES_OK;
}

/* Easy setup states can be reused for WES and EES.
    In case of EES, Operator server plays enroller role */
oc_es_result_t
oc_ees_set_state(size_t device, char *es_status)
{
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  oc_new_string(&(dev_cxt->ees.data.rsp_status), es_status, strlen(es_status));
  oc_notify_observers((oc_resource_t *)dev_cxt->ees.handle);
  return OC_ES_OK;
}

oc_string_t
oc_ees_get_state(size_t device)
{
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  return dev_cxt->ees.data.rsp_status;
}

oc_es_result_t oc_ees_set_resource_callbacks(size_t device, oc_ees_prov_cb_t ees_prov_cb,
	oc_ees_rsp_prov_cb_t rsp_prov_cb, oc_ees_rspcap_prov_cb_t rspcap_prov_cb)
{
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  dev_cxt->ees.prov_cb = ees_prov_cb;
  dev_cxt->rsp.prov_cb = rsp_prov_cb;
  dev_cxt->rsp_cap.prov_cb = rspcap_prov_cb;

  return OC_ES_OK;
}

oc_es_result_t oc_ees_set_userdata_callbacks(size_t device, oc_es_read_userdata_cb_t readcb,
	oc_es_write_userdata_cb_t writecb, oc_es_free_userdata_cb_t freecb)
{
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  dev_cxt->read_cb = readcb;
  dev_cxt->write_cb = writecb;
  dev_cxt->free_cb = freecb;

  return OC_ES_OK;
}


static void
set_rspcap_properties(oc_resource_t *resource, oc_rep_t *rep, void *user_data)
{
  bool res_changed = false;
  char *str_val = NULL;
  size_t str_len = 0;
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(resource->device);

  OC_DBG("update_rspcap_resource\n");

  while (rep != NULL) {
    switch (rep->type) {
      case OC_REP_STRING:
        if (oc_rep_get_string(rep, OC_RSRVD_EES_EUICCINFO,
            &str_val, &str_len)) {
           oc_new_string(&(dev_cxt->rsp_cap.data.euicc_info), str_val, str_len);
          res_changed = true;
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_DEVICEINFO,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->rsp_cap.data.device_info), str_val, str_len);
          res_changed = true;
        }
        break;
      default:
        break;
    }
    rep = rep->next;
  }

  if (res_changed && dev_cxt->rsp_cap.prov_cb) {
    dev_cxt->rsp_cap.prov_cb((oc_ees_rspcap_data_t *)&(dev_cxt->rsp_cap.data), user_data);
  }
}

static void
rspcap_post_handler(oc_request_t *request, oc_interface_mask_t interface,
	void *user_data)
{
  OC_DBG("rspcap_post_handler %d\n", interface);

  if (interface == OC_IF_BASELINE) {
    set_rspcap_properties((oc_resource_t *)request->resource, request->request_payload, user_data);
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
get_rspcap_properties(oc_resource_t *resource, oc_interface_mask_t interface,
                void *user_data)
{
  (void)user_data;
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(resource->device);

  OC_DBG("get_rspcap_properties\n");

  switch (interface) {
  case OC_IF_BASELINE:
  case OC_IF_R:
          oc_rep_set_text_string(root, euiccinfo, oc_string(dev_cxt->rsp_cap.data.euicc_info));
          oc_rep_set_text_string(root, deviceinfo, oc_string(dev_cxt->rsp_cap.data.device_info));
    break;
  default:
    break;
  }
}

static void
rspcap_get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  OC_DBG("rspcap_get_handler %d\n", interface);

  if (interface == OC_IF_BASELINE || interface == OC_IF_R) {
    oc_rep_start_root_object();
    get_rspcap_properties((oc_resource_t *)request->resource, interface, user_data);
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
set_rspconf_properties(oc_resource_t *resource, oc_rep_t *rep, void *user_data)
{
  bool res_changed = false;
  char *str_val = NULL;
  size_t str_len = 0;
  bool ccr = true;
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(resource->device);

  OC_DBG("set_rspconf_properties\n");

  while (rep != NULL) {
    switch (rep->type) {
      case OC_REP_STRING:
        if (oc_rep_get_string(rep, OC_RSRVD_EES_ACTIVATIONCODE,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->rsp.data.activation_code), str_val, str_len);
          res_changed = true;
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_PROFMETADATA,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->rsp.data.profile_metadata), str_val, str_len);
          res_changed = true;
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_CONFIRMATIONCODE,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->rsp.data.confirm_code), str_val, str_len);
          res_changed = true;
        }
        break;
      case OC_REP_BOOL:
        if (oc_rep_get_bool(rep, OC_RSRVD_EES_CONFIRMATIONCODEREQUIRED, &ccr)) {
          dev_cxt->rsp.data.confirm_code_required = ccr;
          res_changed = true;
        }
        break;
      default:
        break;
    }
    rep = rep->next;
  }

  if (res_changed && dev_cxt->rsp.prov_cb) {
    dev_cxt->rsp.prov_cb((oc_ees_rsp_data_t *)&(dev_cxt->rsp.data), user_data);
  }
}

static void
rspconf_post_handler(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  OC_DBG("rspconf_post_handler %d\n", interface);

  if (interface == OC_IF_BASELINE || interface == OC_IF_RW) {
    set_rspconf_properties((oc_resource_t *)request->resource, (oc_rep_t *)request->request_payload,
                            user_data);
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
get_rspconf_properties(oc_resource_t *resource, oc_interface_mask_t interface,
            void *user_data)
{

  (void)user_data;
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(resource->device);

  OC_DBG("get_rspconf_properties\n");

  switch (interface) {
  case OC_IF_BASELINE:
  case OC_IF_RW:
          oc_rep_set_text_string(root, ac, oc_string(dev_cxt->rsp.data.activation_code));
          oc_rep_set_text_string(root, pm, oc_string(dev_cxt->rsp.data.profile_metadata));
          oc_rep_set_text_string(root, cc, oc_string(dev_cxt->rsp.data.confirm_code));
          oc_rep_set_boolean(root, ccr, dev_cxt->rsp.data.confirm_code_required);
    break;
  default:
    break;
  }
}

static void
rspconf_get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  OC_DBG("rspconf_get_handler\n");

  if (interface == OC_IF_BASELINE || interface == OC_IF_RW) {
    oc_rep_start_root_object();
    get_rspconf_properties((oc_resource_t *)request->resource, interface, user_data);
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}


bool
set_ees_properties(oc_resource_t *resource, oc_rep_t *rep, void *user_data)
{
  bool res_changed = false;
  char *str_val = NULL;
  size_t str_len = 0;
  oc_collection_t *ees = (oc_collection_t *)resource;
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(ees->device);

  OC_DBG("set_ees_properties\n");
  // Handle all the ees custom props
  while (rep != NULL) {
    switch (rep->type) {
      case OC_REP_STRING:
        if (oc_rep_get_string(rep, OC_RSRVD_EES_PROVSTATUS,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->ees.data.rsp_status), str_val ,str_len);
          res_changed = true;
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_LASTERRORREASON,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->ees.data.last_err_reason), str_val, str_len);
          res_changed = true;
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_LASTERRORCODE,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->ees.data.last_err_code), str_val ,str_len);
          res_changed = true;
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_LASTERRORRDESCRIPTION,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->ees.data.last_err_desc), str_val ,str_len);
          res_changed = true;
        }
        if (oc_rep_get_string(rep, OC_RSRVD_EES_ENDUSERCONFIRMATION,
            &str_val, &str_len)) {
          oc_new_string(&(dev_cxt->ees.data.end_user_conf), str_val ,str_len);
          res_changed = true;
        }
        break;
      default:
        break;
    }
    rep = rep->next;
  }

  if (res_changed && dev_cxt->ees.prov_cb) {
    dev_cxt->ees.prov_cb((oc_ees_data_t *)&(dev_cxt->ees.data), user_data);
  }
  return true;
}

static void
ees_post_handler(oc_request_t *request, oc_interface_mask_t interface,
              void *user_data)
{
  OC_DBG("ees_post_handler\n");
  if ((interface == OC_IF_BASELINE)||(interface == OC_IF_B)) {
    set_ees_properties((oc_resource_t *)request->resource, (oc_rep_t *)request->request_payload,
                      user_data);
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

void
get_ees_properties(oc_resource_t *resource, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)user_data;
  oc_collection_t *ees = (oc_collection_t *)resource;
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(ees->device);

  OC_DBG("get_ees_properties\n");

  switch (interface) {
  case OC_IF_BASELINE:
  case OC_IF_B:
  case OC_IF_LL:
    oc_rep_set_text_string(root, ps, oc_string(dev_cxt->ees.data.rsp_status));
    oc_rep_set_text_string(root, ler, oc_string(dev_cxt->ees.data.last_err_reason));
    oc_rep_set_text_string(root, lec, oc_string(dev_cxt->ees.data.last_err_code));
    oc_rep_set_text_string(root, led, oc_string(dev_cxt->ees.data.last_err_desc));
    oc_rep_set_text_string(root, euc, oc_string(dev_cxt->ees.data.end_user_conf));
    break;
  default:
    break;
  }
}

static void
ees_get_handler(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  if ((interface == OC_IF_BASELINE)||(interface == OC_IF_LL) || (interface == OC_IF_B)) {
    oc_rep_start_root_object();
    get_ees_properties((oc_resource_t *)request->resource, interface, user_data);
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

void
oc_create_esim_easysetup_resource(size_t device, void *user_data)
{
  OC_DBG("oc_create_esim_easysetup_resource : %d", device);

#ifdef OC_DYNAMIC_ALLOCATION
  assert(device <  OC_MAX_NUM_DEVICES);
#endif

  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  // Initiatize EES Resource state
  oc_new_string(&(dev_cxt->ees.data.rsp_status), EES_PS_NONE, 0);
  oc_new_string(&(dev_cxt->ees.data.last_err_reason), EES_PS_NONE, 0);
  oc_new_string(&(dev_cxt->ees.data.last_err_code), EES_PS_NONE, 0);
  oc_new_string(&(dev_cxt->ees.data.last_err_desc), EES_PS_NONE, 0);
  oc_new_string(&(dev_cxt->ees.data.end_user_conf), EES_PS_NONE, 0);

  // Esim Easy Setup Resource
  oc_core_populate_collection(
    OCF_EES,
    device,
    OC_RSRVD_EES_URI_ESIMEASYSETUP,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
    2,
    OC_RSRVD_EES_RES_TYPE_ESIMEASYSETUP,
    "oic.wk.col");

  dev_cxt->ees.handle =
    (oc_collection_t *)oc_core_get_resource_by_index(OCF_EES, device);

  // Add Self link to EES resource
  oc_link_t *self = oc_new_link((oc_resource_t *)dev_cxt->ees.handle);
  oc_collection_add_link((oc_resource_t *)dev_cxt->ees.handle, self);


  //Enables RETRIEVEs/UPDATEs to Collection properties
  oc_resource_set_request_handler((oc_resource_t *)dev_cxt->ees.handle,
                                OC_GET, ees_get_handler, user_data);
  oc_resource_set_request_handler((oc_resource_t *)dev_cxt->ees.handle,
                                OC_POST, ees_post_handler, user_data);
  oc_resource_set_properties_cbs((oc_resource_t *)dev_cxt->ees.handle, get_ees_properties, user_data,
                                set_ees_properties, user_data);

  //RSP Conf Recource
  oc_core_populate_resource(
    OCF_EES_RSP,
    device,
    OC_RSRVD_EES_URI_RSPCONF,
    OC_IF_RW | OC_IF_BASELINE,
    OC_IF_BASELINE,
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
  // Initialize Confrmation Code Required to True
  dev_cxt->rsp.data.confirm_code_required = true;

  // RSP Capability Conf Resource
  oc_core_populate_resource(
    OCF_EES_RSPCAP,
    device,
    OC_RSRVD_EES_URI_RSPCAP,
    OC_IF_R | OC_IF_BASELINE,
    OC_IF_BASELINE,
    OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
    rspcap_get_handler,
    0,
    rspcap_post_handler,
    0,
    1,
    OC_RSRVD_EES_RES_TYPE_RSPCAP);

  dev_cxt->rsp_cap.handle = oc_core_get_resource_by_index(OCF_EES_RSPCAP, device);
  oc_link_t *l2 = oc_new_link(dev_cxt->rsp_cap.handle);
  oc_collection_add_link((oc_resource_t *)dev_cxt->ees.handle, l2);
}

void
oc_delete_esim_easysetup_resource(size_t device)
{
  OC_DBG("oc_delete_esim_easysetup_resource : %d", device);
  oc_esim_enrollee_t *dev_cxt = get_device_esim_enrollee(device);

  // dev_cxt->rsp.handle is freed during core shwtdown
  oc_free_string(&dev_cxt->rsp.data.activation_code);
  oc_free_string(&dev_cxt->rsp.data.profile_metadata);
  oc_free_string(&dev_cxt->rsp.data.confirm_code);
  dev_cxt->rsp.prov_cb = NULL;

  // dev_cxt->rsp_cap.handle is freed during core shwtdown
  oc_free_string(&dev_cxt->rsp_cap.data.euicc_info);
  oc_free_string(&dev_cxt->rsp_cap.data.device_info);
  dev_cxt->rsp_cap.prov_cb = NULL;

  // Collection is not freed by default. Free collection here.
  if (dev_cxt->ees.handle) {
    oc_delete_collection((oc_resource_t *)dev_cxt->ees.handle);
    dev_cxt->ees.handle = NULL;
  }
  oc_free_string(&dev_cxt->ees.data.rsp_status);
  oc_free_string(&dev_cxt->ees.data.last_err_reason);
  oc_free_string(&dev_cxt->ees.data.last_err_code);
  oc_free_string(&dev_cxt->ees.data.last_err_desc);
  oc_free_string(&dev_cxt->ees.data.end_user_conf);
  dev_cxt->ees.prov_cb = NULL;
}

#endif // OC_ESIM_EASYSETUP
