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
#include "oc_easysetup_enrollee.h"
#include "oc_api.h"
#include "oc_collection.h"
#include "oc_log.h"

#include "es_utils.h"

typedef void (*es_connect_request_cb)(es_connect_request *);
typedef void (*es_wifi_conf_cb)(es_wifi_conf_data *);
typedef void (*es_dev_conf_cb)(es_dev_conf_data *);
typedef void (*es_rsp_conf_cb)(es_rsp_conf_data *);
typedef void (*es_rspcap_conf_cb)(es_rspcap_conf_data *);

typedef struct
{
  oc_resource_t *handle;
} es_resource_t;

enum
{
  ES_RES_TYPE_EASYSETUP = 0,
  ES_RES_TYPE_WIFI_CONF,
  ES_RES_TYPE_DEV_CONF,
  ES_RES_TYPE_RSP_CONF,
  ES_RES_TYPE_RSPCAP_CONF,
  ES_RES_TYPE_MAX
};

typedef struct
{
  es_resource_t base;
  // This structure is synced with es_connect_request
  struct
  {
    es_connect_type connect_request[NUM_CONNECT_TYPE];
    int num_request;
    prov_status status;
    es_error_code last_err_code;
  } data;
  es_connect_request_cb connect_request_cb;
} es_easysetup_resource_t;

#define es_res_cast(p) (es_easysetup_resource_t *)(p)

typedef struct
{
  es_resource_t base;
  // This structure is synced with es_wifi_conf_data
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
  es_wifi_conf_cb wifi_conf_prov_cb;
} es_wifi_conf_resource_t;

#define wifi_res_cast(p) (es_wifi_conf_resource_t *)(p)

typedef struct
{
  es_resource_t base;
  struct
  {
    oc_string_t dev_name;
  } data;
  es_dev_conf_cb dev_prov_cb;
} es_dev_conf_resource_t;

#define dev_res_cast(p) (es_dev_conf_resource_t *)(p)

typedef struct
{
  es_resource_t base;
  struct
  {
    oc_string_t access_code;
  } data;
  es_rsp_conf_cb rsp_prov_cb;
} es_rsp_conf_resource_t;

#define rsp_res_cast(p) (es_rsp_conf_resource_t *)(p)

typedef struct
{
  es_resource_t base;
  struct
  {
    oc_string_t euicc_info;
    oc_string_t device_info;  
  } data;
  es_rspcap_conf_cb rspcap_prov_cb;
} es_rspcap_conf_resource_t;

#define rspcap_res_cast(p) (es_rspcap_conf_resource_t *)(p)


typedef struct
{
  es_resource_t *res[ES_RES_TYPE_MAX];
  es_read_userdata_cb read_cb;
  es_write_userdata_cb write_cb;
  es_free_userdata free_userdata;
} es_enrollee_t;

// Global Enrolee Instance
es_enrollee_t *g_enrollee;

static void
easysetup_get_handler(oc_request_t *request, oc_interface_mask_t interface,
              void *user_data)
{
  (void)request;
  (void)interface;
  (void)user_data;
  OC_DBG("GET request received");

  es_easysetup_resource_t *es_res =
              es_res_cast(g_enrollee->res[ES_RES_TYPE_EASYSETUP]);

  oc_rep_start_root_object();
  es_rep_set_int(root, ps, es_res->data.status);
  es_rep_set_int(root, lec, es_res->data.last_err_code);
  oc_rep_end_root_object();
}

static void
update_easysetup_resource(oc_request_t *request)
{
  int64_t *connect_req;
  size_t connect_req_size;
  es_easysetup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASYSETUP]);

  if (oc_rep_get_int_array(request->request_payload, OC_RSRVD_ES_CONNECT,
                           &connect_req, &connect_req_size)) {
    memset(es_res->data.connect_request, 0,
           sizeof(es_res->data.connect_request));
    es_res->data.num_request = 0;
    size_t i;
    for (i = 0; i < NUM_CONNECT_TYPE && i < connect_req_size; ++i) {
      if (connect_req[i] == ES_CONNECT_WIFI ||
          connect_req[i] == ES_CONNECT_COAPCLOUD) {
        es_res->data.connect_request[es_res->data.num_request++] =
          connect_req[i];
      }
    }

    if (es_res->data.connect_request[0] != ES_CONNECT_NONE &&
        es_res->connect_request_cb) {
      es_connect_request conn_req;
      memcpy(&conn_req, &es_res->data, sizeof(es_connect_request));
      es_res->connect_request_cb(&conn_req);
    }
  }
}

static void
easysetup_post_handler(oc_request_t *request, oc_interface_mask_t interface,
               void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_B && interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_easysetup_resource(request);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
construct_response_of_wificonf(void)
{
  es_wifi_conf_resource_t *wifi_res =
    wifi_res_cast(g_enrollee->res[ES_RES_TYPE_WIFI_CONF]);

  oc_rep_start_root_object();
  oc_process_baseline_interface(wifi_res->base.handle);

  oc_rep_set_array(root, swmt);
  for (int i = 0; i < wifi_res->data.num_mode; i++) {
#ifdef OC_SPEC_VER_OIC
    // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
    oc_rep_add_int(swmt, (int)wifi_res->data.supported_mode[i]);
#else
    // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
    oc_rep_add_text_string(swmt, oc_string(wifi_mode_enum_tostring(wifi_res->data.supported_mode[i])));
#endif  // OC_SPEC_VER_OIC
  }

  oc_rep_close_array(root, swmt);

#ifdef OC_SPEC_VER_OIC
  // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
  es_rep_set_int(root, swf, (int)wifi_res->data.supported_freq);
#else
  // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
  oc_rep_set_array(root, swf);

  switch(wifi_res->data.supported_freq) {
     case WIFI_24G:
     case WIFI_5G :
       oc_rep_add_text_string(swf, oc_string(wifi_freq_enum_tostring(wifi_res->data.supported_freq)));
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

  es_rep_set_text_string(root, tnn, oc_string(wifi_res->data.ssid));
  es_rep_set_text_string(root, cd, oc_string(wifi_res->data.cred));

#ifdef OC_SPEC_VER_OIC
  // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
  es_rep_set_int(root, wat, (int)wifi_res->data.auth_type);
  es_rep_set_int(root, wet, (int)wifi_res->data.enc_type);
#else
  // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
  es_rep_set_text_string(root, wat, oc_string(wifi_authtype_enum_tostring(wifi_res->data.auth_type)));
  es_rep_set_text_string(root, wet, oc_string(wifi_enctype_enum_tostring(wifi_res->data.enc_type)));

  // new properties in OCF 1.3 - swat and swet.
  oc_rep_set_array(root, swat);
  for (int i = 0; i < wifi_res->data.num_supported_authtype; i++) {
    oc_rep_add_text_string(swat, oc_string(wifi_mode_enum_tostring(wifi_res->data.supported_authtype[i])));
  }
  oc_rep_close_array(root, swat);

  oc_rep_set_array(root, swet);
  for (int i = 0; i < wifi_res->data.num_supported_enctype; i++) {
    oc_rep_add_text_string(swet, oc_string(wifi_mode_enum_tostring(wifi_res->data.supported_enctype[i])));
  }
  oc_rep_close_array(root, swet);
#endif  // OC_SPEC_VER_OIC

  // Invoke callback for user defined attributes
  if (g_enrollee->write_cb) {
    g_enrollee->write_cb(NULL, OC_RSRVD_ES_RES_TYPE_WIFICONF);
  }
  oc_rep_end_root_object();
}

static void
wifi_get_handler(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  construct_response_of_wificonf();
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_wifi_conf_resource(oc_request_t *request)
{
  bool changed = false;
  es_wifi_conf_data wifi_cb_data;
  es_wifi_conf_resource_t *wifi_res =
    wifi_res_cast(g_enrollee->res[ES_RES_TYPE_WIFI_CONF]);

  {
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_SSID, &str_val,
                          &str_len)) {
      es_new_string(&(wifi_res->data.ssid), str_val);
      changed = true;
    }

    str_val = NULL;
    str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_CRED, &str_val,
                          &str_len)) {
      es_new_string(&(wifi_res->data.cred), str_val);
      changed = true;
    }
  }

  {
#ifdef OC_SPEC_VER_OIC
    // Follow Easy Setup Resource Model prior to OCF 1.3 spec.
    int64_t int_val = 0;
    if (oc_rep_get_int(request->request_payload, OC_RSRVD_ES_AUTHTYPE,
                       &int_val)) {
      wifi_res->data.auth_type = int_val;
      changed = true;
    }

    if (oc_rep_get_int(request->request_payload, OC_RSRVD_ES_ENCTYPE,
                       &int_val)) {
      wifi_res->data.enc_type = int_val;
      changed = true;
    }
#else
    // Follow Easy Setup Resource Model OCF 1.3 spec onwards.
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_AUTHTYPE, &str_val,
                          &str_len)) {
      wifi_authtype_string_toenum(str_val, &wifi_res->data.auth_type);
      changed = true;
    }

    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_ENCTYPE, &str_val,
                          &str_len)) {
      wifi_enctype_string_toenum(str_val, &wifi_res->data.enc_type);
      changed = true;
    }
#endif  // OC_SPEC_VER_OIC
  }

  // Invoke callback for user defined attributes
  memcpy(&wifi_cb_data, &wifi_res->data, sizeof(es_wifi_conf_data));
  wifi_cb_data.userdata = NULL;
  if (g_enrollee->read_cb) {
    g_enrollee->read_cb(request->request_payload, OC_RSRVD_ES_RES_TYPE_WIFICONF,
                        &wifi_cb_data.userdata);
  }

  // TODO: what about user data change?
  if (changed) {
    if (wifi_res->wifi_conf_prov_cb) {
      wifi_res->wifi_conf_prov_cb(&wifi_cb_data);
    }

    // Notify observers about data change
    oc_notify_observers(wifi_res->base.handle);
  }

  if (g_enrollee->free_userdata) {
    g_enrollee->free_userdata(wifi_cb_data.userdata,
                              OC_RSRVD_ES_RES_TYPE_WIFICONF);
  }
}

static void
wifi_post_handler(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_wifi_conf_resource(request);
  construct_response_of_wificonf();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
construct_response_of_devconf(void)
{
  es_dev_conf_resource_t *dev_res =
    dev_res_cast(g_enrollee->res[ES_RES_TYPE_DEV_CONF]);

  oc_rep_start_root_object();
  oc_process_baseline_interface(dev_res->base.handle);
  es_rep_set_text_string(root, dn, oc_string(dev_res->data.dev_name));

  // Invoke callback for user defined attributes
  if (g_enrollee->write_cb) {
    g_enrollee->write_cb(NULL, OC_RSRVD_ES_RES_TYPE_DEVCONF);
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

  construct_response_of_devconf();
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_devconf_resource(oc_request_t *request)
{
  es_dev_conf_data dev_cb_data;
  dev_cb_data.userdata = NULL;
  es_dev_conf_resource_t *dev_res =
    dev_res_cast(g_enrollee->res[ES_RES_TYPE_DEV_CONF]);

  // Invoke callback for user defined attributes
  if (g_enrollee->read_cb) {
    g_enrollee->read_cb(request->request_payload, OC_RSRVD_ES_RES_TYPE_DEVCONF,
                        &dev_cb_data.userdata);
  }

  if (dev_cb_data.userdata && dev_res->dev_prov_cb) {
    dev_res->dev_prov_cb(&dev_cb_data);
  }

  // Notify observers about data change
  oc_notify_observers(dev_res->base.handle);

  if (g_enrollee->free_userdata) {
    g_enrollee->free_userdata(dev_cb_data.userdata,
                              OC_RSRVD_ES_RES_TYPE_DEVCONF);
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
  construct_response_of_devconf();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
construct_response_of_rspconf(void)
{
  es_rsp_conf_resource_t *rsp_res =
    rsp_res_cast(g_enrollee->res[ES_RES_TYPE_RSP_CONF]);

  oc_rep_start_root_object();
  oc_process_baseline_interface(rsp_res->base.handle);
  es_rep_set_text_string(root, ac, oc_string(rsp_res->data.access_code));

  // Invoke callback for user defined attributes
  if (g_enrollee->write_cb) {
    g_enrollee->write_cb(NULL, OC_RSRVD_ES_RES_TYPE_RSPCONF);
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

  construct_response_of_rspconf();
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_rspconf_resource(oc_request_t *request)
{
  es_rsp_conf_data rsp_cb_data;
  rsp_cb_data.userdata = NULL; // TODO : Pass access code to application
  es_rsp_conf_resource_t *rsp_res =
    rsp_res_cast(g_enrollee->res[ES_RES_TYPE_RSP_CONF]);

  // Invoke callback for user defined attributes
  if (g_enrollee->read_cb) {
    g_enrollee->read_cb(request->request_payload, OC_RSRVD_ES_RES_TYPE_RSPCONF,
                        &rsp_cb_data.userdata);
  }

  if (rsp_cb_data.userdata && rsp_res->rsp_prov_cb) {
    rsp_res->rsp_prov_cb(&rsp_cb_data);
  }

  // Notify observers about data change
  oc_notify_observers(rsp_res->base.handle);

  if (g_enrollee->free_userdata) {
    g_enrollee->free_userdata(rsp_cb_data.userdata,
                              OC_RSRVD_ES_RES_TYPE_RSPCONF);
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
  construct_response_of_rspconf();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
construct_response_of_rspcapconf(void)
{
  es_rspcap_conf_resource_t *rspcap_res =
    rspcap_res_cast(g_enrollee->res[ES_RES_TYPE_RSPCAP_CONF]);

  oc_rep_start_root_object();
  oc_process_baseline_interface(rspcap_res->base.handle);
  es_rep_set_text_string(root, euiccinfo, oc_string(rspcap_res->data.euicc_info));
  es_rep_set_text_string(root, deviceinfo, oc_string(rspcap_res->data.device_info));

  // Invoke callback for user defined attributes
  if (g_enrollee->write_cb) {
    g_enrollee->write_cb(NULL, OC_RSRVD_ES_RES_TYPE_RSPCAPCONF);
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
  construct_response_of_rspcapconf();
  oc_send_response(request, OC_STATUS_OK);
}

static void
update_rspcapconf_resource(oc_request_t *request)
{
  es_rspcap_conf_data rspcap_cb_data;
  rspcap_cb_data.userdata = NULL; // TODO : Pass euicc info, device info to application
  es_rspcap_conf_resource_t *rspcap_res =
    rspcap_res_cast(g_enrollee->res[ES_RES_TYPE_RSPCAP_CONF]);

  // Invoke callback for user defined attributes
  if (g_enrollee->read_cb) {
    g_enrollee->read_cb(request->request_payload, OC_RSRVD_ES_RES_TYPE_RSPCAPCONF,
                        &rspcap_cb_data.userdata);
  }

  if (rspcap_cb_data.userdata && rspcap_res->rspcap_prov_cb) {
    rspcap_res->rspcap_prov_cb(&rspcap_cb_data);
  }

  // Notify observers about data change
  oc_notify_observers(rspcap_res->base.handle);

  if (g_enrollee->free_userdata) {
    g_enrollee->free_userdata(rspcap_cb_data.userdata,
                              OC_RSRVD_ES_RES_TYPE_RSPCAPCONF);
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
  construct_response_of_rspcapconf();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
deinit_wifi_conf_resource(void)
{
  es_wifi_conf_resource_t *wifi_res =
    wifi_res_cast(g_enrollee->res[ES_RES_TYPE_WIFI_CONF]);
  wifi_res->wifi_conf_prov_cb = NULL;
  if (wifi_res->base.handle) {
    oc_delete_resource(wifi_res->base.handle);
    wifi_res->base.handle = NULL;
  }
  es_free_string(wifi_res->data.ssid);
  es_free_string(wifi_res->data.cred);
  free(wifi_res);
}

static void
deinit_dev_conf_resource(void)
{
  es_dev_conf_resource_t *dev_res =
    dev_res_cast(g_enrollee->res[ES_RES_TYPE_DEV_CONF]);
  dev_res->dev_prov_cb = NULL;
  if (dev_res->base.handle) {
    oc_delete_resource(dev_res->base.handle);
    dev_res->base.handle = NULL;
  }
  es_free_string(dev_res->data.dev_name);
  free(dev_res);
}

static void
deinit_rsp_conf_resource(void)
{
  es_rsp_conf_resource_t *rsp_res =
    rsp_res_cast(g_enrollee->res[ES_RES_TYPE_RSP_CONF]);
  rsp_res->rsp_prov_cb = NULL;
  if (rsp_res->base.handle) {
    oc_delete_resource(rsp_res->base.handle);
    rsp_res->base.handle = NULL;
  }
  es_free_string(rsp_res->data.access_code);
  free(rsp_res);
}

static void
deinit_rspcap_conf_resource(void)
{
  es_rspcap_conf_resource_t *rspcap_res =
    rspcap_res_cast(g_enrollee->res[ES_RES_TYPE_RSPCAP_CONF]);
  rspcap_res->rspcap_prov_cb = NULL;
  if (rspcap_res->base.handle) {
    oc_delete_resource(rspcap_res->base.handle);
    rspcap_res->base.handle = NULL;
  }
  es_free_string(rspcap_res->data.euicc_info);
  es_free_string(rspcap_res->data.device_info);
  
  free(rspcap_res);
}

static void
deinit_easysetup_resource(void)
{
  es_easysetup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASYSETUP]);
  es_res->connect_request_cb = NULL;
  if (es_res->base.handle) {
    oc_delete_collection(es_res->base.handle);
    es_res->base.handle = NULL;
  }
  free(es_res);
}
	
static es_result_e
init_easysetup_resource(bool is_secured, es_connect_request_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  g_enrollee = (es_enrollee_t *)calloc(1, sizeof(es_enrollee_t));
  MEM_ALLOC_CHECK(g_enrollee);

  es_easysetup_resource_t *es_res = (es_easysetup_resource_t *)calloc(1, sizeof(es_easysetup_resource_t));
  MEM_ALLOC_CHECK(es_res);

  es_res->data.status = ES_STATE_INIT;
  es_res->data.last_err_code = ES_ERRCODE_NO_ERROR;

  for (int i = 0; i < NUM_CONNECT_TYPE; ++i) {
    es_res->data.connect_request[i] = ES_CONNECT_NONE;
  }

  es_res->data.num_request = 0;
  es_res->connect_request_cb = cb;

  oc_resource_t *col = oc_new_collection("easysetup", OC_RSRVD_ES_URI_EASYSETUP, 4, 4, 4, 0);
  NULL_CHECK(col, "Failed to create!");

  oc_resource_bind_resource_type(col, OC_RSRVD_ES_RES_TYPE_EASYSETUP);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_bind_resource_interface(col, OC_IF_LL);
  oc_resource_bind_resource_interface(col, OC_IF_B);
  oc_resource_set_discoverable(col, true);
  oc_resource_set_observable(col, true);
  oc_resource_set_request_handler(col, OC_GET, easysetup_get_handler, NULL);
  oc_resource_set_request_handler(col, OC_POST, easysetup_post_handler, NULL);

#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(col);
  }
#endif

  // Add Self Link for Easy Setup Resource
  oc_link_t *link = oc_new_link(col);
  NULL_CHECK(link, "Failed to create link!");

  oc_collection_add_link(col, link);
  oc_add_collection(col);
  es_res->base.handle = col;
  g_enrollee->res[ES_RES_TYPE_EASYSETUP] = (es_resource_t *)es_res;
  return ES_OK;

exit:
  return ES_ERROR;
}


static es_result_e
init_wifi_conf_resource(bool is_secured, es_wifi_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  INPUT_PARAM_NULL_CHECK(cb);

  es_easysetup_resource_t *es_res =  es_res_cast(g_enrollee->res[ES_RES_TYPE_EASYSETUP]);
  es_wifi_conf_resource_t *wifi_res = (es_wifi_conf_resource_t *)calloc(1, sizeof(es_wifi_conf_resource_t));
  MEM_ALLOC_CHECK(wifi_res);

  wifi_res->data.supported_freq = WIFI_BOTH;
  wifi_res->data.supported_mode[0] = WIFI_11A;
  wifi_res->data.supported_mode[1] = WIFI_11B;
  wifi_res->data.supported_mode[2] = WIFI_11G;
  wifi_res->data.supported_mode[3] = WIFI_11N;
  wifi_res->data.num_mode = 4;
  wifi_res->data.auth_type = NONE_AUTH;
  wifi_res->data.enc_type = NONE_ENC;

#ifndef OC_SPEC_VER_OIC  // Spec Version is OCF 1.3 or more.
  wifi_res->data.num_supported_authtype = NUM_WIFIAUTHTYPE;
  wifi_res->data.supported_authtype[0] = NONE_AUTH;
  wifi_res->data.supported_authtype[1] = WEP;
  wifi_res->data.supported_authtype[2] = WPA_PSK;
  wifi_res->data.supported_authtype[3] = WPA2_PSK;

  wifi_res->data.num_supported_enctype = NUM_WIFIENCTYPE;
  wifi_res->data.supported_enctype[0] = NONE_ENC;
  wifi_res->data.supported_enctype[1] = WEP_64;
  wifi_res->data.supported_enctype[2] = WEP_128;
  wifi_res->data.supported_enctype[3] = TKIP;
  wifi_res->data.supported_enctype[4] = AES;
  wifi_res->data.supported_enctype[5] = TKIP_AES;
#endif  // OC_SPEC_VER_OIC

  wifi_res->wifi_conf_prov_cb = cb;

  oc_resource_t *res = oc_new_resource("wificonf", OC_RSRVD_ES_URI_WIFICONF, 1, 0);
  RESOURCE_CHECK(res);

  oc_resource_bind_resource_type(res, OC_RSRVD_ES_RES_TYPE_WIFICONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);

#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(res);
  }
#endif

  oc_resource_set_request_handler(res, OC_GET, wifi_get_handler, NULL);
  oc_resource_set_request_handler(res, OC_POST, wifi_post_handler, NULL);
  oc_add_resource(res);
  wifi_res->base.handle = res;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(res);
  RESOURCE_LINK_CHECK(link);

  oc_collection_add_link(es_res->base.handle, link);
  g_enrollee->res[ES_RES_TYPE_WIFI_CONF] = (es_resource_t *)wifi_res;
  return ES_OK;

exit:
  return ES_ERROR;
}

static es_result_e
init_dev_conf_resource(bool is_secured, es_dev_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  INPUT_PARAM_NULL_CHECK(cb);

  es_easysetup_resource_t *es_res = es_res_cast(g_enrollee->res[ES_RES_TYPE_EASYSETUP]);
  es_dev_conf_resource_t *dev_res = (es_dev_conf_resource_t *)calloc(1, sizeof(es_dev_conf_resource_t));
  MEM_ALLOC_CHECK(dev_res);

  dev_res->dev_prov_cb = cb;

  oc_resource_t *res = oc_new_resource("devconf", OC_RSRVD_ES_URI_DEVCONF, 1, 0);
  RESOURCE_CHECK(res);

  oc_resource_bind_resource_type(res, OC_RSRVD_ES_RES_TYPE_DEVCONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(res);
  }
#endif
  oc_resource_set_request_handler(res, OC_GET, devconf_get_handler, NULL);
  oc_resource_set_request_handler(res, OC_POST, devconf_post_handler, NULL);
  oc_add_resource(res);
  dev_res->base.handle = res;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(res);
  RESOURCE_LINK_CHECK(link);

  oc_collection_add_link(es_res->base.handle, link);
  g_enrollee->res[ES_RES_TYPE_DEV_CONF] = (es_resource_t *)dev_res;
  return ES_OK;

exit:
  return ES_ERROR;
}

static es_result_e
init_rsp_conf_resource(bool is_secured, es_rsp_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  INPUT_PARAM_NULL_CHECK(cb);

  es_easysetup_resource_t *es_res = es_res_cast(g_enrollee->res[ES_RES_TYPE_EASYSETUP]);
  es_rsp_conf_resource_t *rsp_res = (es_rsp_conf_resource_t *)calloc(1, sizeof(es_rsp_conf_resource_t));
  MEM_ALLOC_CHECK(rsp_res);

  rsp_res->rsp_prov_cb = cb;

  oc_resource_t *res = oc_new_resource("rspconf", OC_RSRVD_ES_URI_RSPCONF, 1, 0);
  RESOURCE_CHECK(res);

  oc_resource_bind_resource_type(res, OC_RSRVD_ES_RES_TYPE_RSPCONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(res);
  }
#endif
  oc_resource_set_request_handler(res, OC_GET, rspconf_get_handler, NULL);
  oc_resource_set_request_handler(res, OC_POST, rspconf_post_handler, NULL);
  oc_add_resource(res);
  rsp_res->base.handle = res;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(res);
  RESOURCE_LINK_CHECK(link);

  oc_collection_add_link(es_res->base.handle, link);
  g_enrollee->res[ES_RES_TYPE_RSP_CONF] = (es_resource_t *)rsp_res;
  return ES_OK;

exit:
  return ES_ERROR;
}

static es_result_e
init_rspcap_conf_resource(bool is_secured, es_rspcap_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  INPUT_PARAM_NULL_CHECK(cb);

  es_easysetup_resource_t *es_res = es_res_cast(g_enrollee->res[ES_RES_TYPE_EASYSETUP]);
  es_rspcap_conf_resource_t *rspcap_res = (es_rspcap_conf_resource_t *)calloc(1, sizeof(es_rspcap_conf_resource_t));
  MEM_ALLOC_CHECK(rspcap_res);

  rspcap_res->rspcap_prov_cb = cb;

  oc_resource_t *res = oc_new_resource("rspcapabilityconf", OC_RSRVD_ES_URI_RSPCAPCONF, 1, 0);
  RESOURCE_CHECK(res);

  oc_resource_bind_resource_type(res, OC_RSRVD_ES_RES_TYPE_RSPCAPCONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(res);
  }
#endif
  oc_resource_set_request_handler(res, OC_GET, rspcapconf_get_handler, NULL);
  oc_resource_set_request_handler(res, OC_POST, rspcapconf_post_handler, NULL);
  oc_add_resource(res);
  rspcap_res->base.handle = res;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(res);
  RESOURCE_LINK_CHECK(link);

  oc_collection_add_link(es_res->base.handle, link);
  g_enrollee->res[ES_RES_TYPE_RSPCAP_CONF] = (es_resource_t *)rspcap_res;
  return ES_OK;

exit:
  return ES_ERROR;
}

void
delete_easysetup_resources(void)
{
  if (g_enrollee) {
    deinit_wifi_conf_resource();
    deinit_dev_conf_resource();
    deinit_rsp_conf_resource();
    deinit_rspcap_conf_resource();
    deinit_easysetup_resource();
    free(g_enrollee);
    g_enrollee = NULL;
  }
}

es_result_e
oc_init_enrollee(bool is_secured, es_resource_mask_e resource_mask,
                 es_provisioning_callbacks_s callbacks)
{
  es_result_e res = ES_ERROR;

  if (resource_mask == 0 ||
      resource_mask > (ES_WIFICONF_RESOURCE | ES_DEVCONF_RESOURCE | 
        ES_RSPCONF_RESOURCE | ES_RSPCAPCONF_RESOURCE)) {
    OC_ERR("Invalid input!");
    goto exit;
  }

  // Create easysetup collection resource
  res = init_easysetup_resource(is_secured, callbacks.connect_request_cb);
  if (res != ES_OK) {
    goto exit;
  }

  // Create wificonf resource
  if ((resource_mask & ES_WIFICONF_RESOURCE) == ES_WIFICONF_RESOURCE) {
    res = init_wifi_conf_resource(is_secured, callbacks.wifi_conf_prov_cb);
    if (res != ES_OK) {
      goto exit;
    }
  }

  // Create devconf resource
  if ((resource_mask & ES_DEVCONF_RESOURCE) == ES_DEVCONF_RESOURCE) {
    res = init_dev_conf_resource(is_secured, callbacks.dev_conf_prov_cb);
    if (res != ES_OK) {
      goto exit;
    }
  }

  // Create rspconf resource
  if ((resource_mask & ES_RSPCONF_RESOURCE) == ES_RSPCONF_RESOURCE) {
    res = init_rsp_conf_resource(is_secured, callbacks.rsp_conf_prov_cb);
    if (res != ES_OK) {
      goto exit;
    }
  }

  // Create rspcapabilityconf resource
  if ((resource_mask & ES_RSPCAPCONF_RESOURCE) == ES_RSPCAPCONF_RESOURCE) {
    res = init_rspcap_conf_resource(is_secured, callbacks.rspcap_conf_prov_cb);
    if (res != ES_OK) {
      goto exit;
    }
  }  
  
  return ES_OK;

exit:
  delete_easysetup_resources();
  return ES_ERROR;
}
	
void
oc_terminate_enrollee(void)
{
  delete_easysetup_resources();
  return;
}
