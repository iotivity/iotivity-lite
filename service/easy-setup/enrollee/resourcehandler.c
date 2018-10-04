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

#include "resourcehandler.h"
#include "es_utils.h"
#include "oc_collection.h"
#include "oc_log.h"
#include "util/oc_mem.h"

typedef void (*es_connect_request_cb)(es_connect_request *);
typedef void (*es_wifi_conf_cb)(es_wifi_conf_data *);
typedef void (*es_coap_cloud_conf_cb)(es_coap_cloud_conf_data *);
typedef void (*es_dev_conf_cb)(es_dev_conf_data *);

typedef struct
{
  oc_resource_t *handle;
} es_resource_t;

enum
{
  ES_RES_TYPE_EASY_SETUP = 0,
  ES_RES_TYPE_WIFI_CONF,
  ES_RES_TYPE_CLOUD_CONF,
  ES_RES_TYPE_DEV_CONF,
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
} es_easy_setup_resource_t;

#define es_res_cast(p) (es_easy_setup_resource_t *)(p)

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

  es_wifi_conf_cb wifi_prov_cb;
} es_wifi_conf_resource_t;

#define wifi_res_cast(p) (es_wifi_conf_resource_t *)(p)

typedef struct
{
  es_resource_t base;

  // This structure is synced with es_coap_cloud_conf_data
  struct
  {
    oc_string_t auth_code;
    oc_string_t access_token;
    oauth_tokentype access_token_type;
    oc_string_t auth_provider;
    oc_string_t ci_server;
  } data;

  es_coap_cloud_conf_cb cloud_prov_cb;
} es_cloud_conf_resource_t;

#define cloud_res_cast(p) (es_cloud_conf_resource_t *)(p)

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
  es_resource_t *res[ES_RES_TYPE_MAX];
  es_read_userdata_cb read_cb;
  es_write_userdata_cb write_cb;
  es_free_userdata free_userdata;
} es_enrollee_t;

es_enrollee_t *g_enrollee;

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
    int int_val = 0;
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
    if (wifi_res->wifi_prov_cb) {
      wifi_res->wifi_prov_cb(&wifi_cb_data);
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
update_coap_cloud_conf_resource(oc_request_t *request)
{
  bool changed = false;
  es_coap_cloud_conf_data cloud_cb_data;
  es_cloud_conf_resource_t *cloud_res =
    cloud_res_cast(g_enrollee->res[ES_RES_TYPE_CLOUD_CONF]);

  {
    char *str_val = NULL;
    size_t str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_AUTHCODE,
                          &str_val, &str_len)) {
      es_new_string(&(cloud_res->data.auth_code), str_val);
      changed = true;
    }

    str_val = NULL;
    str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_ACCESSTOKEN,
                          &str_val, &str_len)) {
      es_new_string(&(cloud_res->data.access_token), str_val);
      changed = true;
    }

    str_val = NULL;
    str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_AUTHPROVIDER,
                          &str_val, &str_len)) {
      es_new_string(&(cloud_res->data.auth_provider), str_val);
      changed = true;
    }

    str_val = NULL;
    str_len = 0;
    if (oc_rep_get_string(request->request_payload, OC_RSRVD_ES_CISERVER,
                          &str_val, &str_len)) {
      es_new_string(&(cloud_res->data.ci_server), str_val);
      changed = true;
    }
  }

  {
    int int_val = 0;
    if (oc_rep_get_int(request->request_payload, OC_RSRVD_ES_ACCESSTOKEN_TYPE,
                       &int_val)) {
      cloud_res->data.access_token_type = int_val;
      changed = true;
    }
  }

  // Invoke callback for user defined attributes
  memcpy(&cloud_cb_data, &cloud_res->data, sizeof(es_coap_cloud_conf_data));
  cloud_cb_data.userdata = NULL;
  if (g_enrollee->read_cb) {
    g_enrollee->read_cb(request->request_payload,
                        OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF,
                        &cloud_cb_data.userdata);
  }

  // TODO: what about user data change?
  if (changed) {
    if (cloud_res->cloud_prov_cb) {
      cloud_res->cloud_prov_cb(&cloud_cb_data);
    }

    // Notify observers about data change
    oc_notify_observers(cloud_res->base.handle);
  }

  if (g_enrollee->free_userdata) {
    g_enrollee->free_userdata(cloud_cb_data.userdata,
                              OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
  }
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
update_easysetup_resource(oc_request_t *request)
{
  int *connect_req;
  size_t connect_req_size;
  es_easy_setup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);

  if (oc_rep_get_int_array(request->request_payload, OC_RSRVD_ES_CONNECT,
                           &connect_req, &connect_req_size)) {
    memset(es_res->data.connect_request, 0,
           sizeof(es_res->data.connect_request));
    es_res->data.num_request = 0;
    for (int i = 0; i < NUM_CONNECT_TYPE && i < connect_req_size; ++i) {
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
construct_response_of_coapcloudconf(void)
{
  es_cloud_conf_resource_t *cloud_res =
    cloud_res_cast(g_enrollee->res[ES_RES_TYPE_CLOUD_CONF]);

  oc_rep_start_root_object();
  oc_process_baseline_interface(cloud_res->base.handle);

  es_rep_set_text_string(root, ac, oc_string(cloud_res->data.auth_code));
  es_rep_set_text_string(root, at, oc_string(cloud_res->data.access_token));
  es_rep_set_int(root, att, cloud_res->data.access_token_type);
  es_rep_set_text_string(root, apn, oc_string(cloud_res->data.auth_provider));
  es_rep_set_text_string(root, cis, oc_string(cloud_res->data.ci_server));

  // Invoke callback for user defined attributes
  if (g_enrollee->write_cb) {
    g_enrollee->write_cb(NULL, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
  }

  oc_rep_end_root_object();
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
    oc_rep_add_int(swmt, (int)wifi_res->data.supported_mode[i]);
  }

  oc_rep_close_array(root, swmt);
  es_rep_set_int(root, swf, (int)wifi_res->data.supported_freq);
  es_rep_set_text_string(root, tnn, oc_string(wifi_res->data.ssid));
  es_rep_set_text_string(root, cd, oc_string(wifi_res->data.cred));
  es_rep_set_int(root, wat, (int)wifi_res->data.auth_type);
  es_rep_set_int(root, wet, (int)wifi_res->data.enc_type);

  // Invoke callback for user defined attributes
  if (g_enrollee->write_cb) {
    g_enrollee->write_cb(NULL, OC_RSRVD_ES_RES_TYPE_WIFICONF);
  }
  oc_rep_end_root_object();
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

es_result_e
set_callback_for_userdata(es_read_userdata_cb readcb,
                          es_write_userdata_cb writecb,
                          es_free_userdata free_userdata)
{
  if (!g_enrollee) {
    OC_ERR("Enrollee is not initialized!");
    return ES_ERROR;
  }

  if (!readcb && !writecb) {
    OC_ERR("Invalid user attributes read/write callback!");
    return ES_ERROR;
  }

  g_enrollee->read_cb = readcb;
  g_enrollee->write_cb = writecb;
  g_enrollee->free_userdata = free_userdata;
  return ES_OK;
}

static void
get_devconf(oc_request_t *request, oc_interface_mask_t interface,
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
post_devconf(oc_request_t *request, oc_interface_mask_t interface,
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
get_cloud(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  construct_response_of_coapcloudconf();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_cloud(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_coap_cloud_conf_resource(request);
  construct_response_of_coapcloudconf();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
get_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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
post_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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
get_easysetup(oc_request_t *request, oc_interface_mask_t interface,
              void *user_data)
{
  (void)request;
  (void)interface;
  (void)user_data;
  OC_DBG("GET request received");

  es_easy_setup_resource_t *es_res =
              es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);

  oc_rep_start_root_object();
  es_rep_set_int(root, ps, es_res->data.status);
  es_rep_set_int(root, lec, es_res->data.last_err_code);
  oc_rep_end_root_object();
}

static void
post_easysetup(oc_request_t *request, oc_interface_mask_t interface,
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
deinit_easysetup_resource(void)
{
  es_easy_setup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);
  es_res->connect_request_cb = NULL;
  if (es_res->base.handle) {
    oc_delete_collection(es_res->base.handle);
    es_res->base.handle = NULL;
  }
  oc_mem_free(es_res);
}

static void
deinit_wifi_conf_resource(void)
{
  es_wifi_conf_resource_t *wifi_res =
    wifi_res_cast(g_enrollee->res[ES_RES_TYPE_WIFI_CONF]);
  wifi_res->wifi_prov_cb = NULL;
  if (wifi_res->base.handle) {
    oc_delete_resource(wifi_res->base.handle);
    wifi_res->base.handle = NULL;
  }
  es_free_string(wifi_res->data.ssid);
  es_free_string(wifi_res->data.cred);
  oc_mem_free(wifi_res);
}

static void
deinit_devconf_resource(void)
{
  es_dev_conf_resource_t *dev_res =
    dev_res_cast(g_enrollee->res[ES_RES_TYPE_DEV_CONF]);
  dev_res->dev_prov_cb = NULL;
  if (dev_res->base.handle) {
    oc_delete_resource(dev_res->base.handle);
    dev_res->base.handle = NULL;
  }
  es_free_string(dev_res->data.dev_name);
  oc_mem_free(dev_res);
}

static void
deinit_coap_cloudconf_resource(void)
{
  es_cloud_conf_resource_t *cloud_res =
    cloud_res_cast(g_enrollee->res[ES_RES_TYPE_CLOUD_CONF]);
  cloud_res->cloud_prov_cb = NULL;
  if (cloud_res->base.handle) {
    oc_delete_resource(cloud_res->base.handle);
    cloud_res->base.handle = NULL;
  }
  es_free_string(cloud_res->data.auth_code);
  es_free_string(cloud_res->data.auth_provider);
  es_free_string(cloud_res->data.access_token);
  es_free_string(cloud_res->data.ci_server);
  oc_mem_free(cloud_res);
}

static es_result_e
init_easysetup_resource(bool is_secured, es_connect_request_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  g_enrollee = oc_mem_calloc(1, sizeof(es_enrollee_t));
  MEM_ALLOC_CHECK(g_enrollee);

  es_easy_setup_resource_t *es_res =
    oc_mem_calloc(1, sizeof(es_easy_setup_resource_t));
  MEM_ALLOC_CHECK(es_res);

  es_res->data.status = ES_STATE_INIT;
  es_res->data.last_err_code = ES_ERRCODE_NO_ERROR;

  for (int i = 0; i < NUM_CONNECT_TYPE; ++i) {
    es_res->data.connect_request[i] = ES_CONNECT_NONE;
  }

  es_res->data.num_request = 0;
  es_res->connect_request_cb = cb;

  oc_resource_t *col =
    oc_new_collection("easysetup", OC_RSRVD_ES_URI_EASYSETUP, 2, 0);
  NULL_CHECK(col, "Failed to create!");

  oc_resource_bind_resource_type(col, OC_RSRVD_ES_RES_TYPE_EASYSETUP);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_bind_resource_interface(col, OC_IF_LL);
  oc_resource_bind_resource_interface(col, OC_IF_B);
  oc_resource_set_discoverable(col, true);
  oc_resource_set_observable(col, true);
  oc_resource_set_request_handler(col, OC_GET, get_easysetup, NULL);
  oc_resource_set_request_handler(col, OC_POST, post_easysetup, NULL);

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
  g_enrollee->res[ES_RES_TYPE_EASY_SETUP] = (es_resource_t *)es_res;
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

  es_easy_setup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);
  es_wifi_conf_resource_t *wifi_res =
    oc_mem_calloc(1, sizeof(es_wifi_conf_resource_t));
  MEM_ALLOC_CHECK(wifi_res);

  wifi_res->data.supported_freq = WIFI_BOTH;
  wifi_res->data.supported_mode[0] = WIFI_11A;
  wifi_res->data.supported_mode[1] = WIFI_11B;
  wifi_res->data.supported_mode[2] = WIFI_11G;
  wifi_res->data.supported_mode[3] = WIFI_11N;
  wifi_res->data.num_mode = 4;
  wifi_res->data.auth_type = NONE_AUTH;
  wifi_res->data.enc_type = NONE_ENC;
  wifi_res->wifi_prov_cb = cb;

  oc_resource_t *res = oc_new_resource("wifi", OC_RSRVD_ES_URI_WIFICONF, 1, 0);
  RESOURCE_CHECK(res);

  oc_resource_bind_resource_type(res, OC_RSRVD_ES_RES_TYPE_WIFICONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);

#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(res);
  }
#endif

  oc_resource_set_request_handler(res, OC_GET, get_wifi, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_wifi, NULL);
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
init_coap_cloudconf_resource(bool is_secured, es_coap_cloud_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  INPUT_PARAM_NULL_CHECK(cb);

  es_easy_setup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);
  es_cloud_conf_resource_t *cloud_res =
    oc_mem_calloc(1, sizeof(es_cloud_conf_resource_t));
  MEM_ALLOC_CHECK(cloud_res);

  cloud_res->data.access_token_type = NONE_OAUTH_TOKENTYPE;
  cloud_res->cloud_prov_cb = cb;

  oc_resource_t *res =
    oc_new_resource("cloud", OC_RSRVD_ES_URI_COAPCLOUDCONF, 1, 0);
  RESOURCE_CHECK(res);

  oc_resource_bind_resource_type(res, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(res);
  }
#endif
  oc_resource_set_request_handler(res, OC_GET, get_cloud, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_cloud, NULL);
  oc_add_resource(res);
  cloud_res->base.handle = res;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(res);
  RESOURCE_LINK_CHECK(link);

  oc_collection_add_link(es_res->base.handle, link);
  g_enrollee->res[ES_RES_TYPE_CLOUD_CONF] = (es_resource_t *)cloud_res;
  return ES_OK;

exit:
  return ES_ERROR;
}

static es_result_e
init_devconf_resource(bool is_secured, es_dev_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  INPUT_PARAM_NULL_CHECK(cb);

  es_easy_setup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);
  es_dev_conf_resource_t *dev_res =
    oc_mem_calloc(1, sizeof(es_dev_conf_resource_t));
  MEM_ALLOC_CHECK(dev_res);

  dev_res->dev_prov_cb = cb;

  oc_resource_t *res =
    oc_new_resource("devconf", OC_RSRVD_ES_URI_DEVCONF, 1, 0);
  RESOURCE_CHECK(res);

  oc_resource_bind_resource_type(res, OC_RSRVD_ES_RES_TYPE_DEVCONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(res);
  }
#endif
  oc_resource_set_request_handler(res, OC_GET, get_devconf, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_devconf, NULL);
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

es_result_e
create_easysetup_resources(bool is_secured, es_resource_mask_e resource_mask,
                           es_provisioning_callbacks_s callbacks)
{
  es_result_e res = ES_ERROR;

  if (resource_mask == 0 ||
      resource_mask > (ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE |
                       ES_DEVCONF_RESOURCE)) {
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
    res = init_wifi_conf_resource(is_secured, callbacks.wifi_prov_cb);
    if (res != ES_OK) {
      goto exit;
    }
  }

  // Create cloudconf resource
  if ((resource_mask & ES_COAPCLOUDCONF_RESOURCE) ==
      ES_COAPCLOUDCONF_RESOURCE) {
    res =
      init_coap_cloudconf_resource(is_secured, callbacks.cloud_data_prov_cb);
    if (res != ES_OK) {
      goto exit;
    }
  }

  // Create devconf resource
  if ((resource_mask & ES_DEVCONF_RESOURCE) == ES_DEVCONF_RESOURCE) {
    res = init_devconf_resource(is_secured, callbacks.dev_conf_prov_cb);
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
delete_easysetup_resources(void)
{
  if (g_enrollee) {
    deinit_wifi_conf_resource();
    deinit_coap_cloudconf_resource();
    deinit_devconf_resource();
    deinit_easysetup_resource();
    oc_mem_free(g_enrollee);
    g_enrollee = NULL;
  }
}

es_result_e
set_device_property(es_device_property *device_property)
{
  if (!g_enrollee) {
    OC_ERR("Enrollee is not initialized!");
    return ES_ERROR;
  }

  es_wifi_conf_resource_t *wifi_res =
    wifi_res_cast(g_enrollee->res[ES_RES_TYPE_WIFI_CONF]);
  wifi_res->data.supported_freq = (device_property->WiFi).supported_freq;

  int modeIdx = 0;
  while ((device_property->WiFi).supported_mode[modeIdx] != WiFi_EOF) {
    wifi_res->data.supported_mode[modeIdx] =
      (device_property->WiFi).supported_mode[modeIdx];
    modeIdx++;
  }

  wifi_res->data.num_mode = modeIdx;

  es_dev_conf_resource_t *dev_res =
    dev_res_cast(g_enrollee->res[ES_RES_TYPE_DEV_CONF]);
  es_new_string(&(dev_res->data.dev_name),
                oc_string((device_property->DevConf).device_name));

  oc_notify_observers(wifi_res->base.handle);
  oc_notify_observers(dev_res->base.handle);
  return ES_OK;
}

es_result_e
set_enrollee_state(es_enrollee_state es_state)
{
  if (!g_enrollee) {
    OC_ERR("Enrollee is not initialized!");
    return ES_ERROR;
  }

  if (es_state < ES_STATE_INIT || es_state >= ES_STATE_EOF) {
    OC_ERR("Invalid es_set_state to set: %d", es_state);
    return ES_ERROR;
  }

  es_easy_setup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);
  es_res->data.status = es_state;
  oc_notify_observers(es_res->base.handle);
  return ES_OK;
}

es_result_e
set_enrollee_err_code(es_error_code es_err_code)
{
  if (!g_enrollee) {
    OC_ERR("Enrollee is not initialized!");
    return ES_ERROR;
  }

  if (es_err_code < ES_ERRCODE_NO_ERROR || es_err_code > ES_ERRCODE_UNKNOWN) {
    OC_ERR("Invalid lec to set: %d", es_err_code);
    return ES_ERROR;
  }

  if (!g_enrollee)
    return ES_OK;

  es_easy_setup_resource_t *es_res =
    es_res_cast(g_enrollee->res[ES_RES_TYPE_EASY_SETUP]);
  es_res->data.last_err_code = es_err_code;
  oc_notify_observers(es_res->base.handle);
  return ES_OK;
}
