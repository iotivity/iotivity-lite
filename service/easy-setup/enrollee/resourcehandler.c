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
#include "util/oc_mem.h"
#include "oc_log.h"

typedef void (*es_connect_request_cb)(es_connect_request *);
typedef void (*es_wifi_conf_cb)(es_wifi_conf_data *);
typedef void (*es_coap_cloud_conf_cb)(es_coap_cloud_conf_data *);
typedef void (*es_dev_conf_cb)(es_dev_conf_data *);

typedef struct
{
  oc_resource_t *handle;
  prov_status status;
  es_error_code last_err_code;
  es_connect_type connect_request[NUM_CONNECT_TYPE];
  int num_request;
  es_connect_request_cb connect_request_cb;
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
  es_wifi_conf_cb wifi_prov_cb;
} wifi_conf_resource;

typedef struct
{
  oc_resource_t *handle;
  oc_string_t auth_code;
  oc_string_t access_token;
  oauth_tokentype access_token_type;
  oc_string_t auth_provider;
  oc_string_t ci_server;
  es_coap_cloud_conf_cb cloud_prov_cb;
} coap_cloud_conf_resource;

typedef struct
{
  oc_resource_t *handle;
  oc_string_t dev_name;
  es_dev_conf_cb dev_prov_cb;
} dev_conf_resource;

easy_setup_resource *g_easysetup_resource;
wifi_conf_resource *g_wificonf_resource;
coap_cloud_conf_resource *g_cloudconf_resource;
dev_conf_resource *g_devconf_resource;

es_read_userdata_cb g_read_user_data_cb = NULL;
es_write_userdata_cb g_write_user_data_cb = NULL;

bool
es_compare_property(oc_rep_t *rep, char *property_name)
{
  int prop_len = strlen(property_name);
  if ((int)oc_string_len(rep->name) == prop_len &&
      memcmp(oc_string(rep->name), property_name, prop_len) == 0) {
    return true;
  }
  return false;
}

static void
update_wifi_conf_resource(oc_request_t *request, oc_interface_mask_t interface)
{
  OC_DBG("in");

  (void)interface;
  es_wifi_conf_data wifi_data={
    .authtype = NONE_AUTH,
    .enctype = NONE_AUTH,
    .userdata = NULL,
    .ssid.ptr="",
    .pwd.ptr=""
  };

  bool is_valid = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_DBG("key %s", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_STRING: {
      if (es_compare_property(rep, OC_RSRVD_ES_SSID)) {
        if (oc_string_len(rep->value.string) > 0) {
          oc_allocate_string(&g_wificonf_resource->ssid, oc_string(rep->value.string));
          oc_allocate_string(&wifi_data.ssid, oc_string(rep->value.string));
          OC_DBG("g_wificonf_resource->ssid : %s", oc_string(g_wificonf_resource->ssid));
          is_valid = true;
        }
      } else if (es_compare_property(rep, OC_RSRVD_ES_CRED)) {
        if (oc_string_len(rep->value.string) > 0) {
          oc_allocate_string(&g_wificonf_resource->cred, oc_string(rep->value.string));
          oc_allocate_string(&wifi_data.pwd, oc_string(rep->value.string));
          OC_DBG("g_wificonf_resource->cred : %s", oc_string( g_wificonf_resource->cred));
          is_valid = true;
        }
      }
    } break;
    case OC_REP_INT: {
      if (es_compare_property(rep, OC_RSRVD_ES_AUTHTYPE)) {
        g_wificonf_resource->auth_type = rep->value.integer;
        wifi_data.authtype = g_wificonf_resource->auth_type;
        OC_DBG("g_wificonf_resource->auth_type %u",
               g_wificonf_resource->auth_type);
        is_valid = true;
      } else if (es_compare_property(rep, OC_RSRVD_ES_ENCTYPE)) {
        g_wificonf_resource->enc_type = rep->value.integer;
        wifi_data.enctype = g_wificonf_resource->enc_type;
        OC_DBG("g_wificonf_resource->enc_type %u", g_wificonf_resource->enc_type);
        is_valid = true;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (g_read_user_data_cb) {
    g_read_user_data_cb(request->request_payload, OC_RSRVD_ES_RES_TYPE_WIFICONF,
                        &wifi_data.userdata);
  }

  if (is_valid) {
    OC_DBG("Send WiFiConfRsrc Callback To ES");

    if (g_wificonf_resource->wifi_prov_cb != NULL) {
      g_wificonf_resource->wifi_prov_cb(&wifi_data);
    } else {
      OC_ERR("g_wificonf_res_event_cb is NULL");
    }
  } else {
    OC_ERR("wifi conf received payload is invalid");
  }

  if (0 == oc_notify_observers(g_wificonf_resource->handle)) {
    OC_DBG("Enrollee doesn't have any observers for wifi RESOURCE.");
  }

  es_free_property(wifi_data.ssid);
  es_free_property(wifi_data.pwd);
  if(wifi_data.userdata != NULL){
    free(wifi_data.userdata);
  }

  OC_DBG("out");
}

static void
update_coap_cloud_conf_resource(oc_request_t *request,
                                oc_interface_mask_t interface)
{
  OC_DBG("in");

  (void)interface;
  es_coap_cloud_conf_data cloud_data={
    .auth_code.ptr="",
    .access_token.ptr="",
    .access_token_type=NONE_OAUTH_TOKENTYPE,
    .auth_provider.ptr="",
    .ci_server.ptr="",
    .userdata = NULL
  };

  bool is_valid = false;

  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_DBG("key %s", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_STRING: {
      if (es_compare_property(rep, OC_RSRVD_ES_AUTHCODE)) {
        if (oc_string_len(rep->value.string) > 0) {
          oc_allocate_string(&g_cloudconf_resource->auth_code, oc_string(rep->value.string));
          oc_allocate_string(&cloud_data.auth_code, oc_string(rep->value.string));
          OC_DBG("g_cloudconf_resource->auth_code : %s",
                 g_cloudconf_resource->auth_code);
          is_valid = true;
        }
      } else if (es_compare_property(rep, OC_RSRVD_ES_ACCESSTOKEN)) {
        if (oc_string_len(rep->value.string) > 0) {
          oc_allocate_string(&g_cloudconf_resource->access_token, oc_string(rep->value.string));
          oc_allocate_string(&cloud_data.access_token, oc_string(rep->value.string));
          OC_DBG("g_cloudconf_resource->access_token : %s",
                 g_cloudconf_resource->access_token);
          is_valid = true;
        }
      } else if (es_compare_property(rep, OC_RSRVD_ES_AUTHPROVIDER)) {
        if (oc_string_len(rep->value.string) > 0) {
          oc_allocate_string(&g_cloudconf_resource->auth_provider, oc_string(rep->value.string));
          oc_allocate_string(&cloud_data.auth_provider, oc_string(rep->value.string));
          OC_DBG("g_cloudconf_resource->auth_provider : %s",
                 g_cloudconf_resource->auth_provider);
          is_valid = true;
        }
      } else if (es_compare_property(rep, OC_RSRVD_ES_CISERVER)) {
        if (oc_string_len(rep->value.string) > 0) {
          oc_allocate_string(&g_cloudconf_resource->ci_server, oc_string(rep->value.string));
          oc_allocate_string(&cloud_data.ci_server, oc_string(rep->value.string));
          OC_DBG("g_cloudconf_resource->ci_server : %s",
                 g_cloudconf_resource->ci_server);
          is_valid = true;
        }
      }
    } break;
    case OC_REP_INT: {
      if (es_compare_property(rep, OC_RSRVD_ES_ACCESSTOKEN_TYPE)) {
        g_cloudconf_resource->access_token_type = rep->value.integer;
        cloud_data.access_token_type = g_cloudconf_resource->access_token_type;
        OC_DBG("g_cloudconf_resource->access_token_type %u",
               g_cloudconf_resource->access_token_type);
        is_valid = true;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (g_read_user_data_cb) {
    g_read_user_data_cb(request->request_payload, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF,
                        &cloud_data.userdata);
  }

  if (is_valid) {
    OC_DBG("Send CoapCloudConfRsrc Callback To ES");
    if (g_cloudconf_resource->cloud_prov_cb) {
      g_cloudconf_resource->cloud_prov_cb(&cloud_data);
    } else {
      OC_ERR("g_cloud_conf_res_event_cb is NULL");
    }
  }

  if (0 == oc_notify_observers(g_cloudconf_resource->handle)) {
    OC_DBG("Enrollee doesn't have any observers for cloud conf RESOURCE.");
  }

  es_free_property(cloud_data.auth_code);
  es_free_property(cloud_data.access_token);
  es_free_property(cloud_data.auth_provider);
  es_free_property(cloud_data.ci_server);
  if(cloud_data.userdata != NULL){
   free(cloud_data.userdata);
  }

  OC_DBG("out");
}

static void
update_devconf_resource(oc_request_t *request, oc_interface_mask_t interface)
{
  OC_DBG("in");

  (void)interface;
  es_dev_conf_data dev_conf_data;
  dev_conf_data.userdata = NULL;

  if (g_read_user_data_cb) {
    g_read_user_data_cb(request->request_payload, OC_RSRVD_ES_RES_TYPE_DEVCONF,
                        &dev_conf_data.userdata);
  }

  if (dev_conf_data.userdata != NULL) {
    OC_DBG("Send DevConfRsrc Callback To ES");

    if (g_devconf_resource->dev_prov_cb) {
      g_devconf_resource->dev_prov_cb(&dev_conf_data);
    } else {
      OC_ERR("g_dev_conf_res_event_cb is NULL");
    }
  }

  if (0 == oc_notify_observers(g_devconf_resource->handle)) {
    OC_DBG("Enrollee doesn't have any observers for dev conf RESOURCE.");
  }

  if(dev_conf_data.userdata != NULL){
    free(dev_conf_data.userdata);
  }

  OC_DBG("out");
}

static void
update_easysetup_resource(oc_request_t *request, oc_interface_mask_t interface)
{
  OC_DBG("in");
  OC_DBG("g_easysetup_resource.status %d", g_easysetup_resource->status);

  (void)interface;

  oc_rep_t *rep = request->request_payload;

  while (rep != NULL) {
    OC_DBG("key %s", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT_ARRAY: {
      if (es_compare_property(rep, OC_RSRVD_ES_CONNECT)) {
        int i = 0;
        int connect_req_size = (int)oc_int_array_size(rep->value.array);
        int *connect_req = oc_int_array(rep->value.array);
        es_connect_request connect_request;
        for (i = 0; i < (int)oc_int_array_size(rep->value.array); i++) {
          OC_DBG("(%d %d) ", i, connect_req[i]);
        }

        memset(&connect_request, 0, sizeof(es_connect_request));
        int cnt_request = 0;
        for (int i = 0; i < NUM_CONNECT_TYPE; ++i) {
          g_easysetup_resource->connect_request[i] = ES_CONNECT_NONE;
          connect_request.connect[i] = ES_CONNECT_NONE;

          if (i < connect_req_size &&
              (connect_req[i] == ES_CONNECT_WIFI ||
               connect_req[i] == ES_CONNECT_COAPCLOUD)) {
            g_easysetup_resource->connect_request[cnt_request] = connect_req[i];
            connect_request.connect[cnt_request] = connect_req[i];
            OC_DBG("g_easysetup_resource.connectType[%d] : %d", cnt_request,
                   g_easysetup_resource->connect_request[cnt_request]);
            cnt_request++;
          }
        }

        connect_request.num_request = cnt_request;
        g_easysetup_resource->num_request = cnt_request;

        if (g_easysetup_resource->connect_request[0] != ES_CONNECT_NONE) {
          OC_DBG("Send ConnectRequest Callback To ES");

          if (g_easysetup_resource->connect_request_cb) {
            g_easysetup_resource->connect_request_cb(&connect_request);
          } else {
            OC_ERR("g_connect_req_event_cb is NULL");
          }
        }
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  OC_DBG("out");
}

static es_result_e
construct_response_of_coapcloudconf(void)
{
  OC_DBG("in");

  if (g_cloudconf_resource->handle == NULL) {
    OC_ERR("WiFiConf resource is not created");
    return ES_ERROR;
  }

  oc_rep_start_root_object();

  /// TODO: Call this only when interface is baseline
  oc_process_baseline_interface(g_cloudconf_resource->handle);

  set_custom_property_str(root, ac, oc_string(g_cloudconf_resource->auth_code));
  set_custom_property_str(root, at, oc_string(g_cloudconf_resource->access_token));
  set_custom_property_int(root, att, g_cloudconf_resource->access_token_type);
  set_custom_property_str(root, apn, oc_string(g_cloudconf_resource->auth_provider));
  set_custom_property_str(root, cis, oc_string(g_cloudconf_resource->ci_server));

  if (g_write_user_data_cb) {
    g_write_user_data_cb(NULL, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
  }

  oc_rep_end_root_object();
  OC_DBG("out");
  return ES_OK;
}

static es_result_e
construct_response_of_wificonf(void)
{
  OC_DBG("in");

  if (g_wificonf_resource->handle == NULL) {
    OC_ERR("WiFiConf resource is not created");
    return ES_ERROR;
  }

  oc_rep_start_root_object();
  oc_process_baseline_interface(g_wificonf_resource->handle);

  oc_rep_set_array(root, swmt);
  for (int i = 0; i < g_wificonf_resource->num_mode; i++) {
    oc_rep_add_int(swmt, (int)g_wificonf_resource->supported_mode[i]);
  }

  oc_rep_close_array(root, swmt);
  set_custom_property_int(root, swf, (int)g_wificonf_resource->supported_freq);
  set_custom_property_str(root, tnn, oc_string(g_wificonf_resource->ssid));
  set_custom_property_str(root, cd, oc_string(g_wificonf_resource->cred));
  set_custom_property_int(root, wat, (int)g_wificonf_resource->auth_type);
  set_custom_property_int(root, wet, (int)g_wificonf_resource->enc_type);

  if (g_write_user_data_cb) {
    g_write_user_data_cb(NULL, OC_RSRVD_ES_RES_TYPE_WIFICONF);
  }
  oc_rep_end_root_object();

  OC_DBG("out");
  return ES_OK;
}

static es_result_e
construct_response_of_devconf(void)
{
  OC_DBG("construct_response_of_devconf in");

  if (g_devconf_resource->handle == NULL) {
    OC_ERR("DevConf resource is not created");
    return ES_ERROR;
  }

  oc_rep_start_root_object();
  oc_process_baseline_interface(g_devconf_resource->handle);
  set_custom_property_str(root, dn, oc_string(g_devconf_resource->dev_name));

  if (g_write_user_data_cb) {
    g_write_user_data_cb(NULL, OC_RSRVD_ES_RES_TYPE_DEVCONF);
  }

  oc_rep_end_root_object();
  OC_DBG("out");
  return ES_OK;
}

es_result_e
set_callback_for_userdata(es_read_userdata_cb readcb,
                          es_write_userdata_cb writecb)
{
  OC_DBG("in");
  if (!readcb && !writecb) {
    OC_ERR("Both of callbacks for user data are Null");
    return ES_ERROR;
  }

  g_read_user_data_cb = readcb;
  g_write_user_data_cb = writecb;
  OC_DBG("out");
  return ES_OK;
}

static void
get_devconf(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  if (interface == OC_IF_BASELINE) {
    construct_response_of_devconf();
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_DBG("out");
}

static void
post_devconf(oc_request_t *request, oc_interface_mask_t interface,
             void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  if (interface == OC_IF_BASELINE) {
    update_devconf_resource(request, interface);
    construct_response_of_devconf();
    OC_DBG("success");
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_DBG("out");
}

static void
get_cloud(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  if (interface == OC_IF_BASELINE) {
    construct_response_of_coapcloudconf();
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_DBG("out");
}

static void
post_cloud(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  if (interface == OC_IF_BASELINE) {
    update_coap_cloud_conf_resource(request, interface);
    construct_response_of_coapcloudconf();
    OC_DBG("success");
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_DBG("out");
}

static void
get_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  if (interface == OC_IF_BASELINE) {
    construct_response_of_wificonf();
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_DBG("out");
}

static void
post_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  if (interface == OC_IF_BASELINE) {
    update_wifi_conf_resource(request, interface);
    construct_response_of_wificonf();
    OC_DBG("success");
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_DBG("out");
}

static void
get_easysetup(oc_request_t *request, oc_interface_mask_t interface,
              void *user_data)
{
  (void)request;
  (void)interface;
  (void)user_data;

  OC_DBG("in");

  oc_rep_start_root_object();
  set_custom_property_int(root, ps, 0);
  set_custom_property_int(root, lec, 0);
  oc_rep_end_root_object();

  OC_DBG("out");
}

static void
post_easysetup(oc_request_t *request, oc_interface_mask_t interface,
               void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  OC_DBG("interface = %d", interface);

  if ((interface == OC_IF_B) || (interface == OC_IF_BASELINE)) {
    update_easysetup_resource(request, interface);
    OC_DBG("success");
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_DBG("out");
}

static void
deinit_easysetup_resource(void)
{
  g_easysetup_resource->connect_request_cb = NULL;
  if (g_easysetup_resource->handle) {
    oc_delete_collection(g_easysetup_resource->handle);
    g_easysetup_resource->handle = NULL;
  }
  oc_mem_free(g_easysetup_resource);
  g_easysetup_resource = NULL;
}

static void
deinit_wifi_conf_resource(void)
{
  g_wificonf_resource->wifi_prov_cb = NULL;
  if (g_wificonf_resource->handle) {
    oc_delete_resource(g_wificonf_resource->handle);
    g_wificonf_resource->handle = NULL;
  }
  es_free_property(g_wificonf_resource->ssid);
  es_free_property(g_wificonf_resource->cred);
  oc_mem_free(g_wificonf_resource);
  g_wificonf_resource = NULL;
}

static void
deinit_devconf_resource(void)
{
  g_devconf_resource->dev_prov_cb = NULL;
  if (g_devconf_resource->handle) {
    oc_delete_resource(g_devconf_resource->handle);
    g_devconf_resource->handle = NULL;
  }
  es_free_property(g_devconf_resource->dev_name);
  oc_mem_free(g_devconf_resource);
  g_devconf_resource = NULL;
}

static void
deinit_coap_cloudconf_resource(void)
{
  g_cloudconf_resource->cloud_prov_cb = NULL;
  if (g_cloudconf_resource->handle) {
    oc_delete_resource(g_cloudconf_resource->handle);
    g_cloudconf_resource->handle = NULL;
  }
  es_free_property(g_cloudconf_resource->auth_code);
  es_free_property(g_cloudconf_resource->auth_provider);
  es_free_property(g_cloudconf_resource->access_token);
  es_free_property(g_cloudconf_resource->ci_server);
  oc_mem_free(g_cloudconf_resource);
  g_cloudconf_resource = NULL;
}

static es_result_e
init_easysetup_resource(bool is_secured, es_connect_request_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  g_easysetup_resource = oc_mem_calloc(1, sizeof(easy_setup_resource));
  if (!g_easysetup_resource) {
    OC_ERR("EasySetup resource memory allocation failed!");
    return ES_ERROR;
  }

  g_easysetup_resource->status = ES_STATE_INIT;
  g_easysetup_resource->last_err_code = ES_ERRCODE_NO_ERROR;

  for (int i = 0; i < NUM_CONNECT_TYPE; ++i) {
    g_easysetup_resource->connect_request[i] = ES_CONNECT_NONE;
  }

  g_easysetup_resource->num_request = 0;
  g_easysetup_resource->connect_request_cb = cb;

  oc_resource_t *col =
    oc_new_collection("easysetup", OC_RSRVD_ES_URI_EASYSETUP, 2, 0);
  if (NULL == col) {
    OC_ERR("Error in creating EasySetup Resource!");
    return ES_ERROR;
  }

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
  if (link == NULL) {
    OC_ERR("Failed to create link to EasySetup resource!");
    deinit_easysetup_resource();
    return ES_ERROR;
  }

  oc_collection_add_link(col, link);
  oc_add_collection(col);
  g_easysetup_resource->handle = col;
  return ES_OK;
}

static es_result_e
init_wifi_conf_resource(bool is_secured, es_wifi_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif
  if (cb == NULL) {
    OC_ERR("wificonf callback is NULL!");
    return ES_ERROR;
  }

  g_wificonf_resource = oc_mem_calloc(1, sizeof(wifi_conf_resource));
  if (!g_wificonf_resource) {
    OC_ERR("wificonf resource memory allocation failed!");
    return ES_ERROR;
  }

  g_wificonf_resource->supported_freq = WIFI_BOTH;
  g_wificonf_resource->supported_mode[0] = WIFI_11A;
  g_wificonf_resource->supported_mode[1] = WIFI_11B;
  g_wificonf_resource->supported_mode[2] = WIFI_11G;
  g_wificonf_resource->supported_mode[3] = WIFI_11N;
  g_wificonf_resource->num_mode = 4;
  g_wificonf_resource->auth_type = NONE_AUTH;
  g_wificonf_resource->enc_type = NONE_ENC;
  g_wificonf_resource->wifi_prov_cb = cb;

  oc_resource_t *wifi = oc_new_resource("wifi", OC_RSRVD_ES_URI_WIFICONF, 1, 0);
  if (NULL == wifi) {
    OC_ERR("Failed to create wificonf resource!");
    return ES_ERROR;
  }

  oc_resource_bind_resource_type(wifi, OC_RSRVD_ES_RES_TYPE_WIFICONF);
  oc_resource_set_discoverable(wifi, true);
  oc_resource_set_observable(wifi, true);

#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(wifi);
  }
#endif

  oc_resource_set_request_handler(wifi, OC_GET, get_wifi, NULL);
  oc_resource_set_request_handler(wifi, OC_POST, post_wifi, NULL);
  oc_add_resource(wifi);
  g_wificonf_resource->handle = wifi;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(g_wificonf_resource->handle);
  if (link == NULL) {
    OC_ERR("Failed to create link to wificonf resource!");
    deinit_wifi_conf_resource();
    return ES_ERROR;
  }

  oc_collection_add_link(g_easysetup_resource->handle, link);
  return ES_OK;
}

static es_result_e
init_coap_cloudconf_resource(bool is_secured, es_coap_cloud_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif

  if (cb == NULL) {
    OC_ERR("cloudconf callback is NULL!");
    return ES_ERROR;
  }

  g_cloudconf_resource = oc_mem_calloc(1, sizeof(coap_cloud_conf_resource));
  if (!g_cloudconf_resource) {
    OC_ERR("cloudconf resource memory allocation failed!");
    return ES_ERROR;
  }

  g_cloudconf_resource->access_token_type = NONE_OAUTH_TOKENTYPE;
  g_cloudconf_resource->cloud_prov_cb = cb;

  oc_resource_t *cloud =
    oc_new_resource("cloud", OC_RSRVD_ES_URI_COAPCLOUDCONF, 1, 0);
  if (NULL == cloud) {
    OC_ERR("Failed to create cloudconf resource!");
    return ES_ERROR;
  }

  oc_resource_bind_resource_type(cloud, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
  oc_resource_set_discoverable(cloud, true);
  oc_resource_set_observable(cloud, true);
#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(cloud);
  }
#endif
  oc_resource_set_request_handler(cloud, OC_GET, get_cloud, NULL);
  oc_resource_set_request_handler(cloud, OC_POST, post_cloud, NULL);
  oc_add_resource(cloud);
  g_cloudconf_resource->handle = cloud;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(g_cloudconf_resource->handle);
  if (link == NULL) {
    OC_ERR("Failed to create link to cloudconf resource!");
    deinit_coap_cloudconf_resource();
    return ES_ERROR;
  }

  oc_collection_add_link(g_easysetup_resource->handle, link);
  return ES_OK;
}

static es_result_e
init_devconf_resource(bool is_secured, es_dev_conf_cb cb)
{
#ifndef OC_SECURITY
  (void)is_secured;
#endif

  if (cb == NULL) {
    OC_ERR("devconf callback is NULL!");
    return ES_ERROR;
  }

  g_devconf_resource = oc_mem_calloc(1, sizeof(dev_conf_resource));
  if (!g_devconf_resource) {
    OC_ERR("devconf resource memory allocation failed!");
    return ES_ERROR;
  }

  g_devconf_resource->dev_prov_cb = cb;

  oc_resource_t *devconf =
    oc_new_resource("devconf", OC_RSRVD_ES_URI_DEVCONF, 1, 0);
  if (NULL == devconf) {
    OC_ERR("Failed to create devconf resource!");
    return ES_ERROR;
  }

  oc_resource_bind_resource_type(devconf, OC_RSRVD_ES_RES_TYPE_DEVCONF);
  oc_resource_set_discoverable(devconf, true);
  oc_resource_set_observable(devconf, true);
#ifdef OC_SECURITY
  if (!is_secured) {
    oc_resource_make_public(devconf);
  }
#endif
  oc_resource_set_request_handler(devconf, OC_GET, get_devconf, NULL);
  oc_resource_set_request_handler(devconf, OC_POST, post_devconf, NULL);
  oc_add_resource(devconf);
  g_devconf_resource->handle = devconf;

  // Add to easysetup collection resource
  oc_link_t *link = oc_new_link(g_devconf_resource->handle);
  if (link == NULL) {
    OC_ERR("Failed to create link to devconf resource!");
    deinit_devconf_resource();
    return ES_ERROR;
  }

  oc_collection_add_link(g_easysetup_resource->handle, link);
  return ES_OK;
}

es_result_e
create_easysetup_resources(bool is_secured, es_resource_mask_e resource_mask,
                           es_provisioning_callbacks_s callbacks)
{
  es_result_e res = ES_ERROR;

  if (resource_mask == 0 ||
      resource_mask > (ES_WIFICONF_RESOURCE|ES_COAPCLOUDCONF_RESOURCE|ES_DEVCONF_RESOURCE)) {
    OC_ERR("Invalid resource mask supplied for enrollee initialization!");
    return res;
  }

  // Create easysetup collection resource
  res = init_easysetup_resource(is_secured, callbacks.connect_request_cb);
  if (res != ES_OK) {
    OC_ERR("Failed to initialize easysetup resource!");
    delete_easysetup_resources();
    return res;
  }

  // Create wificonf resource
  if ((resource_mask & ES_WIFICONF_RESOURCE) == ES_WIFICONF_RESOURCE) {
    res = init_wifi_conf_resource(is_secured, callbacks.wifi_prov_cb);
    if (res != ES_OK) {
      OC_DBG("Failed to initialize wificonf resource!");
      delete_easysetup_resources();
      return res;
    }
  }

  // Create cloudconf resource
  if ((resource_mask & ES_COAPCLOUDCONF_RESOURCE) ==
      ES_COAPCLOUDCONF_RESOURCE) {
    res = init_coap_cloudconf_resource(is_secured, callbacks.cloud_data_prov_cb);
    if (res != ES_OK) {
      OC_ERR("Failed to initialize cloudconf resource!");
      delete_easysetup_resources();
      return res;
    }
  }

  // Create devconf resource
  if ((resource_mask & ES_DEVCONF_RESOURCE) == ES_DEVCONF_RESOURCE) {
    res = init_devconf_resource(is_secured, callbacks.dev_conf_prov_cb);
    if (res != ES_OK) {
      OC_ERR("Failed to initialize deviceconf resource!");
      delete_easysetup_resources();
      return res;
    }
  }

  return ES_OK;
}

void
delete_easysetup_resources(void)
{
  deinit_wifi_conf_resource();
  deinit_coap_cloudconf_resource();
  deinit_devconf_resource();
  deinit_easysetup_resource();
}

es_result_e
set_device_property(es_device_property *device_property)
{
  g_wificonf_resource->supported_freq = (device_property->WiFi).supported_freq;

  int modeIdx = 0;
  while ((device_property->WiFi).supported_mode[modeIdx] != WiFi_EOF) {
    g_wificonf_resource->supported_mode[modeIdx] =
      (device_property->WiFi).supported_mode[modeIdx];
    modeIdx++;
  }

  g_wificonf_resource->num_mode = modeIdx;
  oc_allocate_string(&(g_devconf_resource->dev_name),
                             oc_string((device_property->DevConf).device_name));

  oc_notify_observers(g_wificonf_resource->handle);
  oc_notify_observers(g_devconf_resource->handle);
  return ES_OK;
}

es_result_e
set_enrollee_state(es_enrollee_state es_state)
{
  if (es_state < ES_STATE_INIT || es_state >= ES_STATE_EOF) {
    OC_ERR("Invalid es_set_state to set: %d", es_state);
    return ES_ERROR;
  }

  g_easysetup_resource->status = es_state;
  oc_notify_observers(g_easysetup_resource->handle);
  return ES_OK;
}

es_result_e
set_enrollee_err_code(es_error_code es_err_code)
{
  if (es_err_code < ES_ERRCODE_NO_ERROR || es_err_code > ES_ERRCODE_UNKNOWN) {
    OC_ERR("Invalid lec to set: %d", es_err_code);
    return ES_ERROR;
  }

  g_easysetup_resource->last_err_code = es_err_code;
  oc_notify_observers(g_easysetup_resource->handle);
  return ES_OK;
}

void
notify_connection_change(void)
{
  oc_notify_observers(g_easysetup_resource->handle);
}
