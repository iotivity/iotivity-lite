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

#include "samsung/sc_easysetup.h"
#include "es_utils.h"
#include "inttypes.h"
#include "oc_helpers.h"
#include "oc_log.h"
#include "oc_rep.h"
#include "util/oc_mem.h"

#define SC_RSRVD_ES_URI_PROVISIONING_INFO "/sec/provisioninginfo"
#define SC_RSRVD_ES_RES_TYPE_PROVISIONING_INFO "x.com.samsung.provisioninginfo"
#define SC_RSRVD_ES_RES_NAME_PROVISIONING_INFO "x.network.provisioning.info"

#define SC_RSRVD_ES_URI_ACCESSPOINT_LIST "/sec/accesspointlist"
#define SC_RSRVD_ES_RES_TYPE_ACCESSPOINT_LIST "x.com.samsung.acesspointlist"
#define SC_RSRVD_ES_RES_NAME_ACCESSPOINT_LIST "x.network.wifi.ap"

#define SC_RSRVD_ES_ATTR_NAME_PREFIX "x.com.samsung"

#ifndef SC_ES_OPT
#define SC_RSRVD_ES_VENDOR_DEVICE_TYPE "dt"
#define SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE "sdt"
#define SC_RSRVD_ES_VENDOR_LOCATION "location"
#define SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV "rmd"
#define SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV "rsd"
#define SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO "npi"
#define SC_RSRVD_ES_VENDOR_ACCOUNT "account"
#define SC_RSRVD_ES_VENDOR_SSO_LIST "ssolist"
#define SC_RSRVD_ES_VENDOR_PNP_PIN "pnppin"
#define SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION "espv"
#define SC_RSRVD_ES_VENDOR_TNC_HEADER "tcheader"
#define SC_RSRVD_ES_VENDOR_TNC_VERSION "tcversion"
#define SC_RSRVD_ES_VENDOR_TNC_RESULT "tcresult"
#define SC_RSRVD_ES_VENDOR_TNC_STATUS "tcstatus"
#endif/* SC_ES_OPT */

#define SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE "ncs"
#define SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL "chn"
#define SC_RSRVD_ES_VENDOR_REFRESH_TOKEN "refreshtoken"
#define SC_RSRVD_ES_VENDOR_UID "uid"
#define SC_RSRVD_ES_VENDOR_BSSID "bssid"
#define SC_RSRVD_ES_VENDOR_CLIENTID "clientid"
#define SC_RSRVD_ES_VENDOR_MODEL_NUMBER "modelnumber"
#define SC_RSRVD_ES_VENDOR_LANGUAGE "language"
#define SC_RSRVD_ES_VENDOR_COUNTRY "country"
#define SC_RSRVD_ES_VENDOR_GPSLOCATION "gpslocation"
#define SC_RSRVD_ES_VENDOR_UTC_DATE_TIME "datetime"
#define SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME "regionaldatetime"
#define SC_RSRVD_ES_VENDOR_AAC "aac"


#define SC_RSRVD_ES_PROVISIONING_INFO_TARGETS "provisioning.targets"
#define SC_RSRVD_ES_PROVISIONING_INFO_OWNED "provisioning.owned"
#define SC_RSRVD_ES_PROVISIONING_INFO_EASY_SETUP_DI "provisioning.easysetupdi"
#define SC_RSRVD_ES_PROVISIONING_INFO_TARGETDI "targetDi"
#define SC_RSRVD_ES_PROVISIONING_INFO_TARGETRT "targetRt"
#define SC_RSRVD_ES_PROVISIONING_INFO_PUBLISHED "published"

#define SC_RSRVD_ES_ACCESSPOINT_LIST_AP_ITEMS "accesspoint.items"
#define SC_RSRVD_ES_ACCESSPOINT_LIST_CHANNEL "channel"
#define SC_RSRVD_ES_ACCESSPOINT_LIST_ENCRYPTION_TYPE "encryptionType"
#define SC_RSRVD_ES_ACCESSPOINT_LIST_MAC_ADDRESS "macAddress"
#define SC_RSRVD_ES_ACCESSPOINT_LIST_MAX_RATE "maxRate"
#define SC_RSRVD_ES_ACCESSPOINT_LIST_RSSI "rssi"
#define SC_RSRVD_ES_ACCESSPOINT_LIST_SECURITY_TYPE "securityType"
#define SC_RSRVD_ES_ACCESSPOINT_LIST_SSID "ssid"

#define SC_MAX_ES_ATTR_NAME_LEN 50

typedef struct
{
  oc_resource_t *res;
  sec_provisioning_info *info;
} sec_provisioning_res_t;

typedef struct
{
  oc_resource_t *res;
  get_ap_scan_list cb;
} sec_accesspoints_res_t;

sc_properties *g_scprop;
sec_provisioning_res_t *g_sec_prov;
sec_accesspoints_res_t *g_sec_aplist;

static void
construct_vnd_attr_name(char *vnd_attr, int vnd_attr_size, char *attr_name)
{
  snprintf(vnd_attr, vnd_attr_size, "%s.%s",
           SC_RSRVD_ES_ATTR_NAME_PREFIX, attr_name);
}

sc_properties *
get_sc_properties(void)
{
  return g_scprop;
}

es_result_e
set_sc_properties(sc_properties *prop)
{
  INPUT_PARAM_NULL_CHECK(prop);

  g_scprop = prop;
  return ES_OK;

exit:
  return ES_ERROR;
}

es_result_e
reset_sc_properties(void)
{
  g_scprop = NULL;
  return ES_OK;
}

static bool
read_sc_string_prop_from_payload(oc_rep_t *payload, char *prop_key,
                                 oc_string_t *prop_value)
{
  char *str_val = NULL;
  int str_len = 0;
  char attr_name[SC_MAX_ES_ATTR_NAME_LEN] = { 0 };

  construct_vnd_attr_name(attr_name, SC_MAX_ES_ATTR_NAME_LEN, prop_key);
  if (oc_rep_get_string(payload, attr_name, &str_val, &str_len)) {
    es_new_string(prop_value, str_val);
    return true;
  }

  return false;
}

static bool
read_sc_int_prop_from_payload(oc_rep_t *payload, char *prop_key,
                              int *prop_value)
{
  int int_val = 0;
  char attr_name[SC_MAX_ES_ATTR_NAME_LEN] = { 0 };

  construct_vnd_attr_name(attr_name, SC_MAX_ES_ATTR_NAME_LEN, prop_key);
  if (oc_rep_get_int(payload, attr_name, &int_val)) {
    *prop_value = int_val;
    return true;
  }

  return false;
}

static void
write_sc_string_prop_to_payload(char *prop_key, oc_string_t *prop_value)
{
  if (prop_value && oc_string_len(*prop_value) > 0) {
    char attr_name[SC_MAX_ES_ATTR_NAME_LEN] = { 0 };
    construct_vnd_attr_name(attr_name, SC_MAX_ES_ATTR_NAME_LEN, prop_key);
    es_rep_set_text_string_with_keystr(root, attr_name, oc_string(*prop_value));
  }
}

static void
write_sc_int_prop_to_payload(char *prop_key, int prop_value)
{
  char attr_name[SC_MAX_ES_ATTR_NAME_LEN] = { 0 };
  construct_vnd_attr_name(attr_name, SC_MAX_ES_ATTR_NAME_LEN, prop_key);
  es_rep_set_int_with_keystr(root, attr_name, prop_value);
}

static void
delete_wifi_prop(sc_wifi_conf_properties *prop)
{
  if (!prop) {
    return;
  }

  oc_free_string(&prop->bssid);
  oc_mem_free(prop);
}

static void
read_wifi_conf_data(oc_rep_t *payload, void **userdata)
{
  sc_wifi_conf_properties *wifi_prop =
    oc_mem_calloc(1, sizeof(sc_wifi_conf_properties));
  MEM_ALLOC_CHECK(wifi_prop);

  if (read_sc_int_prop_from_payload(payload,
                                    SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL,
                                    &wifi_prop->disc_channel)) {
    g_scprop->disc_channel = wifi_prop->disc_channel;
  }

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_BSSID,
                                       &wifi_prop->bssid)) {
    es_new_string(&g_scprop->bssid, oc_string(wifi_prop->bssid));
  }

  *userdata = wifi_prop;
  return;

exit:
  delete_wifi_prop(wifi_prop);
}

static void
delete_dev_prop(sc_dev_conf_properties *prop)
{
  if (!prop) {
    return;
  }

  if (oc_string_array_get_allocated_size(prop->location) > 0) {
    oc_free_string_array(&prop->location);
  }
  oc_free_string(&prop->reg_mobile_dev);
  oc_free_string(&prop->sso_list);
  oc_free_string(&prop->account);
  oc_free_string(&prop->country);
  oc_free_string(&prop->language);
  oc_free_string(&prop->gps_location);
  oc_free_string(&prop->utc_date_time);
  oc_free_string(&prop->regional_date_time);
  oc_mem_free(prop);
}

static void
read_dev_conf_data(oc_rep_t *payload, void **user_data)
{
  sc_dev_conf_properties *dev_prop =
    oc_mem_calloc(1, sizeof(sc_dev_conf_properties));
  MEM_ALLOC_CHECK(dev_prop);

#ifndef SC_ES_OPT
  char attr_name[SC_MAX_ES_ATTR_NAME_LEN] = { 0 };
  oc_string_array_t str_arr;
  int str_arr_len;
  construct_vnd_attr_name(attr_name, SC_MAX_ES_ATTR_NAME_LEN,
                           SC_RSRVD_ES_VENDOR_LOCATION);
  if (oc_rep_get_string_array(payload, attr_name, &str_arr, &str_arr_len)) {
    oc_new_string_array(&dev_prop->location, str_arr_len);
    if (oc_string_array_get_allocated_size(g_scprop->location) > 0)
      oc_free_string_array(&g_scprop->location);
    oc_new_string_array(&g_scprop->location, str_arr_len);
    for (int i = 0; i < str_arr_len; i++) {
      oc_string_array_add_item(dev_prop->location,
                               oc_string_array_get_item(str_arr, i));
      oc_string_array_add_item(g_scprop->location,
                               oc_string_array_get_item(str_arr, i));
    }
  }

  if (read_sc_string_prop_from_payload(payload,
                                       SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV,
                                       &dev_prop->reg_mobile_dev)) {
    es_new_string(&g_scprop->reg_mobile_dev,
                  oc_string(dev_prop->reg_mobile_dev));
  }

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_SSO_LIST,
                                       &dev_prop->sso_list)) {
    es_new_string(&g_scprop->sso_list, oc_string(dev_prop->sso_list));
  }

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_ACCOUNT,
                                       &dev_prop->account)) {
    es_new_string(&g_scprop->account, oc_string(dev_prop->account));
  }
#endif /* SC_ES_OPT */
  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_COUNTRY,
                                       &dev_prop->country)) {
    es_new_string(&g_scprop->country, oc_string(dev_prop->country));
  }

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_LANGUAGE,
                                       &dev_prop->language)) {
    es_new_string(&g_scprop->language, oc_string(dev_prop->language));
  }

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_GPSLOCATION,
                                       &dev_prop->gps_location)) {
    es_new_string(&g_scprop->gps_location, oc_string(dev_prop->gps_location));
  }

  if (read_sc_string_prop_from_payload(
        payload, SC_RSRVD_ES_VENDOR_UTC_DATE_TIME, &dev_prop->utc_date_time)) {
    es_new_string(&g_scprop->utc_date_time, oc_string(dev_prop->utc_date_time));
  }

  if (read_sc_string_prop_from_payload(payload,
                                       SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME,
                                       &dev_prop->regional_date_time)) {
    es_new_string(&g_scprop->regional_date_time,
                  oc_string(dev_prop->regional_date_time));
  }

  *user_data = dev_prop;
  return;

exit:
  delete_dev_prop(dev_prop);
}

static void
delete_cloud_prop(sc_cloud_server_conf_properties *prop)
{
  if (!prop) {
    return;
  }

  oc_free_string(&prop->client_id);
  oc_free_string(&prop->aac);
  oc_free_string(&prop->tnc_result);
  oc_free_string(&prop->uid);
  oc_free_string(&prop->refresh_token);
  oc_mem_free(prop);
}

static void
read_cloud_conf_data(oc_rep_t *payload, void **user_data)
{
  sc_cloud_server_conf_properties *cloud_prop =
    oc_mem_calloc(1, sizeof(sc_cloud_server_conf_properties));
  MEM_ALLOC_CHECK(cloud_prop);

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_CLIENTID,
                                       &cloud_prop->client_id)) {
    es_new_string(&g_scprop->client_id, oc_string(cloud_prop->client_id));
  }

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_AAC,
                                       &cloud_prop->aac)) {
    es_new_string(&g_scprop->aac, oc_string(cloud_prop->aac));
  }

#ifndef SC_ES_OPT
  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_TNC_RESULT,
                                       &cloud_prop->tnc_result)) {
    es_new_string(&g_scprop->tnc_result, oc_string(cloud_prop->tnc_result));
  }
#endif

  if (read_sc_string_prop_from_payload(payload, SC_RSRVD_ES_VENDOR_UID,
                                       &cloud_prop->uid)) {
    es_new_string(&g_scprop->uid, oc_string(cloud_prop->uid));
  }

  if (read_sc_string_prop_from_payload(payload,
                                       SC_RSRVD_ES_VENDOR_REFRESH_TOKEN,
                                       &cloud_prop->refresh_token)) {
    es_new_string(&g_scprop->refresh_token,
                  oc_string(cloud_prop->refresh_token));
  }

  *user_data = cloud_prop;
  return;

exit:
  delete_cloud_prop(cloud_prop);
}

void
sc_read_userdata_cb(oc_rep_t *payload, char *resource_type, void **user_data)
{
  if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_WIFICONF)) {
    read_wifi_conf_data(payload, user_data);
  } else if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    read_dev_conf_data(payload, user_data);
  } else if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF)) {
    read_cloud_conf_data(payload, user_data);
  }
}

void
sc_write_userdata_cb(oc_rep_t *payload, char *resource_type)
{
  (void)payload;

  if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_EASYSETUP)) {
    write_sc_int_prop_to_payload(SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE,
                                 g_scprop->net_conn_state);
#ifndef SC_ES_OPT
    write_sc_int_prop_to_payload(SC_RSRVD_ES_VENDOR_TNC_STATUS,
                                 g_scprop->tnc_status);
#endif
  } else if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_WIFICONF)) {
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_BSSID, &g_scprop->bssid);
  } else if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
#ifndef SC_ES_OPT
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_DEVICE_TYPE,
                                    &g_scprop->device_type);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE,
                                    &g_scprop->device_sub_type);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV,
                                    &g_scprop->reg_set_dev);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV,
                                    &g_scprop->reg_mobile_dev);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO,
                                    &g_scprop->net_prov_info);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_SSO_LIST,
                                    &g_scprop->sso_list);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_PNP_PIN,
                                    &g_scprop->pnp_pin);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_COUNTRY,
                                    &g_scprop->country);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_LANGUAGE,
                                    &g_scprop->language);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_GPSLOCATION,
                                    &g_scprop->gps_location);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_UTC_DATE_TIME,
                                    &g_scprop->utc_date_time);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME,
                                    &g_scprop->regional_date_time);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION,
                                    &g_scprop->es_protocol_ver);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_TNC_HEADER,
                                    &g_scprop->tnc_info.header);
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_TNC_VERSION,
                                    &g_scprop->tnc_info.version);
#endif /* SC_ES_OPT */
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_MODEL_NUMBER,
                                    &g_scprop->model);
  } else if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF)) {
#ifndef SC_ES_OPT
    write_sc_string_prop_to_payload(SC_RSRVD_ES_VENDOR_TNC_RESULT,
                                    &g_scprop->tnc_result);
#endif
  }
}

void
sc_free_userdata(void *user_data, char *resource_type)
{
  if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_WIFICONF)) {
    delete_wifi_prop(user_data);
  } else if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    delete_dev_prop(user_data);
  } else if (!strcmp(resource_type, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF)) {
    delete_cloud_prop(user_data);
  }
}

// --- "/sec/provisioninginfo" resource related code -----
static void
update_provisioning_info_resource(oc_request_t *request)
{
  (void)request;
  // TODO - Add update when more write properties are added
}

static void
construct_response_of_sec_provisioning(void)
{
  char key_name[SC_MAX_ES_ATTR_NAME_LEN] = { 0 };
  sec_provisioning_info *info = g_sec_prov->info;

  oc_rep_start_root_object();

  construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                           SC_RSRVD_ES_PROVISIONING_INFO_TARGETS);
  oc_rep_set_key(root_map, key_name);

  oc_rep_start_array(root_map, provisioning_targets);
  for (int i = 0; i < info->targets_size; i++) {
    oc_rep_object_array_start_item(provisioning_targets);

    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_PROVISIONING_INFO_TARGETDI);
    es_rep_set_text_string_with_keystr(provisioning_targets, key_name,
                                       oc_string(info->targets[i].target_di));

    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_PROVISIONING_INFO_TARGETRT);
    es_rep_set_text_string_with_keystr(provisioning_targets, key_name,
                                       oc_string(info->targets[i].target_rt));

    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_PROVISIONING_INFO_PUBLISHED);
    es_rep_set_boolean_with_keystr(provisioning_targets, key_name,
                                   info->targets[i].published);
    oc_rep_object_array_end_item(provisioning_targets);
  }
  oc_rep_close_array(root, provisioning_targets);

  construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                           SC_RSRVD_ES_PROVISIONING_INFO_OWNED);
  es_rep_set_boolean_with_keystr(root, key_name, info->owned);

  construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                           SC_RSRVD_ES_PROVISIONING_INFO_EASY_SETUP_DI);
  es_rep_set_text_string_with_keystr(root, key_name,
                                     oc_string(info->easysetup_di));

  oc_rep_end_root_object();
}

static void
get_sec_provisioning(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_A) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  construct_response_of_sec_provisioning();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_sec_provisioning(oc_request_t *request, oc_interface_mask_t interface,
                      void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_A) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_provisioning_info_resource(request);
  construct_response_of_sec_provisioning();
  oc_send_response(request, OC_STATUS_CHANGED);
}

es_result_e
init_provisioning_info_resource(sec_provisioning_info *prov_info)
{
  if (g_sec_prov) {
    deinit_provisioning_info_resource();
  }

  g_sec_prov = oc_mem_calloc(1, sizeof(sec_provisioning_res_t));
  MEM_ALLOC_CHECK(g_sec_prov);

  g_sec_prov->res = oc_new_resource(SC_RSRVD_ES_RES_NAME_PROVISIONING_INFO,
                                    SC_RSRVD_ES_URI_PROVISIONING_INFO, 1, 0);
  RESOURCE_CHECK(g_sec_prov->res);

  oc_resource_bind_resource_type(g_sec_prov->res,
                                 SC_RSRVD_ES_RES_TYPE_PROVISIONING_INFO);
  oc_resource_bind_resource_interface(g_sec_prov->res, OC_IF_A);
  oc_resource_set_default_interface(g_sec_prov->res, OC_IF_A);
  oc_resource_set_discoverable(g_sec_prov->res, true);
  oc_resource_set_observable(g_sec_prov->res, false);
#ifdef OC_SECURITY
  oc_resource_make_public(g_sec_prov->res);
#endif
  oc_resource_set_request_handler(g_sec_prov->res, OC_GET, get_sec_provisioning,
                                  NULL);
  oc_resource_set_request_handler(g_sec_prov->res, OC_POST,
                                  post_sec_provisioning, NULL);
  oc_add_resource(g_sec_prov->res);
#ifdef OC_SECURITY
  oc_sec_ace_update_conn_anon_clear(SC_RSRVD_ES_URI_PROVISIONING_INFO, 2, 14, 0);
#endif

  g_sec_prov->info = prov_info;
  return ES_OK;

exit:
  deinit_provisioning_info_resource();
  return ES_ERROR;
}

es_result_e
set_sec_prov_info(sec_provisioning_info *prov_info)
{
  INPUT_PARAM_NULL_CHECK(prov_info);

  g_sec_prov->info = prov_info;
  return ES_OK;

exit:
  return ES_ERROR;
}

es_result_e
deinit_provisioning_info_resource(void)
{
  if (g_sec_prov) {
    if (g_sec_prov->res) {
      oc_delete_resource(g_sec_prov->res);
    }
    oc_mem_free(g_sec_prov);
    g_sec_prov = NULL;
  }
  return ES_OK;
}

// --- "/sec/accesspointlist" resource related code -----
static void
construct_response_of_sec_aplist(sec_accesspoint *ap_list)
{
  if (!ap_list) {
    return;
  }

  sec_accesspoint *wifi_ap = ap_list;
  char key_name[SC_MAX_ES_ATTR_NAME_LEN] = { 0 };

  oc_rep_start_root_object();
  construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                           SC_RSRVD_ES_ACCESSPOINT_LIST_AP_ITEMS);
  oc_rep_set_key(root_map, key_name);
  oc_rep_start_array(root_map, ap_items);
  while (wifi_ap) {
    oc_rep_object_array_start_item(ap_items);

    OC_DBG("Channel - %s", oc_string(wifi_ap->channel));
    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_ACCESSPOINT_LIST_CHANNEL);
    es_rep_set_text_string_with_keystr(ap_items, key_name,
                                       oc_string(wifi_ap->channel));

    OC_DBG("Encryption Type - %s", oc_string(wifi_ap->enc_type));
    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_ACCESSPOINT_LIST_ENCRYPTION_TYPE);
    es_rep_set_text_string_with_keystr(ap_items, key_name,
                                       oc_string(wifi_ap->enc_type));

    OC_DBG("Mac address - %s", oc_string(wifi_ap->mac_address));
    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_ACCESSPOINT_LIST_MAC_ADDRESS);
    es_rep_set_text_string_with_keystr(ap_items, key_name,
                                       oc_string(wifi_ap->mac_address));

    OC_DBG("Max rate - %s", oc_string(wifi_ap->max_rate));
    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_ACCESSPOINT_LIST_MAX_RATE);
    es_rep_set_text_string_with_keystr(ap_items, key_name,
                                       oc_string(wifi_ap->max_rate));

    OC_DBG("RSSI - %s", oc_string(wifi_ap->rssi));
    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_ACCESSPOINT_LIST_RSSI);
    es_rep_set_text_string_with_keystr(ap_items, key_name,
                                       oc_string(wifi_ap->rssi));

    OC_DBG("Security type - %s", oc_string(wifi_ap->security_type));
    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_ACCESSPOINT_LIST_SECURITY_TYPE);
    es_rep_set_text_string_with_keystr(ap_items, key_name,
                                       oc_string(wifi_ap->security_type));

    OC_DBG("SSID - %s", oc_string(wifi_ap->ssid));
    construct_vnd_attr_name(key_name, SC_MAX_ES_ATTR_NAME_LEN,
                             SC_RSRVD_ES_ACCESSPOINT_LIST_SSID);
    es_rep_set_text_string_with_keystr(ap_items, key_name,
                                       oc_string(wifi_ap->ssid));

    oc_rep_object_array_end_item(ap_items);
    wifi_ap = wifi_ap->next;
  }
  oc_rep_close_array(root, ap_items);
  oc_rep_end_root_object();
}

static void
get_sec_aplist(oc_request_t *request, oc_interface_mask_t interface,
               void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received");

  if (!g_sec_aplist) {
    OC_ERR("sec aplist resource is invalid!");
    return;
  }

  if (interface != OC_IF_S) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  sec_accesspoint *ap_list = NULL;
  g_sec_aplist->cb(&ap_list);

  construct_response_of_sec_aplist(ap_list);
  oc_send_response(request, OC_STATUS_OK);

  // Free scan list
  while (ap_list) {
    sec_accesspoint *del = ap_list;
    ap_list = ap_list->next;

    oc_free_string(&(del->ssid));
    oc_free_string(&(del->channel));
    oc_free_string(&(del->enc_type));
    oc_free_string(&(del->mac_address));
    oc_free_string(&(del->max_rate));
    oc_free_string(&(del->rssi));
    oc_free_string(&(del->security_type));
    free(del);
  }
}

es_result_e
init_accesspointlist_resource(get_ap_scan_list cb)
{
  if (!cb) {
    OC_ERR("Invalid input!");
    return ES_ERROR;
  }

  g_sec_aplist = oc_mem_calloc(1, sizeof(sec_accesspoints_res_t));
  MEM_ALLOC_CHECK(g_sec_aplist);

  g_sec_aplist->res = oc_new_resource(SC_RSRVD_ES_RES_NAME_ACCESSPOINT_LIST,
                                      SC_RSRVD_ES_URI_ACCESSPOINT_LIST, 1, 0);
  RESOURCE_CHECK(g_sec_aplist->res);

  oc_resource_bind_resource_type(g_sec_aplist->res,
                                 SC_RSRVD_ES_RES_TYPE_ACCESSPOINT_LIST);
  oc_resource_bind_resource_interface(g_sec_aplist->res, OC_IF_S);
  oc_resource_set_default_interface(g_sec_aplist->res, OC_IF_S);
  oc_resource_set_discoverable(g_sec_aplist->res, true);
  oc_resource_set_observable(g_sec_aplist->res, false);
#ifdef OC_SECURITY
  oc_resource_make_public(g_sec_aplist->res);
#endif
  oc_resource_set_request_handler(g_sec_aplist->res, OC_GET, get_sec_aplist,
                                  NULL);
  oc_add_resource(g_sec_aplist->res);
  g_sec_aplist->cb = cb;
#ifdef OC_SECURITY
  oc_sec_ace_update_conn_anon_clear(SC_RSRVD_ES_URI_ACCESSPOINT_LIST, 2, 14, 0);
#endif
  return ES_OK;

exit:
  deinit_accesspointlist_resource();
  return ES_ERROR;
}

es_result_e
deinit_accesspointlist_resource(void)
{
  if (g_sec_aplist) {
    if (g_sec_aplist->res) {
      oc_delete_resource(g_sec_aplist->res);
    }
    g_sec_aplist->cb = NULL;
    oc_mem_free(g_sec_aplist);
    g_sec_aplist = NULL;
  }
  return ES_OK;
}
