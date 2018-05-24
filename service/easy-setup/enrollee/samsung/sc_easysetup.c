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
#include "string.h"
#include "stdio.h"
#include "oc_helpers.h"
#include "inttypes.h"
#include "es_utils.h"
#include "util/oc_mem.h"
#include "oc_log.h"

#define SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE  x.com.samsung.ncs
#define SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL    x.com.samsung.chn
#define SC_RSRVD_ES_VENDOR_DEVICE_TYPE          x.com.samsung.dt
#define SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE       x.com.samsung.sdt
#define SC_RSRVD_ES_VENDOR_LOCATION             x.com.samsung.location
#define SC_RSRVD_ES_VENDOR_CLIENTID             x.com.samsung.clientid
#define SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV  x.com.samsung.rmd
#define SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV     x.com.samsung.rsd
#define SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO    x.com.samsung.npi
#define SC_RSRVD_ES_VENDOR_ACCOUNT              x.com.samsung.account
#define SC_RSRVD_ES_VENDOR_SSO_LIST             x.com.samsung.ssolist
#define SC_RSRVD_ES_VENDOR_AAC                  x.com.samsung.aac
#define SC_RSRVD_ES_VENDOR_TNC_HEADER           x.com.samsung.tcheader
#define SC_RSRVD_ES_VENDOR_TNC_VERSION          x.com.samsung.tcversion
#define SC_RSRVD_ES_VENDOR_TNC_RESULT           x.com.samsung.tcresult
#define SC_RSRVD_ES_VENDOR_TNC_STATUS           x.com.samsung.tcstatus
#define SC_RSRVD_ES_VENDOR_REFRESH_TOKEN        x.com.samsung.refreshtoken
#define SC_RSRVD_ES_VENDOR_UID                  x.com.samsung.uid
#define SC_RSRVD_ES_VENDOR_BSSID                x.com.samsung.bssid
#define SC_RSRVD_ES_VENDOR_PNP_PIN              x.com.samsung.pnppin
#define SC_RSRVD_ES_VENDOR_MODEL_NUMBER         x.com.samsung.modelnumber
#define SC_RSRVD_ES_VENDOR_LANGUAGE             x.com.samsung.language
#define SC_RSRVD_ES_VENDOR_COUNTRY              x.com.samsung.country
#define SC_RSRVD_ES_VENDOR_GPSLOCATION          x.com.samsung.gpslocation
#define SC_RSRVD_ES_VENDOR_UTC_DATE_TIME        x.com.samsung.datetime
#define SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME   x.com.samsung.regionaldatetime
#define SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION  x.com.samsung.espv

#define SC_RSRVD_ES_PROVISIONING_INFO_TARGETS                     x.com.samsung.provisioning.targets
#define SC_RSRVD_ES_PROVISIONING_INFO_OWNED                       x.com.samsung.provisioning.owned
#define SC_RSRVD_ES_PROVISIONING_INFO_EASY_SETUP_DI               x.com.samsung.provisioning.easysetupdi
#define SC_RSRVD_ES_PROVISIONING_INFO_TARGETDI                    x.com.samsung.targetDi
#define SC_RSRVD_ES_PROVISIONING_INFO_TARGETRT                    x.com.samsung.targetRt
#define SC_RSRVD_ES_PROVISIONING_INFO_PUBLISHED                   x.com.samsung.published
#define STR_SC_RSRVD_ES_PROVISIONING_INFO_TARGETS                 "x.com.samsung.provisioning.targets"

provisioning_info_resource g_provisioninginfo_resource;

sc_properties g_SCProperties;

static void read_account_data(oc_rep_t* payload,void** userdata);
static void read_tnc_data(oc_rep_t* payload,void** userdata);
static void write_tnc_data(oc_rep_t* payload, char* resourceType);
static void write_wifi_data(oc_rep_t* payload, char* resourceType);

static void
initialize_sc_properties(const sc_properties *prop)
{
  es_new_string(&g_SCProperties.aac, oc_string(prop->aac));
  es_new_string(&g_SCProperties.account, oc_string(prop->account));
  es_new_string(&g_SCProperties.bssid, oc_string(prop->bssid));
  es_new_string(&g_SCProperties.clientID, oc_string(prop->clientID));
  es_new_string(&g_SCProperties.country, oc_string(prop->country));
  es_new_string(&g_SCProperties.deviceSubType, oc_string(prop->deviceSubType));
  es_new_string(&g_SCProperties.deviceType, oc_string(prop->deviceType));
  es_new_string(&g_SCProperties.esProtocolVersion, oc_string(prop->esProtocolVersion));
  es_new_string(&g_SCProperties.gpsLocation, oc_string(prop->gpsLocation));
  es_new_string(&g_SCProperties.language, oc_string(prop->language));
  es_new_string(&g_SCProperties.location, oc_string(prop->location));
  es_new_string(&g_SCProperties.modelNumber, oc_string(prop->modelNumber));
  es_new_string(&g_SCProperties.nwProvInfo, oc_string(prop->nwProvInfo));
  es_new_string(&g_SCProperties.pnpPin, oc_string(prop->pnpPin));
  es_new_string(&g_SCProperties.refreshToken, oc_string(prop->refreshToken));
  es_new_string(&g_SCProperties.regionalDateTime, oc_string(prop->regionalDateTime));
  es_new_string(&g_SCProperties.regMobileDev, oc_string(prop->regMobileDev));
  es_new_string(&g_SCProperties.regSetDev, oc_string(prop->regSetDev));
  es_new_string(&g_SCProperties.ssoList, oc_string(prop->ssoList));
  es_new_string(&g_SCProperties.tncResult, oc_string(prop->tncResult));
  es_new_string(&g_SCProperties.uid, oc_string(prop->uid));
  es_new_string(&g_SCProperties.utcDateTime, oc_string(prop->utcDateTime));
  es_new_string(&g_SCProperties.tncInfo.header, oc_string(prop->tncInfo.header));
  es_new_string(&g_SCProperties.tncInfo.version, oc_string(prop->tncInfo.version));
}

static void
deinitialize_sc_properties(void)
{
  es_free_string(g_SCProperties.aac);
  es_free_string(g_SCProperties.account);
  es_free_string(g_SCProperties.bssid);
  es_free_string(g_SCProperties.clientID);
  es_free_string(g_SCProperties.country);
  es_free_string(g_SCProperties.deviceSubType);
  es_free_string(g_SCProperties.deviceType);
  es_free_string(g_SCProperties.esProtocolVersion);
  es_free_string(g_SCProperties.gpsLocation);
  es_free_string(g_SCProperties.language);
  es_free_string(g_SCProperties.location);
  es_free_string(g_SCProperties.modelNumber);
  es_free_string(g_SCProperties.nwProvInfo);
  es_free_string(g_SCProperties.refreshToken);
  es_free_string(g_SCProperties.regionalDateTime);
  es_free_string(g_SCProperties.regMobileDev);
  es_free_string(g_SCProperties.regSetDev);
  es_free_string(g_SCProperties.ssoList);
  es_free_string(g_SCProperties.tncResult);
  es_free_string(g_SCProperties.uid);
  es_free_string(g_SCProperties.utcDateTime);
  es_free_string(g_SCProperties.tncInfo.header);
  es_free_string(g_SCProperties.tncInfo.version);
}

static void
update_provisioning_info_resource(oc_request_t *request)
{
   (void)request;
  //TODO - Add update when more write properties are added
}

static void
construct_response_of_provisioning_info(void)
{
  oc_rep_start_root_object();
  oc_rep_set_key(root_map, STR_SC_RSRVD_ES_PROVISIONING_INFO_TARGETS);
  oc_rep_start_array(root_map, provisioning_targets);
  for (int i=0;i<g_provisioninginfo_resource.targets_size;i++) {
    oc_rep_object_array_start_item(provisioning_targets);
    es_rep_set_text_string(provisioning_targets, SC_RSRVD_ES_PROVISIONING_INFO_TARGETDI,
                            oc_string(g_provisioninginfo_resource.targets[i].targetDi));
    es_rep_set_text_string(provisioning_targets, SC_RSRVD_ES_PROVISIONING_INFO_TARGETRT,
                            oc_string(g_provisioninginfo_resource.targets[i].targetRt));
    es_rep_set_boolean(provisioning_targets, SC_RSRVD_ES_PROVISIONING_INFO_PUBLISHED,
                             g_provisioninginfo_resource.targets[i].published);
    oc_rep_object_array_end_item(provisioning_targets);
  }
  oc_rep_close_array(root, provisioning_targets);
  oc_rep_set_boolean(root, SC_RSRVD_ES_PROVISIONING_INFO_OWNED, g_provisioninginfo_resource.owned);
  es_rep_set_text_string(root, SC_RSRVD_ES_PROVISIONING_INFO_EASY_SETUP_DI, oc_string(g_provisioninginfo_resource.easysetupdi));

  oc_rep_end_root_object();
}

static void
post_provisioning_info(oc_request_t *request, oc_interface_mask_t interface,void *user_data)
{
  (void)user_data;
  OC_DBG("POST request received on sec provisioning resource");

  if (interface != OC_IF_A) {
    OC_ERR("Sec prov resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  update_provisioning_info_resource(request);
  construct_response_of_provisioning_info();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
get_provisioning_info(oc_request_t *request, oc_interface_mask_t interface,void *user_data)
{
  (void)user_data;
  OC_DBG("GET request received on sec provisioning resource");

  if (interface != OC_IF_A) {
    OC_ERR("Sec prov resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  construct_response_of_provisioning_info();
  oc_send_response(request, OC_STATUS_OK);
}

es_result_e
set_properties_for_sc_prov_info(const provisioning_info_resource *prop)
{
  if(prop != NULL) {
    OC_DBG("Invalid sec provisioning info!");
    return ES_ERROR;
  }

  memcpy(&g_provisioninginfo_resource, prop, sizeof(provisioning_info_resource));
  return ES_OK;
}

es_result_e
register_sc_provisioning_info_resource()
{
  oc_resource_t *provisioninginfo =
    oc_new_resource("provisioninginfo", SC_RSRVD_ES_URI_PROVISIONING_INFO, 1, 0);
  if (!provisioninginfo) {
    OC_ERR("Failed to create provisioninginfo resource!");
    return ES_ERROR;
  }

  g_provisioninginfo_resource.easysetupdi.ptr="";
  oc_resource_bind_resource_type(provisioninginfo, SC_RSRVD_ES_RES_TYPE_PROVISIONING_INFO);
  oc_resource_bind_resource_interface(provisioninginfo, OC_IF_A);
  oc_resource_set_default_interface(provisioninginfo, OC_IF_A);
  oc_resource_set_discoverable(provisioninginfo, true);
  oc_resource_set_observable(provisioninginfo, false);
#ifdef OC_SECURITY
  oc_resource_make_public(provisioninginfo);
#endif
  oc_resource_set_request_handler(provisioninginfo, OC_GET, get_provisioning_info, NULL);
  oc_resource_set_request_handler(provisioninginfo, OC_POST, post_provisioning_info, NULL);
  oc_add_resource(provisioninginfo);
  g_provisioninginfo_resource.handle = provisioninginfo;
  return ES_OK;
}

es_result_e
set_sc_properties(const sc_properties *prop)
{
  if(prop != NULL) {
    OC_DBG("Invalid sc properties!");
    return ES_ERROR;
  }

  memcpy(&g_SCProperties, prop, sizeof(sc_properties));
  initialize_sc_properties(prop);
  return ES_OK;
}

es_result_e
reset_sc_properties()
{
  deinitialize_sc_properties();
  return ES_OK;
}

static void
read_account_data(oc_rep_t *payload, void **userdata)
{
  char *str_val = NULL;
  int str_len = 0;
  if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_ACCOUNT, &str_val, &str_len)) {
    if (!*userdata) {
      *userdata = (void *)oc_mem_calloc(1, sizeof(sc_dev_conf_properties));
      if (!*userdata) {
        OC_ERR("Memory allocation failed!");
        return;
      }
    }

    sc_dev_conf_properties *pDevConfProp =
      (sc_dev_conf_properties *)(*userdata);
    es_new_string(&pDevConfProp->account, str_val);
    es_new_string(&g_SCProperties.account, str_val);
  }
}

es_result_e
set_sc_tnc_info(sc_tnc_info *tncInfo)
{
  if(!tncInfo) {
      return ES_ERROR;
  }

  g_SCProperties.tncInfo = *tncInfo;
  return ES_OK;
}

es_result_e
set_sc_tnc_status(int status)
{
  g_SCProperties.tncStatus = status;
  return ES_OK;
}

es_result_e
set_sc_net_connection_state(NETCONNECTION_STATE netConnectionState)
{
  g_SCProperties.netConnectionState = netConnectionState;
  es_notify_connection_change();
  return ES_OK;
}

static void
read_tnc_data(oc_rep_t* payload,void** userdata)
{
  char *str_val = NULL;
  int str_len = 0;
  if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_TNC_RESULT, &str_val, &str_len)) {
    if (!*userdata) {
      *userdata = (void *)oc_mem_calloc(1, sizeof(sc_coap_cloud_server_conf_properties));
      if (!*userdata) {
        OC_ERR("Memory allocation failed!");
        return;
      }
    }

    sc_coap_cloud_server_conf_properties *pProp =
      (sc_coap_cloud_server_conf_properties *)(*userdata);
    es_new_string(&pProp->tncResult, str_val);
    es_new_string(&g_SCProperties.tncResult, str_val);
  }
}

static void
write_tnc_data(oc_rep_t *payload, char *resourceType)
{
  (void)payload;

  if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_EASYSETUP)) {
    es_rep_set_int(root, SC_RSRVD_ES_VENDOR_TNC_STATUS,
                            g_SCProperties.tncStatus);
  } else if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_TNC_HEADER,
                            oc_string(g_SCProperties.tncInfo.header));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_TNC_VERSION,
                            oc_string(g_SCProperties.tncInfo.version));
  } else if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF)) {
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_TNC_RESULT,
                            oc_string(g_SCProperties.tncResult));
  }
}

static void
write_wifi_data(oc_rep_t *payload, char *resourceType)
{
  (void)payload;

  if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_WIFICONF)) {
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_BSSID,
                            oc_string(g_SCProperties.bssid));
  }
}

es_result_e
set_register_set_device(const char *regSetDevice)
{
  if (!regSetDevice) {
    return ES_ERROR;
  }

  es_new_string(&g_SCProperties.regSetDev, (char *)regSetDevice);
  return ES_OK;
}

es_result_e
set_network_prov_info(const char *nwProvInfo)
{
  if (!nwProvInfo) {
    return ES_ERROR;
  }

  es_new_string(&g_SCProperties.nwProvInfo,(char *) nwProvInfo);
  return ES_OK;
}

es_result_e
set_sc_pnp_pin(const char *pnp)
{
  if (!pnp) {
    return ES_ERROR;
  }

  es_new_string(&g_SCProperties.pnpPin,(char *) pnp);
  return ES_OK;
}

es_result_e
set_es_version_info(const char *esProtocolVersion)
{
  if (!esProtocolVersion) {
    return ES_ERROR;
  }

  es_new_string(&g_SCProperties.esProtocolVersion, (char *)esProtocolVersion);
  return ES_OK;
}

void
ReadUserdataCb(oc_rep_t* payload, char* resourceType, void** userdata)
{
  if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_WIFICONF)) {
    // Allocate memory for user data
    if (!*userdata) {
      *userdata = (void *)oc_mem_calloc(1, sizeof(sc_wifi_conf_properties));
      if (!*userdata) {
        OC_ERR("Memory allocation failed!");
        return;
      }
    }

    sc_wifi_conf_properties *pWifiConfProp =
      (sc_wifi_conf_properties *)(*userdata);

    int int_val = 0;
    if (oc_rep_get_int(payload, STR_SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL, &int_val)) {
        pWifiConfProp->discoveryChannel = (int)int_val;
        g_SCProperties.discoveryChannel = int_val;
    }

    char *str_val = NULL;;
    int str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_BSSID, &str_val, &str_len)) {
      es_new_string(&pWifiConfProp->bssid, str_val);
      es_new_string(&g_SCProperties.bssid, str_val);
    }
  } else if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    // Allocate memory for user data
    if (!*userdata) {
      *userdata = (void *)oc_mem_calloc(1, sizeof(sc_dev_conf_properties));
      if (!*userdata) {
        OC_ERR("Memory allocation failed!");
        return;
      }
    }

    sc_dev_conf_properties *pDevConfProp =
      (sc_dev_conf_properties *)(*userdata);

    oc_string_array_t str_arr;
    int str_arr_len;
    if (oc_rep_get_string_array(payload, STR_SC_RSRVD_ES_VENDOR_LOCATION, &str_arr, &str_arr_len)) {
      oc_new_string_array(&pDevConfProp->location, str_arr_len);
      oc_new_string_array(&g_SCProperties.location, str_arr_len);
      for (int i = 0; i < str_arr_len; i++) {
        oc_string_array_add_item(
          pDevConfProp->location,
          oc_string_array_get_item(str_arr, i));
        oc_string_array_add_item(
          g_SCProperties.location,
          oc_string_array_get_item(str_arr, i));
      }
    }

    read_account_data(payload,userdata);

    char *str_val = NULL;;
    int str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV, &str_val, &str_len)) {
      es_new_string(&pDevConfProp->regMobileDev, str_val);
      es_new_string(&g_SCProperties.regMobileDev, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_COUNTRY, &str_val, &str_len)) {
      es_new_string(&pDevConfProp->country, str_val);
      es_new_string(&g_SCProperties.country, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_LANGUAGE, &str_val, &str_len)) {
      es_new_string(&pDevConfProp->language, str_val);
      es_new_string(&g_SCProperties.language, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_GPSLOCATION, &str_val, &str_len)) {
      es_new_string(&pDevConfProp->gpsLocation, str_val);
      es_new_string(&g_SCProperties.gpsLocation, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_UTC_DATE_TIME, &str_val, &str_len)) {
      es_new_string(&pDevConfProp->utcDateTime, str_val);
      es_new_string(&g_SCProperties.utcDateTime, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME, &str_val, &str_len)) {
      es_new_string(&pDevConfProp->regionalDateTime, str_val);
      es_new_string(&g_SCProperties.regionalDateTime, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_SSO_LIST, &str_val, &str_len)) {
      es_new_string(&pDevConfProp->ssoList, str_val);
      es_new_string(&g_SCProperties.ssoList, str_val);
    }
  } else if(!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF)) {
    // Allocate memory for user data
    if (!*userdata) {
      *userdata = (void *)oc_mem_calloc(1, sizeof(sc_coap_cloud_server_conf_properties));
      if (!*userdata) {
        OC_ERR("Memory allocation failed!");
        return;
      }
    }

    sc_coap_cloud_server_conf_properties *pCloudProp =
      (sc_coap_cloud_server_conf_properties *)(*userdata);

    char *str_val = NULL;;
    int str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_CLIENTID, &str_val, &str_len)) {
      es_new_string(&pCloudProp->clientID, str_val);
      es_new_string(&g_SCProperties.clientID, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_AAC, &str_val, &str_len)) {
      es_new_string(&pCloudProp->aac, str_val);
      es_new_string(&g_SCProperties.aac, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_UID, &str_val, &str_len)) {
      es_new_string(&pCloudProp->uid, str_val);
      es_new_string(&g_SCProperties.uid, str_val);
    }

    str_val = NULL; str_len = 0;
    if (oc_rep_get_string(payload, STR_SC_RSRVD_ES_VENDOR_REFRESH_TOKEN, &str_val, &str_len)) {
      es_new_string(&pCloudProp->refreshToken, str_val);
      es_new_string(&g_SCProperties.refreshToken, str_val);
    }

    read_tnc_data(payload,userdata);
  }
}

void
WriteUserdataCb(oc_rep_t* payload, char* resourceType)
{
  if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_EASYSETUP)) {
    es_rep_set_int(root, SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE,
                   (int)g_SCProperties.netConnectionState);
  } else if (!strcmp(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_DEVICE_TYPE,
                            oc_string(g_SCProperties.deviceType));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE,
                            oc_string(g_SCProperties.deviceSubType));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV,
                            oc_string(g_SCProperties.regSetDev));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV,
                            oc_string(g_SCProperties.regMobileDev));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO,
                            oc_string(g_SCProperties.nwProvInfo));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_SSO_LIST,
                            oc_string(g_SCProperties.ssoList));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_PNP_PIN,
                            oc_string(g_SCProperties.pnpPin));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_MODEL_NUMBER,
                            oc_string(g_SCProperties.modelNumber));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_COUNTRY,
                            oc_string(g_SCProperties.country));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_LANGUAGE,
                            oc_string(g_SCProperties.language));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_GPSLOCATION,
                            oc_string(g_SCProperties.gpsLocation));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_UTC_DATE_TIME,
                            oc_string(g_SCProperties.utcDateTime));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME,
                            oc_string(g_SCProperties.regionalDateTime));
    es_rep_set_text_string(root, SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION,
                            oc_string(g_SCProperties.esProtocolVersion));
  }

  write_tnc_data(payload, resourceType);
  write_wifi_data(payload, resourceType);
}
