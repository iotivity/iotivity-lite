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
#include "oc_log.h"
#include "stdio.h"
#include "oc_helpers.h"
#include "inttypes.h"

#include "resourcehandler.h"

/**
 * @var SC_ENROLLEE_TAG
 * @brief Logging tag for module name.
 */
#define SC_ENROLLEE_TAG "ES_SC_ENROLLEE"

#define MAX_REP_ARRAY_DEPTH 3

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

easy_setup_resource g_ESEasySetupResource;
wifi_conf_resource g_ESWiFiConfResource;
coap_cloud_conf_resource g_ESCoapCloudConfResource;
dev_conf_resource g_ESDevConfResource;
provisioning_info_resource g_provisioninginfo_resource;

sc_properties g_SCProperties;

static void read_account_data(oc_rep_t* payload,void** userdata);
static void read_tnc_data(oc_rep_t* payload,void** userdata);
static void write_tnc_data(oc_rep_t* payload, char* resourceType);
static void write_wifi_data(oc_rep_t* payload, char* resourceType);

#define custom_oc_string_dup(dest, src)                   \
  do {                                     \
    if (src.size != 0) {              \
      oc_new_string(&dest,oc_string(src),src.size);  \
    }       \
  } while (0)

static void
initialize_sc_properties(const sc_properties *prop)
{
  // Initialize samsung specific properlties
  custom_oc_string_dup(g_SCProperties.aac, prop->aac);
  custom_oc_string_dup(g_SCProperties.account, prop->account);
  custom_oc_string_dup(g_SCProperties.bssid, prop->bssid);
  custom_oc_string_dup(g_SCProperties.clientID, prop->clientID);
  custom_oc_string_dup(g_SCProperties.country, prop->country);
  custom_oc_string_dup(g_SCProperties.deviceSubType, prop->deviceSubType);
  custom_oc_string_dup(g_SCProperties.deviceType, prop->deviceType);
  custom_oc_string_dup(g_SCProperties.esProtocolVersion, prop->esProtocolVersion);
  custom_oc_string_dup(g_SCProperties.gpsLocation, prop->gpsLocation);
  custom_oc_string_dup(g_SCProperties.language, prop->language);
  custom_oc_string_dup(g_SCProperties.location, prop->location);
  custom_oc_string_dup(g_SCProperties.modelNumber, prop->modelNumber);
  custom_oc_string_dup(g_SCProperties.nwProvInfo, prop->nwProvInfo);
  custom_oc_string_dup(g_SCProperties.pnpPin, prop->pnpPin);
  custom_oc_string_dup(g_SCProperties.refreshToken, prop->refreshToken);
  custom_oc_string_dup(g_SCProperties.regionalDateTime, prop->regionalDateTime);
  custom_oc_string_dup(g_SCProperties.regMobileDev, prop->regMobileDev);
  custom_oc_string_dup(g_SCProperties.regSetDev, prop->regSetDev);
  custom_oc_string_dup(g_SCProperties.ssoList, prop->ssoList);
  custom_oc_string_dup(g_SCProperties.tncResult, prop->tncResult);
  custom_oc_string_dup(g_SCProperties.uid, prop->uid);
  custom_oc_string_dup(g_SCProperties.utcDateTime, prop->utcDateTime);
  custom_oc_string_dup(g_SCProperties.tncInfo.header, prop->tncInfo.header);
  custom_oc_string_dup(g_SCProperties.tncInfo.version, prop->tncInfo.version);
}

static void
deinitialize_sc_properties(void)
{
  es_free_property(g_SCProperties.aac);
  es_free_property(g_SCProperties.account);
  es_free_property(g_SCProperties.bssid);
  es_free_property(g_SCProperties.clientID);
  es_free_property(g_SCProperties.country);
  es_free_property(g_SCProperties.deviceSubType);
  es_free_property(g_SCProperties.deviceType);
  es_free_property(g_SCProperties.esProtocolVersion);
  es_free_property(g_SCProperties.gpsLocation);
  es_free_property(g_SCProperties.language);
  es_free_property(g_SCProperties.location);
  es_free_property(g_SCProperties.modelNumber);
  es_free_property(g_SCProperties.nwProvInfo);
  es_free_property(g_SCProperties.refreshToken);
  es_free_property(g_SCProperties.regionalDateTime);
  es_free_property(g_SCProperties.regMobileDev);
  es_free_property(g_SCProperties.regSetDev);
  es_free_property(g_SCProperties.ssoList);
  es_free_property(g_SCProperties.tncResult);
  es_free_property(g_SCProperties.uid);
  es_free_property(g_SCProperties.utcDateTime);
  es_free_property(g_SCProperties.tncInfo.header);
  es_free_property(g_SCProperties.tncInfo.version);

}
static void update_provisioning_info_resource(oc_request_t *request)
{
   (void)request;
  //TODO - Add update when more write properties are added

}
static void construct_response_of_provisioning_info(void)
{
  oc_rep_start_root_object();
  oc_rep_set_key(root_map,STR_SC_RSRVD_ES_PROVISIONING_INFO_TARGETS);
  oc_rep_start_array(root_map, provisioning_targets);
  for (int i=0;i<g_provisioninginfo_resource.targets_size;i++) {
    oc_rep_object_array_start_item(provisioning_targets);
    set_custom_property_str(provisioning_targets, SC_RSRVD_ES_PROVISIONING_INFO_TARGETDI,  oc_string(g_provisioninginfo_resource.targets[i].targetDi));
    set_custom_property_str(provisioning_targets, SC_RSRVD_ES_PROVISIONING_INFO_TARGETRT, oc_string(g_provisioninginfo_resource.targets[i].targetRt));
    set_custom_property_bool(provisioning_targets, SC_RSRVD_ES_PROVISIONING_INFO_PUBLISHED, g_provisioninginfo_resource.targets[i].published);
    oc_rep_object_array_end_item(provisioning_targets);
  }
  oc_rep_close_array(root, provisioning_targets);
  set_custom_property_bool(root, SC_RSRVD_ES_PROVISIONING_INFO_OWNED, g_provisioninginfo_resource.owned);
  set_custom_property_str(root, SC_RSRVD_ES_PROVISIONING_INFO_EASY_SETUP_DI, oc_string(g_provisioninginfo_resource.easysetupdi));

  oc_rep_end_root_object();
}

static void post_provisioning_info(oc_request_t *request, oc_interface_mask_t interface,void *user_data)
{
  (void)user_data;

  if (interface == OC_IF_A) {
    update_provisioning_info_resource(request);
    construct_response_of_provisioning_info();
    OC_DBG("success");
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void get_provisioning_info(oc_request_t *request, oc_interface_mask_t interface,void *user_data)
{
  (void)user_data;

  if (interface == OC_IF_A) {
    construct_response_of_provisioning_info();
    oc_send_response(request, OC_STATUS_OK);
  } else {
    OC_ERR("Error");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

es_result_e set_properties_for_sc_prov_info(const provisioning_info_resource *prop)
{
    if(prop != NULL)
    {
        memcpy(&g_provisioninginfo_resource, prop, sizeof(provisioning_info_resource));
        OC_DBG("SetSCProperties OUT");
        return ES_OK;
    }
    return ES_ERROR;
}

es_result_e register_sc_provisioning_info_resource(void)
{
  oc_resource_t *provisioninginfo =
    oc_new_resource("provisioninginfo", SC_RSRVD_ES_URI_PROVISIONING_INFO, 1, 0);
  g_provisioninginfo_resource.easysetupdi.ptr="";

  if (NULL == provisioninginfo) {
    OC_ERR("Error in creating provisioninginfo Resource!");
    return ES_ERROR;
  }

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
  OC_DBG("Created provisioninginfo Resource with success");

  return ES_OK;
}

es_result_e set_sc_properties(const sc_properties *prop)
{
  if(prop != NULL)
  {
    memcpy(&g_SCProperties, prop, sizeof(sc_properties));
    initialize_sc_properties(prop);
    OC_DBG("SetSCProperties OUT");
    return ES_OK;
  }
  return ES_ERROR;
}

es_result_e reset_sc_properties(const sc_properties *prop)
{
    if(prop != NULL)
    {
        deinitialize_sc_properties();
        OC_DBG("ResetSCProperties OUT");
        return ES_OK;
    }
    return ES_ERROR;
}


static void
read_account_data(oc_rep_t *payload, void **userdata)
{
  if (strcmp(oc_string(payload->name), STR_SC_RSRVD_ES_VENDOR_ACCOUNT) == 0 &&
      payload->type == OC_REP_STRING) {
    if (*userdata == NULL) {
      *userdata = (void*)malloc(sizeof(sc_dev_conf_properties));
      if( *userdata == NULL )
      {
        OC_DBG("OICMalloc for SCDevConfProperties is failed");
        return;
      }
    }

    sc_dev_conf_properties *pDevConfProp =
      (sc_dev_conf_properties *)(*userdata);
    oc_allocate_string(&pDevConfProp->account, oc_string(payload->value.string));
    oc_allocate_string(&g_SCProperties.account, oc_string(payload->value.string));

    OC_DBG("[User specific property] %s : %s", STR_SC_RSRVD_ES_VENDOR_ACCOUNT,
           oc_string(pDevConfProp->account));
  }
}

es_result_e set_sc_tnc_info(sc_tnc_info *tncInfo)
{
    if(tncInfo == NULL)
    {
        return ES_ERROR;
    }
    g_SCProperties.tncInfo = *tncInfo;
    return ES_OK;
}

es_result_e set_sc_tnc_status(int status)
{
    g_SCProperties.tncStatus = status;
    return ES_OK;
}

es_result_e set_sc_net_connection_state(NETCONNECTION_STATE netConnectionState)
{
    OC_DBG( "SetSCNetConnectionState: %d", netConnectionState);
    g_SCProperties.netConnectionState = netConnectionState;

    if(0 == oc_notify_observers(g_ESEasySetupResource.handle))
    {
        OC_DBG("provResource doesn't have any observers.");
    }
    return ES_OK;
}

static void read_tnc_data(oc_rep_t* payload,void** userdata)
{
  if (strcmp(oc_string(payload->name), STR_SC_RSRVD_ES_VENDOR_TNC_RESULT) ==
        0 &&
      payload->type == OC_REP_STRING) {
    if (*userdata == NULL) {
      *userdata = (void*)malloc(sizeof(sc_coap_cloud_server_conf_properties));
      if( *userdata == NULL )
      {
        OC_ERR("OICMalloc for sc_coap_cloud_server_conf_properties is failed");
        return;
      }
    }

    sc_coap_cloud_server_conf_properties *pProp =
      (sc_coap_cloud_server_conf_properties *)(*userdata);
    oc_allocate_string(&pProp->tncResult, oc_string(payload->value.string));
    oc_allocate_string(&g_SCProperties.tncResult, oc_string(payload->value.string));

    OC_DBG("[User specific property] %s : %s",
           STR_SC_RSRVD_ES_VENDOR_TNC_RESULT, oc_string(pProp->tncResult));
  }
}

static void
write_tnc_data(oc_rep_t *payload, char *resourceType)
{
  (void)payload;
  if (resourceType == NULL) {
    OC_ERR("resourceType is NULL");
    OC_ERR("WriteTnCdata OUT");
    return;
  }
  if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_EASYSETUP)) {
    set_custom_property_int(root, SC_RSRVD_ES_VENDOR_TNC_STATUS,
                            g_SCProperties.tncStatus);
  } else if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_TNC_HEADER,
                            oc_string(g_SCProperties.tncInfo.header));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_TNC_VERSION,
                            oc_string(g_SCProperties.tncInfo.version));
  } else if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF)) {
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_TNC_RESULT,
                            oc_string(g_SCProperties.tncResult));
  }
}

static void
write_wifi_data(oc_rep_t *payload, char *resourceType)
{
  (void)payload;
  if (resourceType == NULL) {
    OC_DBG("Invalid Params resourceType is NULL");
    OC_DBG("WriteWifiData OUT");
    return;
  }

  if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_WIFICONF)) {
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_BSSID,
                            oc_string(g_SCProperties.bssid));
  }
}

es_result_e set_register_set_device(const char *regSetDevice)
{
  if (regSetDevice != NULL) {
    oc_allocate_string(&g_SCProperties.regSetDev, (char *)regSetDevice);
    return ES_OK;
  }
  return ES_ERROR;
}

es_result_e set_network_prov_info(const char *nwProvInfo)
{
  if (nwProvInfo != NULL) {
    oc_allocate_string(&g_SCProperties.nwProvInfo,(char *) nwProvInfo);
    return ES_OK;
  }
  return ES_ERROR;
}

es_result_e set_sc_pnp_pin(const char *pnp)
{
  if (pnp != NULL) {
    oc_allocate_string(&g_SCProperties.pnpPin,(char *) pnp);
    return ES_OK;
  }
  return ES_ERROR;
}

es_result_e set_es_version_info(const char *esProtocolVersion)
{
  if (esProtocolVersion != NULL) {
    oc_allocate_string(&g_SCProperties.esProtocolVersion, (char *)esProtocolVersion);
    return ES_OK;
  }
  return ES_ERROR;
}

void ReadUserdataCb(oc_rep_t* payload, char* resourceType, void** userdata)
{
  if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_WIFICONF)) {
    oc_rep_t *rep = payload;
    if (*userdata == NULL) {
      *userdata = (void *)malloc(sizeof(sc_wifi_conf_properties));
      if (*userdata == NULL) {
        OC_ERR("OICMalloc for SCWiFiConfProperties is failed");
        return;
      }
      memset(*userdata, 0, sizeof(sc_wifi_conf_properties));
    }
    sc_wifi_conf_properties *pWifiConfProp =
      (sc_wifi_conf_properties *)(*userdata);

    while (rep != NULL) {
      if (strcmp(oc_string(rep->name),
                 STR_SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL) == 0 &&
          rep->type == OC_REP_INT) {
        int64_t channel = -1;
        channel = rep->value.integer;
        OC_DBG("[User specific property] %s : [%" PRId64 "]",
               STR_SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL, channel);
        pWifiConfProp->discoveryChannel = (int)channel;
        g_SCProperties.discoveryChannel = channel;
      }
      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_BSSID) == 0 &&
          rep->type == OC_REP_STRING) {
          oc_allocate_string(&pWifiConfProp->bssid, oc_string(rep->value.string));
          oc_allocate_string(&g_SCProperties.bssid, oc_string(rep->value.string));
        OC_DBG("[User specific property] %s : %s", STR_SC_RSRVD_ES_VENDOR_BSSID,
               oc_string(pWifiConfProp->bssid));
      }
      rep = rep->next;
    }
  } else if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    oc_rep_t *rep = payload;
    if (*userdata == NULL) {
      *userdata = (void *)malloc(sizeof(sc_dev_conf_properties));
      if (*userdata == NULL) {
        OC_ERR("malloc for SCDevConfProperties is failed");
        return;
      }
      memset(*userdata, 0, sizeof(sc_dev_conf_properties));
    }
    sc_dev_conf_properties *pDevConfProp =
      (sc_dev_conf_properties *)(*userdata);

    while (rep != NULL) {
      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_LOCATION) == 0 &&
          rep->type == OC_REP_STRING_ARRAY) {
        oc_array_t rep_array = rep->value.array;
        int dimensions = (int)oc_string_array_get_allocated_size(rep_array);
        oc_new_string_array(&pDevConfProp->location, dimensions);
        oc_new_string_array(&g_SCProperties.location, dimensions);

        uint8_t i;
        for (i = 0; i < dimensions; i++) {
          oc_string_array_add_item(
            pDevConfProp->location,
            oc_string_array_get_item(rep->value.array, i));
          oc_string_array_add_item(
            g_SCProperties.location,
            oc_string_array_get_item(rep->value.array, i));
          OC_DBG("[User specific property] %s : %s",
                 STR_SC_RSRVD_ES_VENDOR_LOCATION,
                 oc_string_array_get_item(pDevConfProp->location, i));
        }
      }

      read_account_data(payload,userdata);

      if (strcmp(oc_string(rep->name),
                 STR_SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV) == 0 &&
          rep->type == OC_REP_STRING) {
          oc_allocate_string(&pDevConfProp->regMobileDev, oc_string(rep->value.string));
          oc_allocate_string(&g_SCProperties.regMobileDev, oc_string(rep->value.string));
        OC_DBG("pDevConfProp.regMobileDev %s",
               oc_string(g_SCProperties.regMobileDev));
      }

      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_COUNTRY) == 0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pDevConfProp->country, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.country, oc_string(rep->value.string));
        OC_DBG("pDevConfProp.country %s", oc_string(g_SCProperties.country));
      }

      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_LANGUAGE) == 0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pDevConfProp->language, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.language, oc_string(rep->value.string));
        OC_DBG("pDevConfProp.language %s", oc_string(g_SCProperties.language));
      }

      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_GPSLOCATION) ==
            0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pDevConfProp->gpsLocation, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.gpsLocation, oc_string(rep->value.string));
        OC_DBG("pDevConfProp.gpsLocation %s",
               oc_string(g_SCProperties.gpsLocation));
      }

      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_UTC_DATE_TIME) ==
            0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pDevConfProp->utcDateTime, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.utcDateTime, oc_string(rep->value.string));
        OC_DBG("pDevConfProp.utcDateTime %s",
               oc_string(g_SCProperties.utcDateTime));
      }

      if (strcmp(oc_string(rep->name),
                 STR_SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME) == 0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pDevConfProp->regionalDateTime,
                      oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.regionalDateTime,
                      oc_string(rep->value.string));
        OC_DBG("pDevConfProp.regionalDateTime %s",
               oc_string(g_SCProperties.regionalDateTime));
      }

      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_SSO_LIST) == 0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pDevConfProp->ssoList, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.ssoList, oc_string(rep->value.string));
        OC_DBG("pDevConfProp.ssoList %s", oc_string(g_SCProperties.ssoList));
      }
      rep = rep->next;
    }
  }
  else if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF))
  {
    oc_rep_t *rep = payload;
    if (*userdata == NULL) {
      *userdata = (void *)malloc(sizeof(sc_coap_cloud_server_conf_properties));
      if (*userdata == NULL) {
        OC_ERR("OICMalloc for sc_coap_cloud_server_conf_properties is failed");
        return;
      }
      memset(*userdata, 0, sizeof(sc_coap_cloud_server_conf_properties));
    }
    sc_coap_cloud_server_conf_properties *pCloudProp =
      (sc_coap_cloud_server_conf_properties *)(*userdata);

    while (rep != NULL) {
      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_CLIENTID) == 0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pCloudProp->clientID, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.clientID, oc_string(rep->value.string));
        OC_DBG("[User specific property] %s : %s",
               STR_SC_RSRVD_ES_VENDOR_CLIENTID,
               oc_string(pCloudProp->clientID));
      }

      // SC_RSRVD_ES_VENDOR_AAC
      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_AAC) == 0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pCloudProp->aac, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.aac, oc_string(rep->value.string));
        OC_DBG("[User specific property] %s : %s", STR_SC_RSRVD_ES_VENDOR_AAC,
               oc_string(pCloudProp->aac));
      }

      // SC_RSRVD_ES_VENDOR_UID
      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_UID) == 0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pCloudProp->uid, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.uid, oc_string(rep->value.string));
        OC_DBG("[User specific property] %s : %s", STR_SC_RSRVD_ES_VENDOR_UID,
               oc_string(pCloudProp->uid));
      }

      //SC_RSRVD_ES_VENDOR_REFRESH_TOKEN
      if (strcmp(oc_string(rep->name), STR_SC_RSRVD_ES_VENDOR_REFRESH_TOKEN) ==
            0 &&
          rep->type == OC_REP_STRING) {
        oc_allocate_string(&pCloudProp->refreshToken, oc_string(rep->value.string));
        oc_allocate_string(&g_SCProperties.refreshToken,oc_string(rep->value.string));
        OC_DBG("[User specific property] %s : %s",
               STR_SC_RSRVD_ES_VENDOR_REFRESH_TOKEN,
               oc_string(pCloudProp->refreshToken));
      }

      read_tnc_data(payload,userdata);
      rep=rep->next;
    }
  }
}

void WriteUserdataCb(oc_rep_t* payload, char* resourceType)
{
  if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_EASYSETUP)) {
    set_custom_property_int(root, SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE,
                            (int)g_SCProperties.netConnectionState);
  }

  if (strstr(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF)) {
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_DEVICE_TYPE,
                            oc_string(g_SCProperties.deviceType));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE,
                            oc_string(g_SCProperties.deviceSubType));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV,
                            oc_string(g_SCProperties.regSetDev));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV,
                            oc_string(g_SCProperties.regMobileDev));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO,
                            oc_string(g_SCProperties.nwProvInfo));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_SSO_LIST,
                            oc_string(g_SCProperties.ssoList));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_PNP_PIN,
                            oc_string(g_SCProperties.pnpPin));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_MODEL_NUMBER,
                            oc_string(g_SCProperties.modelNumber));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_COUNTRY,
                            oc_string(g_SCProperties.country));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_LANGUAGE,
                            oc_string(g_SCProperties.language));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_GPSLOCATION,
                            oc_string(g_SCProperties.gpsLocation));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_UTC_DATE_TIME,
                            oc_string(g_SCProperties.utcDateTime));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME,
                            oc_string(g_SCProperties.regionalDateTime));
    set_custom_property_str(root, SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION,
                            oc_string(g_SCProperties.esProtocolVersion));
  }

  write_tnc_data(payload, resourceType);
  write_wifi_data(payload, resourceType);
}
