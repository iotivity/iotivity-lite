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

/**
 * @file
 *
 * This file contains the implementation for EasySetup Enrollee device.
 */

#include "easysetup.h"
#include "oc_log.h"
#include "resourcehandler.h"

#include "es_utils.h"

static es_provisioning_callbacks_s g_es_provisioning_cb;
static es_device_property g_es_device_property;

void
es_connect_request_callback(es_result_e es_result,
                            es_connect_request *event_data)
{
  OC_DBG("in");

  if (es_result != ES_OK) {
    OC_ERR("es_connect_request_callback error occured");
    return;
  }

  if (g_es_provisioning_cb.connect_request_cb != NULL) {
    g_es_provisioning_cb.connect_request_cb(event_data);
  } else {
    OC_ERR("connect_request_cb is NULL");
    return;
  }
  OC_DBG("out");
}

void
es_wifi_conf_rsrc_callback(es_result_e es_result, es_wifi_conf_data *event_data)
{
  OC_DBG("in");

  if (es_result != ES_OK) {
    OC_ERR("erro_wifi_conf_rsrc_callback error occured");
    return;
  }

  if (g_es_provisioning_cb.wifi_prov_cb != NULL) {
    g_es_provisioning_cb.wifi_prov_cb(event_data);
  } else {
    OC_ERR("wifi_prov_cb is NULL");
    return;
  }
  OC_DBG("out");
}

void
es_coap_cloud_conf_rsrc_callback(es_result_e es_result,
                                 es_coap_cloud_conf_data *event_data)
{
  OC_DBG("in");

  if (es_result != ES_OK) {
    OC_ERR("es_coap_cloud_conf_rsrc_callback error occured");
    return;
  }

  if (g_es_provisioning_cb.cloud_data_prov_cb != NULL) {
    g_es_provisioning_cb.cloud_data_prov_cb(event_data);
  } else {
    OC_ERR("cloud_data_prov_cb is NULL");
    return;
  }
  OC_DBG("out");
}

void
es_dev_conf_rsrc_callback(es_result_e es_result, es_dev_conf_data *event_data)
{
  OC_DBG("in");

  if (es_result != ES_OK) {
    OC_ERR("es_dev_conf_rsrc_callback error occured");
    return;
  }

  if (g_es_provisioning_cb.dev_conf_prov_cb != NULL) {
    g_es_provisioning_cb.dev_conf_prov_cb(event_data);
  } else {
    OC_ERR("dev_conf_prov_cb is NULL");
    return;
  }
  OC_DBG("out");
}

es_result_e
es_init_enrollee(bool is_secured, es_resource_mask_e resource_mask,
                 es_provisioning_callbacks_s callbacks)
{
  OC_DBG("in");

  if ((resource_mask & ES_WIFICONF_RESOURCE) == ES_WIFICONF_RESOURCE) {
    if (callbacks.wifi_prov_cb != NULL) {
      g_es_provisioning_cb.wifi_prov_cb = callbacks.wifi_prov_cb;
      resgister_wifi_rsrc_event_callback(es_wifi_conf_rsrc_callback);
    } else {
      OC_ERR("wifi_prov_cb is NULL");
      return ES_ERROR;
    }
  }

  if ((resource_mask & ES_DEVCONF_RESOURCE) == ES_DEVCONF_RESOURCE) {
    if (callbacks.dev_conf_prov_cb != NULL) {
      g_es_provisioning_cb.dev_conf_prov_cb = callbacks.dev_conf_prov_cb;
      register_devconf_rsrc_event_callback(es_dev_conf_rsrc_callback);
    } else {
      OC_ERR("dev_conf_prov_cb is NULL");
      return ES_ERROR;
    }
  }

  if ((resource_mask & ES_COAPCLOUDCONF_RESOURCE) ==
      ES_COAPCLOUDCONF_RESOURCE) {
    if (callbacks.cloud_data_prov_cb != NULL) {
      g_es_provisioning_cb.cloud_data_prov_cb = callbacks.cloud_data_prov_cb;
      register_cloud_rsrc_event_callback(es_coap_cloud_conf_rsrc_callback);
    } else {
      OC_ERR("cloud_data_prov_cb is NULL");
      return ES_ERROR;
    }
  }

  if (callbacks.connect_request_cb != NULL) {
    g_es_provisioning_cb.connect_request_cb = callbacks.connect_request_cb;
    register_connect_request_event_callback(es_connect_request_callback);
  }

  if (ES_OK != create_easysetup_resources(is_secured, resource_mask)) {
    unregister_resource_event_callback();

    if (ES_OK != delete_easysetup_resources()) {
      OC_ERR("deleting prov resource error!!");
    }
    return ES_ERROR;
  }
  OC_DBG("out");
  return ES_OK;
}

es_result_e
es_set_device_property(es_device_property *device_property)
{
  OC_DBG("in");

  if (ES_OK != set_device_property(device_property)) {
    OC_ERR("es_set_device_property Error");
    return ES_ERROR;
  }

  int modeIdx = 0;
  while ((device_property->WiFi).supported_mode[modeIdx] != WiFi_EOF) {
    (g_es_device_property.WiFi).supported_mode[modeIdx] =
      (device_property->WiFi).supported_mode[modeIdx];
    OC_DBG("WiFi Mode : %d",
           (g_es_device_property.WiFi).supported_mode[modeIdx]);
    modeIdx++;
  }

  (g_es_device_property.WiFi).supported_freq =
    (device_property->WiFi).supported_freq;
  OC_DBG("WiFi Freq : %d", (g_es_device_property.WiFi).supported_freq);

  oc_strncpy((g_es_device_property.DevConf).device_name,
             (device_property->DevConf).device_name, OC_STRING_MAX_VALUE);
  OC_DBG("Device Name : %s", (g_es_device_property.DevConf).device_name);

  OC_DBG("out");
  return ES_OK;
}

es_result_e
es_set_state(es_enrollee_state es_state)
{
  OC_DBG("in");

  if (es_state < ES_STATE_INIT || es_state >= ES_STATE_EOF) {
    OC_ERR("Invalid es_set_state : %d", es_state);
    return ES_ERROR;
  }

  if (ES_OK != set_enrollee_state(es_state)) {
    OC_ERR("es_set_state ES_ERROR");
    return ES_ERROR;
  }

  OC_DBG("set es_state succesfully : %d", es_state);
  OC_DBG("out");
  return ES_OK;
}

es_result_e
es_set_error_code(es_error_code es_err_code)
{
  OC_DBG("in");

  if (es_err_code < ES_ERRCODE_NO_ERROR || es_err_code > ES_ERRCODE_UNKNOWN) {
    OC_ERR("Invalid es_set_error_code : %d", es_err_code);
    return ES_ERROR;
  }

  if (ES_OK != set_enrollee_err_code(es_err_code)) {
    OC_ERR("es_set_error_code ES_ERROR");
    return ES_ERROR;
  }

  OC_DBG("set es_err_code succesfully : %d", es_err_code);
  OC_DBG("out");
  return ES_OK;
}

es_result_e
es_terminate_enrollee()
{
  OC_DBG("in");

  unregister_resource_event_callback();

  if (ES_OK != delete_easysetup_resources()) {
    OC_ERR("deleting prov resource error!!");
    return ES_ERROR;
  }

  OC_DBG("success");
  return ES_OK;
}

es_result_e
es_set_callback_for_userdata(es_read_userdata_cb readcb,
                             es_write_userdata_cb writecb)
{
  OC_DBG("in");

  if (!readcb && !writecb) {
    OC_ERR("Both of callbacks for user data are Null");
    return ES_ERROR;
  }

  set_callback_for_userdata(readcb, writecb);
  OC_DBG("out");
  return ES_OK;
}
