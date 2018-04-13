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
 * This file contains the implementation for EasySetup Enrollee device
 */

#include "enrolleecommon.h"
#include "estypes.h"
#include "easysetup.h"

static bool gIsSecured = false;

static es_provisioning_callbacks_s gESProvisioningCb;

void es_connect_request_callback (es_result_e es_result, es_connect_request *eventData)
{
    if (es_result != ES_OK) {
        return;
    }

    if (gESProvisioningCb.connect_request_cb != NULL) {
        gESProvisioningCb.connect_request_cb(eventData);
    }
}

void es_wifi_conf_rsrc_callback (es_result_e es_result, es_wifi_conf_data *eventData)
{
    if (es_result != ES_OK) {
        return;
    }

    if (gESProvisioningCb.wifi_prov_cb != NULL) {
        gESProvisioningCb.wifi_prov_cb(eventData);
    }
}

void es_coap_cloud_conf_rsrc_callback (es_result_e es_result, es_coap_cloud_conf_data *eventData)
{
    if (es_result != ES_OK) {
        return;
    }

    if (gESProvisioningCb.cloud_data_prov_cb != NULL) {
        gESProvisioningCb.cloud_data_prov_cb(eventData);
    }
}

void es_dev_conf_rsrc_callback (es_result_e es_result, es_dev_conf_data *eventData)
{
    if (es_result != ES_OK) {
        return;
    }

    if (gESProvisioningCb.dev_conf_prov_cb != NULL) {
        gESProvisioningCb.dev_conf_prov_cb(eventData);
    }
}

es_result_e es_init_enrollee (bool is_secured, es_resource_mask_e resource_mask, es_provisioning_callbacks_s callbacks)
{
    gIsSecured = is_secured;

    if ((resource_mask & ES_WIFICONF_RESOURCE) == ES_WIFICONF_RESOURCE) {
        if (callbacks.wifi_prov_cb != NULL) {
            gESProvisioningCb.wifi_prov_cb = callbacks.wifi_prov_cb;
            resgister_wifi_rsrc_event_callback(es_wifi_conf_rsrc_callback);
        }
        else {
            return ES_ERROR;
        }
    }
    if ((resource_mask & ES_DEVCONF_RESOURCE) == ES_DEVCONF_RESOURCE) {
        if (callbacks.dev_conf_prov_cb != NULL) {
            gESProvisioningCb.dev_conf_prov_cb = callbacks.dev_conf_prov_cb;
            register_devconf_rsrc_event_callback(es_dev_conf_rsrc_callback);
        }
        else {
            return ES_ERROR;
        }
    }
    if ((resource_mask & ES_COAPCLOUDCONF_RESOURCE) == ES_COAPCLOUDCONF_RESOURCE) {
        if (callbacks.cloud_data_prov_cb != NULL) {
            gESProvisioningCb.cloud_data_prov_cb = callbacks.cloud_data_prov_cb;
            register_cloud_rsrc_event_callback(es_coap_cloud_conf_rsrc_callback);
        }
        else {
            return ES_ERROR;
        }
    }

    if (callbacks.connect_request_cb != NULL) {
        gESProvisioningCb.connect_request_cb = callbacks.connect_request_cb;
        register_connect_request_event_callback(es_connect_request_callback);
    }

    create_easysetup_resources();

    return ES_OK;
}
