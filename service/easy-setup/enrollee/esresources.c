/****************************************************************************
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

#include "esresources.h"
#include "estypes.h"
#include "oc_api.h"

es_connect_request_cb gConnectRequestEvtCb = NULL;
es_wifi_conf_cb gWifiConfRsrcEvtCb = NULL;
es_coap_cloud_conf_cb gCoapCloudConfRsrcEvtCb = NULL;
es_dev_conf_cb gDevConfRsrcEvtCb = NULL;

es_read_userdata_cb gReadUserdataCb = NULL;
es_write_userdata_cb gWriteUserdataCb = NULL;

es_result_e set_callback_for_userdata(es_read_userdata_cb readcb, es_write_userdata_cb writecb)
{
    if (!readcb && !writecb)
    {
        OC_ERR("Both of callbacks for user data are Null");
        return ES_ERROR;
    }
    gReadUserdataCb = readcb;
    gWriteUserdataCb = writecb;
    return ES_OK;
}

void resgister_wifi_rsrc_event_callback(es_wifi_conf_cb cb)
{
    gWifiConfRsrcEvtCb = cb;
}

void register_cloud_rsrc_event_callback(es_coap_cloud_conf_cb cb)
{
    gCoapCloudConfRsrcEvtCb = cb;
}

void register_devconf_rsrc_event_callback(es_dev_conf_cb cb)
{
    gDevConfRsrcEvtCb = cb;
}

void register_connect_request_event_callback(es_connect_request_cb cb)
{
    gConnectRequestEvtCb = cb;
}

void unregister_resource_event_callback(void)
{
    if (gWifiConfRsrcEvtCb) {
        gWifiConfRsrcEvtCb = NULL;
    }
    if (gCoapCloudConfRsrcEvtCb) {
        gCoapCloudConfRsrcEvtCb = NULL;
    }
    if (gDevConfRsrcEvtCb) {
        gDevConfRsrcEvtCb = NULL;
    }
    if (gConnectRequestEvtCb) {
        gConnectRequestEvtCb = NULL;
    }
}

static void get_devconf(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  OC_DBG("get_devconf");
}

static void post_devconf(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  OC_DBG("POST_devconf");
}

static void get_cloud(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  OC_DBG("get_cloud");
}

static void post_cloud(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  OC_DBG("post_cloud");
}

static void get_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  OC_DBG("get_wifi");
}

static void post_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  OC_DBG("post_wifi");
}

void create_easysetup_resources(void)
{
  oc_resource_t *wifi = oc_new_resource("wifi", OC_RSRVD_ES_URI_WIFICONF, 1, 0);
  oc_resource_bind_resource_type(wifi, OC_RSRVD_ES_RES_TYPE_WIFICONF);
  oc_resource_bind_resource_interface(wifi,OC_IF_BASELINE);
  oc_resource_set_default_interface(wifi, OC_IF_BASELINE);
  oc_resource_set_discoverable(wifi, true);
  oc_resource_set_periodic_observable(wifi, 1);
  oc_resource_set_request_handler(wifi, OC_GET, get_wifi, NULL);
  oc_resource_set_request_handler(wifi, OC_POST, post_wifi, NULL);
  oc_add_resource(wifi);

  oc_resource_t *cloud = oc_new_resource("cloud", OC_RSRVD_ES_URI_COAPCLOUDCONF, 1, 0);
  oc_resource_bind_resource_type(cloud, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
  oc_resource_bind_resource_interface(cloud,OC_IF_BASELINE);
  oc_resource_set_default_interface(cloud, OC_IF_BASELINE);
  oc_resource_set_discoverable(cloud, true);
  oc_resource_set_periodic_observable(cloud, 1);
  oc_resource_set_request_handler(cloud, OC_GET, get_cloud, NULL);
  oc_resource_set_request_handler(cloud, OC_POST, post_cloud, NULL);
  oc_add_resource(cloud);

  oc_resource_t *devconf = oc_new_resource("devconf", OC_RSRVD_ES_URI_DEVCONF, 1, 0);
  oc_resource_bind_resource_type(devconf, OC_RSRVD_ES_RES_TYPE_DEVCONF);
  oc_resource_bind_resource_interface(devconf,OC_IF_BASELINE);
  oc_resource_set_default_interface(devconf, OC_IF_BASELINE);
  oc_resource_set_discoverable(devconf, true);
  oc_resource_set_periodic_observable(devconf, 1);
  oc_resource_set_request_handler(devconf, OC_GET, get_devconf, NULL);
  oc_resource_set_request_handler(devconf, OC_POST, post_devconf, NULL);
  oc_add_resource(devconf);

#ifdef OC_COLLECTIONS
  oc_resource_t *col = oc_new_collection("easysetup", OC_RSRVD_ES_URI_EASYSETUP, 2, 0);
  oc_resource_bind_resource_type(col, OC_RSRVD_ES_RES_TYPE_EASYSETUP);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_bind_resource_interface(col,OC_IF_LL);
  oc_resource_bind_resource_interface(col,OC_IF_B);
  oc_resource_set_discoverable(col, true);
  oc_link_t *l1 = oc_new_link(wifi);
  oc_collection_add_link(col, l1);

  oc_link_t *l2 = oc_new_link(devconf);
  oc_collection_add_link(col, l2);

  oc_link_t *l3 = oc_new_link(cloud);
  oc_collection_add_link(col, l3);
  oc_add_collection(col);
#endif /* OC_COLLECTIONS */
}
