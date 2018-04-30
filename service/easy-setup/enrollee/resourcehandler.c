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

#include "easysetup.h"
#include "resourcehandler.h"
#include "es_utils.h"
#include "oc_log.h"
#include "oc_collection.h"

easy_setup_resource g_ESEasySetupResource;
wifi_conf_resource g_ESWiFiConfResource;
coap_cloud_conf_resource g_ESCoapCloudConfResource;
dev_conf_resource g_ESDevConfResource;

es_connect_request_cb gConnectRequestEvtCb = NULL;
es_wifi_conf_cb gWifiConfRsrcEvtCb = NULL;
es_coap_cloud_conf_cb gCoapCloudConfRsrcEvtCb = NULL;
es_dev_conf_cb gDevConfRsrcEvtCb = NULL;

es_read_userdata_cb gReadUserdataCb = NULL;
es_write_userdata_cb gWriteUserdataCb = NULL;

bool oc_compare_property(oc_rep_t *rep, char *property_name)
{
    int prop_len = strlen(property_name);
    if ((int)oc_string_len(rep->name) == prop_len &&
         memcmp(oc_string(rep->name), property_name, prop_len) == 0) {
        return true;
    }
    return false;
}

void update_wifi_conf_resource(oc_request_t *request, oc_interface_mask_t interface)
{
    OC_DBG("in");

    (void)interface;
    es_wifi_conf_data wifi_data;

    memset(wifi_data.ssid, 0, OC_STRING_MAX_VALUE);
    memset(wifi_data.pwd, 0, OC_STRING_MAX_VALUE);
    wifi_data.authtype = NONE_AUTH;
    wifi_data.enctype = NONE_AUTH;
    wifi_data.userdata = NULL;

    bool bIsValid = false;

    oc_rep_t *rep   = request->request_payload;
    while(rep != NULL) {
        OC_DBG("key %s", oc_string(rep->name));
        switch (rep->type) {
            case OC_REP_STRING:
            {
                if(oc_compare_property(rep, OC_RSRVD_ES_SSID)) {
                    if (oc_string_len(rep->value.string) > 0) {
                        oc_strncpy(g_ESWiFiConfResource.ssid, oc_string(rep->value.string),
                                   sizeof(g_ESWiFiConfResource.ssid));
                        oc_strncpy(wifi_data.ssid, oc_string(rep->value.string),
                                   sizeof(wifi_data.ssid));
                        OC_DBG("g_ESWiFiConfResource.ssid : %s", g_ESWiFiConfResource.ssid);
                        bIsValid = true;
                    }
                } else if (oc_compare_property(rep, OC_RSRVD_ES_CRED)) {
                    if (oc_string_len(rep->value.string) > 0) {
                        oc_strncpy(g_ESWiFiConfResource.cred, oc_string(rep->value.string),
                                   sizeof(g_ESWiFiConfResource.cred));
                        oc_strncpy(wifi_data.pwd, oc_string(rep->value.string),
                                   sizeof(wifi_data.pwd));
                        OC_DBG("g_ESWiFiConfResource.cred : %s", g_ESWiFiConfResource.cred);
                        bIsValid = true;
                    }
                }
            }
            break;
            case OC_REP_INT:
            {
                if (oc_compare_property(rep, OC_RSRVD_ES_AUTHTYPE)) {
                    g_ESWiFiConfResource.auth_type = rep->value.integer;
                    wifi_data.authtype = g_ESWiFiConfResource.auth_type;
                    OC_DBG("g_ESWiFiConfResource.auth_type %u", g_ESWiFiConfResource.auth_type);
                    bIsValid = true;
                } else if (oc_compare_property(rep, OC_RSRVD_ES_ENCTYPE)) {
                    g_ESWiFiConfResource.enc_type = rep->value.integer;
                    wifi_data.enctype = g_ESWiFiConfResource.enc_type;
                    OC_DBG("g_ESWiFiConfResource.enc_type %u", g_ESWiFiConfResource.enc_type);
                    bIsValid = true;
                }
            }
            break;
            default:
            break;
        }
        rep = rep->next;
    }

    if (gReadUserdataCb) {
        gReadUserdataCb(rep, OC_RSRVD_ES_RES_TYPE_WIFICONF, &wifi_data.userdata);
    }

    if (bIsValid) {
        OC_DBG("Send WiFiConfRsrc Callback To ES");

        if(gWifiConfRsrcEvtCb != NULL) {
            gWifiConfRsrcEvtCb(ES_OK, &wifi_data);
        } else {
            OC_ERR("gWifiConfRsrcEvtCb is NULL");
        }
    } else {
        OC_ERR("wifi conf received payload is invalid");
    }

    if (0 == oc_notify_observers(g_ESWiFiConfResource.handle)) {
        OC_DBG("Enrollee doesn't have any observers for wifi RESOURCE.");
    }

    OC_DBG("out");
}

void update_coap_cloud_conf_resource(oc_request_t *request, oc_interface_mask_t interface)
{
    OC_DBG("in");

    (void)interface;
    es_coap_cloud_conf_data cloud_data;

    memset(cloud_data.auth_code, 0, OC_STRING_MAX_VALUE);
    memset(cloud_data.access_token, 0, OC_STRING_MAX_VALUE);
    g_ESCoapCloudConfResource.access_token_type = NONE_OAUTH_TOKENTYPE;
    memset(cloud_data.auth_provider, 0, OC_STRING_MAX_VALUE);
    memset(cloud_data.ci_server, 0, OC_STRING_MAX_VALUE);
    cloud_data.userdata = NULL;

    int bIsValid = false;

    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
        OC_DBG("key %s", oc_string(rep->name));
        switch (rep->type) {
            case OC_REP_STRING:
            {
                if (oc_compare_property(rep, OC_RSRVD_ES_AUTHCODE)) {
                    if (oc_string_len(rep->value.string) > 0) {
                        oc_strncpy(g_ESCoapCloudConfResource.auth_code, oc_string(rep->value.string),
                                   sizeof(g_ESCoapCloudConfResource.auth_code));
                        oc_strncpy(cloud_data.auth_code, oc_string(rep->value.string),
                                   sizeof(cloud_data.auth_code));
                        OC_DBG("g_ESCoapCloudConfResource.auth_code : %s", g_ESCoapCloudConfResource.auth_code);
                        bIsValid = true;
                    }
                } else if (oc_compare_property(rep, OC_RSRVD_ES_ACCESSTOKEN)) {
                    if (oc_string_len(rep->value.string) > 0) {
                        oc_strncpy(g_ESCoapCloudConfResource.access_token, oc_string(rep->value.string),
                                   sizeof(g_ESCoapCloudConfResource.access_token));
                        oc_strncpy(cloud_data.access_token, oc_string(rep->value.string),
                                   sizeof(cloud_data.access_token));
                        OC_DBG("g_ESCoapCloudConfResource.access_token : %s", g_ESCoapCloudConfResource.access_token);
                        bIsValid = true;
                    }
                } else if (oc_compare_property(rep, OC_RSRVD_ES_AUTHPROVIDER)) {
                    if (oc_string_len(rep->value.string) > 0) {
                        oc_strncpy(g_ESCoapCloudConfResource.auth_provider, oc_string(rep->value.string),
                                   sizeof(g_ESCoapCloudConfResource.auth_provider));
                        oc_strncpy(cloud_data.auth_provider, oc_string(rep->value.string),
                                   sizeof(cloud_data.auth_provider));
                        OC_DBG("g_ESCoapCloudConfResource.auth_provider : %s", g_ESCoapCloudConfResource.auth_provider);
                        bIsValid = true;
                    }
                } else if (oc_compare_property(rep, OC_RSRVD_ES_CISERVER)) {
                    if (oc_string_len(rep->value.string) > 0) {
                        oc_strncpy(g_ESCoapCloudConfResource.ci_server, oc_string(rep->value.string),
                                   sizeof(g_ESCoapCloudConfResource.ci_server));
                        oc_strncpy(cloud_data.ci_server, oc_string(rep->value.string),
                                   sizeof(cloud_data.ci_server));
                        OC_DBG("g_ESCoapCloudConfResource.ci_server : %s", g_ESCoapCloudConfResource.ci_server);
                        bIsValid = true;
                    }
                }
            }
            break;
            case OC_REP_INT:
            {
                if(oc_compare_property(rep, OC_RSRVD_ES_ACCESSTOKEN_TYPE)) {
                    g_ESCoapCloudConfResource.access_token_type = rep->value.integer;
                    cloud_data.access_token_type = g_ESCoapCloudConfResource.access_token_type;
                    OC_DBG("g_ESCoapCloudConfResource.access_token_type %u", g_ESCoapCloudConfResource.access_token_type);
                    bIsValid = true;
                }
            }
            break;
            default:
            break;
        }
        rep = rep->next;
    }

    if (gReadUserdataCb) {
        gReadUserdataCb(rep, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF, &cloud_data.userdata);
    }

    if (bIsValid) {
        OC_DBG("Send CoapCloudConfRsrc Callback To ES");

        if(gCoapCloudConfRsrcEvtCb) {
            gCoapCloudConfRsrcEvtCb(ES_OK, &cloud_data);
        } else {
            OC_ERR("gCoapCloudConfRsrcEvtCb is NULL");
        }
    }

    if (0 == oc_notify_observers(g_ESCoapCloudConfResource.handle)) {
        OC_DBG("Enrollee doesn't have any observers for cloud conf RESOURCE.");
    }

    OC_DBG("out");
}

void update_devconf_resource(oc_request_t *request, oc_interface_mask_t interface)
{
    OC_DBG("in");

    (void)interface;
    es_dev_conf_data dev_conf_data;
    dev_conf_data.userdata = NULL;

    if (gReadUserdataCb) {
        gReadUserdataCb(request->request_payload, OC_RSRVD_ES_RES_TYPE_DEVCONF, &dev_conf_data.userdata);
    }

    if (dev_conf_data.userdata != NULL) {
        OC_DBG("Send DevConfRsrc Callback To ES");

        if(gDevConfRsrcEvtCb != NULL) {
            gDevConfRsrcEvtCb(ES_OK, &dev_conf_data);
        } else {
            OC_ERR("gDevConfRsrcEvtCb is NULL");
        }
    }

    if (0 == oc_notify_observers(g_ESDevConfResource.handle)) {
        OC_DBG("Enrollee doesn't have any observers for dev conf RESOURCE.");
    }
    OC_DBG("out");
}

void update_easysetup_resource(oc_request_t *request, oc_interface_mask_t interface)
{
    OC_DBG("in");
    OC_DBG("g_ESEasySetupResource.status %d", g_ESEasySetupResource.status);

    (void)interface;

    oc_rep_t *rep = request->request_payload;

    while (rep != NULL) {
        OC_DBG("key %s", oc_string(rep->name));
        switch (rep->type) {
            case OC_REP_INT_ARRAY:
            {
                if (oc_compare_property(rep, OC_RSRVD_ES_CONNECT)) {
                    int i=0;
                    int connect_req_size = (int)oc_int_array_size(rep->value.array);
                    int *connect_req = oc_int_array(rep->value.array);
                    es_connect_request connect_request ;
                    for (i = 0; i < (int)oc_int_array_size(rep->value.array); i++) {
                        OC_DBG("(%d %d) ", i, connect_req[i]);
                    }

                    memset(&connect_request, 0, sizeof(es_connect_request));
                    int cnt_request = 0;
                    for (int i = 0 ; i < NUM_CONNECT_TYPE ; ++i) {
                        g_ESEasySetupResource.connect_request[i] = ES_CONNECT_NONE;
                        connect_request.connect[i] = ES_CONNECT_NONE;

                        if (i < connect_req_size &&
                            (connect_req[i] == ES_CONNECT_WIFI ||
                            connect_req[i] == ES_CONNECT_COAPCLOUD)) {
                            g_ESEasySetupResource.connect_request[cnt_request] = connect_req[i];
                            connect_request.connect[cnt_request] = connect_req[i];
                            OC_DBG("g_ESEasySetupResource.connectType[%d] : %d",
                                    cnt_request, g_ESEasySetupResource.connect_request[cnt_request]);
                            cnt_request++;
                        }
                    }

                    connect_request.num_request = cnt_request;
                    g_ESEasySetupResource.num_request = cnt_request;

                    if (g_ESEasySetupResource.connect_request[0] != ES_CONNECT_NONE)
                    {
                        OC_DBG("Send ConnectRequest Callback To ES");

                        if(gConnectRequestEvtCb != NULL) {
                            gConnectRequestEvtCb(ES_OK, &connect_request);
                        } else {
                            OC_ERR("gConnectRequestEvtCb is NULL");
                        }
                    }
                }
            }
            break;
            default:
            break;
        }
        rep = rep->next;
    }

    OC_DBG("out");
}

es_result_e construct_response_of_coapcloudconf(void)
{
    OC_DBG("in");

    if(g_ESCoapCloudConfResource.handle == NULL) {
        OC_ERR("WiFiConf resource is not created");
        return ES_ERROR;
    }

    oc_rep_start_root_object();

    ///TODO: Call this only when interface is baseline
    oc_process_baseline_interface(g_ESCoapCloudConfResource.handle);

    oc_rep_set_text_string(root, ac, g_ESCoapCloudConfResource.auth_code);
    oc_rep_set_text_string(root, at, g_ESCoapCloudConfResource.access_token);
    oc_rep_set_int(root, att, g_ESCoapCloudConfResource.access_token_type);
    oc_rep_set_text_string(root, apn, g_ESCoapCloudConfResource.auth_provider);
    oc_rep_set_text_string(root, cis, g_ESCoapCloudConfResource.ci_server);

    if(gWriteUserdataCb) {
        gWriteUserdataCb(NULL, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
    }

    oc_rep_end_root_object();
    OC_DBG("out");
    return ES_OK;
}

es_result_e construct_response_of_wificonf(void)
{
    OC_DBG("in");

    if(g_ESWiFiConfResource.handle == NULL) {
        OC_ERR("WiFiConf resource is not created");
        return ES_ERROR;
    }

    oc_rep_start_root_object();
    oc_process_baseline_interface(g_ESWiFiConfResource.handle);

    oc_rep_set_array(root, swmt);
    for (int i = 0; i< g_ESWiFiConfResource.num_mode; i++) {
        oc_rep_add_int(swmt, (int)g_ESWiFiConfResource.supported_mode[i]);
    }

    oc_rep_close_array(root, swmt);
    oc_rep_set_int(root, swf, (int)g_ESWiFiConfResource.supported_freq);
    oc_rep_set_text_string(root, tnn, g_ESWiFiConfResource.ssid);
    oc_rep_set_text_string(root, cd, g_ESWiFiConfResource.cred);
    oc_rep_set_int(root, wat, (int)g_ESWiFiConfResource.auth_type);
    oc_rep_set_int(root, wet, (int)g_ESWiFiConfResource.enc_type);

    if(gWriteUserdataCb) {
        gWriteUserdataCb(NULL, OC_RSRVD_ES_RES_TYPE_WIFICONF);
    }

    oc_rep_end_root_object();

    OC_DBG("construct_response_of_wificonf out");
    return ES_OK;
}

es_result_e construct_response_of_devconf(void)
{
    OC_DBG("construct_response_of_devconf in");

    if(g_ESDevConfResource.handle == NULL) {
        OC_ERR("DevConf resource is not created");
        return ES_ERROR;
    }

    oc_rep_start_root_object();
    oc_process_baseline_interface(g_ESDevConfResource.handle);
    oc_rep_set_text_string(root, dn, g_ESDevConfResource.dev_name);

    if(gWriteUserdataCb) {
        gWriteUserdataCb(NULL, OC_RSRVD_ES_RES_TYPE_DEVCONF);
    }

    oc_rep_end_root_object();
    OC_DBG("out");
    return ES_OK;
}

es_result_e set_callback_for_userdata(es_read_userdata_cb readcb, es_write_userdata_cb writecb)
{
    OC_DBG("in");
    if (!readcb && !writecb) {
        OC_ERR("Both of callbacks for user data are Null");
        return ES_ERROR;
    }
    gReadUserdataCb = readcb;
    gWriteUserdataCb = writecb;
    OC_DBG("out");
    return ES_OK;
}

void resgister_wifi_rsrc_event_callback(es_wifi_conf_cb cb)
{
    OC_DBG("in");
    gWifiConfRsrcEvtCb = cb;
    OC_DBG("out");
}

void register_cloud_rsrc_event_callback(es_coap_cloud_conf_cb cb)
{
    OC_DBG("in");
    gCoapCloudConfRsrcEvtCb = cb;
    OC_DBG("out");
}

void register_devconf_rsrc_event_callback(es_dev_conf_cb cb)
{
    OC_DBG("in");
    gDevConfRsrcEvtCb = cb;
    OC_DBG("out");
}

void register_connect_request_event_callback(es_connect_request_cb cb)
{
    OC_DBG("in");
    gConnectRequestEvtCb = cb;
    OC_DBG("out");
}

void unregister_resource_event_callback(void)
{
    OC_DBG("in");
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
    OC_DBG("out");
}

static void get_devconf(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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

static void post_devconf(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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

static void get_cloud(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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

static void post_cloud(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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

static void get_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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

static void post_wifi(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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

static void get_easysetup(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
    (void)request;
    (void)interface;
    (void)user_data;

    OC_DBG("in");

    oc_rep_start_root_object();
    oc_rep_set_int(root, ps, 0);
    oc_rep_set_int(root, lec, 0);
    oc_rep_end_root_object();

    OC_DBG("out");
}

static void post_easysetup(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;

  OC_DBG("in");

  OC_DBG("interface = %d", interface);


  ///TODO: Check below comment:
  // RI stack is sending default interface i.e. oic.if.ll for collection in request.
  // For time being ignoring the error response sending due to wrong interface.
  // It should be fixed in RI stack by sending interface received in request.

  //if ((interface == OC_IF_B) || (interface == OC_IF_BASELINE)) {
    update_easysetup_resource(request, interface);
    OC_DBG("success");
    oc_send_response(request, OC_STATUS_CHANGED);
  //} else {
    //OC_ERR("Error");
    //oc_send_response(request, OC_STATUS_BAD_REQUEST);
  //}
  OC_DBG("out");
}

es_result_e init_easysetup_resource(bool is_secured)
{
    OC_DBG("in");

#ifndef OC_SECURITY
    (void)is_secured;
#endif
    g_ESEasySetupResource.status = ES_STATE_INIT;
    g_ESEasySetupResource.last_err_code = ES_ERRCODE_NO_ERROR;

    for( int i = 0 ; i < NUM_CONNECT_TYPE ; ++i ) {
        g_ESEasySetupResource.connect_request[i] = ES_CONNECT_NONE;
    }
    g_ESEasySetupResource.num_request = 0;
    oc_resource_t *col = oc_new_collection("easysetup", OC_RSRVD_ES_URI_EASYSETUP, 2, 0);

    if (NULL == col) {
        OC_ERR("Error in creating WiFiConf Resource!");
        return ES_ERROR;
    }

    oc_resource_bind_resource_type(col, OC_RSRVD_ES_RES_TYPE_EASYSETUP);
    oc_resource_bind_resource_type(col, "oic.wk.col");
    oc_resource_bind_resource_interface(col,OC_IF_LL);
    oc_resource_bind_resource_interface(col,OC_IF_B);
    oc_resource_set_discoverable(col, true);
    oc_resource_set_observable(col, true);
    oc_resource_set_request_handler(col, OC_GET, get_easysetup, NULL);
    oc_resource_set_request_handler(col, OC_POST, post_easysetup, NULL);

#ifdef OC_SECURITY
    if(!is_secured) {
        oc_resource_make_public(col);
    }
#endif
    /** Add Self Link for Easy Setup Resource */
    oc_link_t *l_es = oc_new_link(col);
    oc_collection_add_link(col, l_es);

    if (g_ESWiFiConfResource.handle != NULL) {
        oc_link_t *l1 = oc_new_link(g_ESWiFiConfResource.handle);
        oc_collection_add_link(col, l1);
    } else {
        OC_ERR("wifi resource is not added to collection resource");
    }

    if (g_ESCoapCloudConfResource.handle != NULL) {
        oc_link_t *l2 = oc_new_link(g_ESCoapCloudConfResource.handle);
        oc_collection_add_link(col, l2);
    } else {
        OC_ERR("cloud config is not added to collection resource");
    }

    if (g_ESDevConfResource.handle != NULL) {
        oc_link_t *l3 = oc_new_link(g_ESDevConfResource.handle);
        oc_collection_add_link(col, l3);
    } else {
        OC_ERR("dev config is not added to collection resource");
    }

    oc_add_collection(col);

    g_ESEasySetupResource.handle = col;
    OC_DBG("Created EasySetup Resource with success");
    return ES_OK;
}

es_result_e init_wifi_conf_resource(bool is_secured)
{
    OC_DBG("in");

#ifndef OC_SECURITY
    (void)is_secured;
#endif
    g_ESWiFiConfResource.supported_freq = WIFI_BOTH;
    g_ESWiFiConfResource.supported_mode[0] = WIFI_11A;
    g_ESWiFiConfResource.supported_mode[1] = WIFI_11B;
    g_ESWiFiConfResource.supported_mode[2] = WIFI_11G;
    g_ESWiFiConfResource.supported_mode[3] = WIFI_11N;
    g_ESWiFiConfResource.num_mode = 4;
    g_ESWiFiConfResource.auth_type = NONE_AUTH;
    g_ESWiFiConfResource.enc_type = NONE_ENC;

    memset(g_ESWiFiConfResource.ssid, 0, sizeof(g_ESWiFiConfResource.ssid));
    memset(g_ESWiFiConfResource.cred, 0, sizeof(g_ESWiFiConfResource.cred));

    oc_resource_t *wifi = oc_new_resource("wifi", OC_RSRVD_ES_URI_WIFICONF, 1, 0);

    if (NULL == wifi) {
        OC_ERR("Error in creating WiFiConf Resource!");
        return ES_ERROR;
    }

    oc_resource_bind_resource_type(wifi, OC_RSRVD_ES_RES_TYPE_WIFICONF);
    oc_resource_set_discoverable(wifi, true);
    oc_resource_set_observable(wifi, true);

#ifdef OC_SECURITY
    if(!is_secured) {
        oc_resource_make_public(wifi);
    }
#endif

    oc_resource_set_request_handler(wifi, OC_GET, get_wifi, NULL);
    oc_resource_set_request_handler(wifi, OC_POST, post_wifi, NULL);
    oc_add_resource(wifi);

    g_ESWiFiConfResource.handle = wifi;
    OC_DBG("Created WiFiConf Resource with success");
    return ES_OK;
}

es_result_e init_coap_cloudconf_resource(bool is_secured)
{
#ifndef OC_SECURITY
    (void)is_secured;
#endif
    memset(g_ESCoapCloudConfResource.auth_code, 0, sizeof(g_ESCoapCloudConfResource.auth_code));
    memset(g_ESCoapCloudConfResource.access_token, 0, sizeof(g_ESCoapCloudConfResource.access_token));
    g_ESCoapCloudConfResource.access_token_type = NONE_OAUTH_TOKENTYPE;
    memset(g_ESCoapCloudConfResource.auth_provider, 0, sizeof(g_ESCoapCloudConfResource.auth_provider));
    memset(g_ESCoapCloudConfResource.ci_server, 0, sizeof(g_ESCoapCloudConfResource.ci_server));

    oc_resource_t *cloud = oc_new_resource("cloud", OC_RSRVD_ES_URI_COAPCLOUDCONF, 1, 0);

    if (NULL == cloud) {
        OC_ERR("Error in creating WiFiConf Resource!");
        return ES_ERROR;
    }

    oc_resource_bind_resource_type(cloud, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF);
    oc_resource_set_discoverable(cloud, true);
    oc_resource_set_observable(cloud, true);
#ifdef OC_SECURITY
    if(!is_secured) {
        oc_resource_make_public(cloud);
    }
#endif
    oc_resource_set_request_handler(cloud, OC_GET, get_cloud, NULL);
    oc_resource_set_request_handler(cloud, OC_POST, post_cloud, NULL);
    oc_add_resource(cloud);
    g_ESCoapCloudConfResource.handle = cloud;

    OC_DBG("Created CoapCloudConf Resource success");
    return ES_OK;

}

es_result_e init_devconf_resource(bool is_secured)
{
#ifndef OC_SECURITY
    (void)is_secured;
#endif
    memset(g_ESDevConfResource.dev_name, 0, sizeof(g_ESDevConfResource.dev_name));

    oc_resource_t *devconf = oc_new_resource("devconf", OC_RSRVD_ES_URI_DEVCONF, 1, 0);

    if (NULL == devconf) {
        OC_ERR("Error in creating WiFiConf Resource!");
        return ES_ERROR;
    }

    oc_resource_bind_resource_type(devconf, OC_RSRVD_ES_RES_TYPE_DEVCONF);
    oc_resource_set_discoverable(devconf, true);
    oc_resource_set_observable(devconf, true);
#ifdef OC_SECURITY
    if(!isSecured) {
        oc_resource_make_public(devconf);
    }
#endif
    oc_resource_set_request_handler(devconf, OC_GET, get_devconf, NULL);
    oc_resource_set_request_handler(devconf, OC_POST, post_devconf, NULL);
    oc_add_resource(devconf);
    g_ESDevConfResource.handle = devconf;
    OC_DBG("Created DevConf Resource with success");
    return ES_OK;
}

es_result_e create_easysetup_resources(bool is_secured, es_resource_mask_e resource_mask)
{
    OC_DBG("in");
    es_result_e res = ES_ERROR;
    bool mask_flag = false;

    if((resource_mask & ES_WIFICONF_RESOURCE) == ES_WIFICONF_RESOURCE) {
        mask_flag = true;
        res = init_wifi_conf_resource(is_secured);
        if(res != ES_OK) {
            OC_DBG("initWiFiConfResource result: failed");
            return res;
        }
    }

    if((resource_mask & ES_COAPCLOUDCONF_RESOURCE) == ES_COAPCLOUDCONF_RESOURCE) {
        mask_flag = true;
        res = init_coap_cloudconf_resource(is_secured);
        if(res != ES_OK) {
            OC_ERR("initCoapCloudConfResource result: failed");
            return res;
        }
    }

    if((resource_mask & ES_DEVCONF_RESOURCE) == ES_DEVCONF_RESOURCE) {
        mask_flag = true;
        res = init_devconf_resource(is_secured);
        if(res != ES_OK) {
            OC_ERR("initDevConf result: failed");
            return res;
        }
    }

    if(mask_flag == false) {
        OC_ERR("Invalid ResourceMask");
        return ES_ERROR;
    } else {
        res = init_easysetup_resource(is_secured);
        if(res != ES_OK) {
            OC_ERR("initEasySetupResource result: failed");
            return res;
        }
    }

    OC_DBG("Created all resources with result: success");
    OC_DBG("out");
    return ES_OK;
}

es_result_e delete_easysetup_resources()
{
    OC_DBG("in");
    if (g_ESEasySetupResource.handle != NULL) {
        oc_delete_collection(g_ESEasySetupResource.handle);
        g_ESEasySetupResource.handle = NULL;
    }

    if (g_ESWiFiConfResource.handle != NULL) {
        oc_delete_resource(g_ESWiFiConfResource.handle);
        g_ESWiFiConfResource.handle = NULL;
    }

    if (g_ESCoapCloudConfResource.handle != NULL) {
        oc_delete_resource(g_ESCoapCloudConfResource.handle);
        g_ESCoapCloudConfResource.handle = NULL;
    }

    if (g_ESDevConfResource.handle != NULL) {
        oc_delete_resource(g_ESDevConfResource.handle);
        g_ESDevConfResource.handle = NULL;
    }

    OC_DBG("out");
    return ES_OK;
}

es_result_e set_device_property(es_device_property *device_property)
{
    OC_DBG("in");

    g_ESWiFiConfResource.supported_freq = (device_property->WiFi).supported_freq;
    OC_DBG("WiFi Freq : %d", g_ESWiFiConfResource.supported_freq);

    int modeIdx = 0;
    while((device_property->WiFi).supported_mode[modeIdx] != WiFi_EOF) {
        g_ESWiFiConfResource.supported_mode[modeIdx] = (device_property->WiFi).supported_mode[modeIdx];
        OC_DBG("WiFi Mode : %d", g_ESWiFiConfResource.supported_mode[modeIdx]);
        modeIdx ++;
    }
    g_ESWiFiConfResource.num_mode = modeIdx;

    oc_strncpy(g_ESDevConfResource.dev_name, (device_property->DevConf).device_name, OC_STRING_MAX_VALUE);
    OC_DBG("Device Name : %s", g_ESDevConfResource.dev_name);

    if (0 == oc_notify_observers(g_ESWiFiConfResource.handle)) {
        OC_DBG("wifiResource doesn't have any observers.");
    }

    if (0 == oc_notify_observers(g_ESDevConfResource.handle)) {
        OC_DBG("devConfResource doesn't have any observers.");
    }

    OC_DBG("out");
    return ES_OK;
}

es_result_e set_enrollee_state(es_enrollee_state es_state)
{
    OC_DBG("set_enrollee_state in");

    g_ESEasySetupResource.status = es_state;
    OC_DBG("Enrollee Status : %d", g_ESEasySetupResource.status);

    if (0 == oc_notify_observers(g_ESEasySetupResource.handle)) {
        OC_DBG("provResource doesn't have any observers.");
    }

    OC_DBG("set_enrollee_state out");
    return ES_OK;
}

es_result_e set_enrollee_err_code(es_error_code es_err_code)
{
    OC_DBG("set_enrollee_err_code in");

    g_ESEasySetupResource.last_err_code = es_err_code;
    OC_DBG("Enrollee ErrorCode : %d", g_ESEasySetupResource.last_err_code);

    if (0 == oc_notify_observers(g_ESEasySetupResource.handle)) {
        OC_DBG("provResource doesn't have any observers.");
    }

    OC_DBG("set_enrollee_err_code out");
    return ES_OK;
}
