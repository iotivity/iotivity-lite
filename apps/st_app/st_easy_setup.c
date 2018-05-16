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

#include "st_easy_setup.h"
#include "oc_network_monitor.h"
#include "st_port.h"

typedef enum {
  ST_EASY_SETUP_DEV_PROV = 1 << 0,
  ST_EASY_SETUP_WIFI_PROV = 1 << 1,
  ST_EASY_SETUP_CLOUD_PROV = 1 << 2
} st_prov_step_t;

/**
 * @var g_is_secured
 * @brief Variable to check if secure mode is enabled or not.
 */
#ifdef OC_SECURITY
static bool g_is_secured = true;
#else  /* OC_SECURITY */
static bool g_is_secured = false;
#endif /* !OC_SECURITY */

static st_soft_ap_t g_soft_ap;

static st_easy_setup_cb_t g_callback = NULL;

static st_easy_setup_status_t g_easy_setup_status = EASY_SETUP_INITIALIZE;

static es_coap_cloud_conf_data g_cloud_info;

static sc_coap_cloud_server_conf_properties g_st_cloud_info;

static bool is_have_st_cloud_info = false;

static st_prov_step_t g_prov_step_check;

static es_wifi_conf_data g_wifi_conf_data;

// static void soft_ap_handler(void);
static void wifi_prov_cb(es_wifi_conf_data *event_data);
static void dev_conf_prov_cb(es_dev_conf_data *event_data);
static void cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data);
static bool is_easy_setup_step_done(void);

static es_provisioning_callbacks_s g_callbacks = {.wifi_prov_cb = wifi_prov_cb,
                                                  .dev_conf_prov_cb =
                                                    dev_conf_prov_cb,
                                                  .cloud_data_prov_cb =
                                                    cloud_conf_prov_cb };

int
st_easy_setup_start(sc_properties *vendor_props, st_easy_setup_cb_t cb)
{
  st_print_log("[Easy_Setup] st_easy_setup_start in\n");

  if (!cb) {
    return -1;
  }

  es_connect_type resourcemMask =
    ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE | ES_DEVCONF_RESOURCE;
  if (es_init_enrollee(g_is_secured, resourcemMask, g_callbacks) != ES_OK) {
    st_print_log("[Easy_Setup] es_init_enrollee error!\n");
    return -1;
  }

  g_callback = cb;
  memset(&g_wifi_conf_data, 0, sizeof(es_wifi_conf_data));
  memset(&g_cloud_info, 0, sizeof(es_coap_cloud_conf_data));
  memset(&g_st_cloud_info, 0, sizeof(sc_coap_cloud_server_conf_properties));
  is_have_st_cloud_info = false;
  g_easy_setup_status = EASY_SETUP_PROGRESSING;
  st_print_log("[Easy_Setup] es_init_enrollee Success\n");

  st_turn_on_soft_AP(&g_soft_ap);

  if (vendor_props) {
    if (set_sc_properties(vendor_props) == ES_ERROR) {
      st_print_log("SetSCProperties Error\n");
      return -1;
    }
  }

  // Set callbacks for Vendor Specific Properties
  es_set_callback_for_userdata(ReadUserdataCb, WriteUserdataCb);
  st_print_log("[Easy_Setup] st_easy_setup_start out\n");

  return 0;
}

void
st_easy_setup_stop(void)
{
  st_print_log("[Easy_Setup] st_easy_setup_stop in\n");

  if (es_terminate_enrollee() == ES_ERROR) {
    st_print_log("es_terminate_enrollee failed!\n");
    return;
  }

  g_callback = NULL;
  g_easy_setup_status = EASY_SETUP_INITIALIZE;
  g_prov_step_check = 0;
  es_set_state(ES_STATE_INIT);

  st_print_log("[Easy_Setup] st_easy_setup_stop out\n");
}

st_easy_setup_status_t
get_easy_setup_status(void)
{
  return g_easy_setup_status;
}

es_coap_cloud_conf_data *
get_cloud_informations(void)
{
  if (g_easy_setup_status != EASY_SETUP_FINISH)
    return NULL;

  return &g_cloud_info;
}

sc_coap_cloud_server_conf_properties *
get_st_cloud_informations(void)
{
  if (g_easy_setup_status != EASY_SETUP_FINISH ||
      is_have_st_cloud_info == false)
    return NULL;

  return &g_st_cloud_info;
}

static oc_event_callback_retval_t
callback_handler(void *data)
{
  (void)data;
  if (g_callback)
    g_callback(g_easy_setup_status);
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
easy_setup_finish_handler(void *data)
{
  (void)data;
  if (is_easy_setup_step_done()) {
    st_print_log("[Easy_Setup] Terminate Soft AP thread.\n");
    st_turn_off_soft_AP(&g_soft_ap);
    st_connect_wifi(oc_string(g_wifi_conf_data.ssid),
                    oc_string(g_wifi_conf_data.pwd));
    es_set_state(ES_STATE_CONNECTED_TO_ENROLLER);
    es_set_error_code(ES_ERRCODE_NO_ERROR);
    g_easy_setup_status = EASY_SETUP_FINISH;
    oc_set_delayed_callback(NULL, callback_handler, 0);
  }
  return OC_EVENT_DONE;
}

static void
wifi_prov_cb(es_wifi_conf_data *event_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_WIFI_PROV)
    return;

  st_print_log("[Easy_Setup] wifi_prov_cb in\n");

  es_set_state(ES_STATE_CONNECTING_TO_ENROLLER);

  if (event_data == NULL) {
    st_print_log("[Easy_Setup] es_wifi_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  st_print_log("[Easy_Setup] SSID : %s\n", oc_string(event_data->ssid));
  st_print_log("[Easy_Setup] Password : %s\n", oc_string(event_data->pwd));
  st_print_log("[Easy_Setup] AuthType : %d\n", event_data->authtype);
  st_print_log("[Easy_Setup] EncType : %d\n", event_data->enctype);

  if (event_data->userdata) {
    sc_wifi_conf_properties *data = event_data->userdata;
    st_print_log("[Easy_Setup] DiscoveryChannel : %d\n",
                 data->discoveryChannel);
  }

  memcpy(&g_wifi_conf_data, event_data, sizeof(es_wifi_conf_data));
  oc_new_string(&g_wifi_conf_data.ssid,oc_string(event_data->ssid),oc_string_len(event_data->ssid));
  oc_new_string(&g_wifi_conf_data.pwd,oc_string(event_data->pwd),oc_string_len(event_data->pwd));

  g_prov_step_check |= ST_EASY_SETUP_WIFI_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[Easy_Setup] wifi_prov_cb out\n");
}

static void
dev_conf_prov_cb(es_dev_conf_data *event_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_DEV_PROV)
    return;

  st_print_log("[Easy_Setup] dev_conf_prov_cb in\n");

  if (event_data == NULL) {
    st_print_log("[Easy_Setup] es_dev_conf_data is NULL\n");
    return;
  }

  if (event_data->userdata) {
    sc_dev_conf_properties *data = event_data->userdata;

    if (!oc_string(data->country))
      return;

    for (uint8_t i = 0; i < oc_string_array_get_allocated_size(data->location);
         ++i) {
      st_print_log("[Easy_Setup] Location : %s\n",
                   oc_string_array_get_item(data->location, i));
    }
    st_print_log("[Easy_Setup] Register Mobile Device : %s\n",
                 oc_string(data->regMobileDev));
    st_print_log("[Easy_Setup] Country : %s\n", oc_string(data->country));
    st_print_log("[Easy_Setup] Language : %s\n", oc_string(data->language));
    st_print_log("[Easy_Setup] GPS Location : %s\n",
                 oc_string(data->gpsLocation));
    st_print_log("[Easy_Setup] UTC Date time : %s\n",
                 oc_string(data->utcDateTime));
    st_print_log("[Easy_Setup] Regional time : %s\n",
                 oc_string(data->regionalDateTime));
    st_print_log("[Easy_Setup] SSO List : %s\n", oc_string(data->ssoList));
  }

  g_prov_step_check |= ST_EASY_SETUP_DEV_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[Easy_Setup] dev_conf_prov_cb out\n");
}

static void
cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_CLOUD_PROV)
    return;

  st_print_log("[Easy_Setup] cloud_conf_prov_cb in\n");

  if (event_data == NULL) {
    st_print_log("es_coap_cloud_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  if (oc_string(event_data->auth_code)) {
    st_print_log("[Easy_Setup] AuthCode : %s\n",
                 oc_string(event_data->auth_code));
  }

  if (oc_string(event_data->access_token)) {
    st_print_log("[Easy_Setup] Access Token : %s\n",
                 oc_string(event_data->access_token));
  }

  if (oc_string(event_data->auth_provider)) {
    st_print_log("[Easy_Setup] AuthProvider : %s\n",
                 oc_string(event_data->auth_provider));
  }

  if (oc_string(event_data->ci_server)) {
    st_print_log("[Easy_Setup] CI Server : %s\n",
                 oc_string(event_data->ci_server));
  }

  if (event_data->userdata) {
    sc_coap_cloud_server_conf_properties *data = event_data->userdata;
    st_print_log("[Easy_Setup] ClientID : %s\n", oc_string(data->clientID));
    st_print_log("[Easy_Setup] uid : %s\n", oc_string(data->uid));
    st_print_log("[Easy_Setup] Refresh token : %s\n",
                 oc_string(data->refreshToken));
    memcpy(&g_st_cloud_info, data,
           sizeof(sc_coap_cloud_server_conf_properties));
    is_have_st_cloud_info = true;
  }

  memcpy(&g_cloud_info, event_data, sizeof(es_coap_cloud_conf_data));

  g_prov_step_check |= ST_EASY_SETUP_CLOUD_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[Easy_Setup] cloud_conf_prov_cb out\n");
}

static bool
is_easy_setup_step_done(void)
{
  if (g_prov_step_check & ST_EASY_SETUP_DEV_PROV &&
      g_prov_step_check & ST_EASY_SETUP_WIFI_PROV &&
      g_prov_step_check & ST_EASY_SETUP_CLOUD_PROV) {
    return true;
  }
  return false;
}
