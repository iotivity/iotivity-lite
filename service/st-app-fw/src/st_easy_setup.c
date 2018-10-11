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
#include "oc_helpers.h"
#include "oc_network_monitor.h"
#include <wifi_manager/wifi_manager.h>
#ifdef OC_SECURITY
#include "oc_security.h"
#endif
#include "st_port.h"
#include "st_store.h"

#include <stdlib.h>

#define EASYSETUP_TAG "E1"
#define EASYSETUP_TIMEOUT (60)
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

static st_easy_setup_cb_t g_callback = NULL;

static st_easy_setup_status_t g_easy_setup_status = EASY_SETUP_INITIALIZE;

static st_prov_step_t g_prov_step_check;

static void wifi_prov_cb(es_wifi_conf_data *event_data);
static void dev_conf_prov_cb(es_dev_conf_data *event_data);
static void cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data);
static bool is_easy_setup_step_done(void);
static oc_event_callback_retval_t easy_setup_finish_handler(void *data);
static oc_event_callback_retval_t easy_setup_timeout_handler(void *data);
#ifdef OC_SECURITY
static void st_otm_state_handler(oc_sec_otm_err_code_t state);
#endif
static void get_ap_list(sec_accesspoint **ap_list);

static es_provisioning_callbacks_s g_callbacks = {.wifi_prov_cb = wifi_prov_cb,
                                                  .dev_conf_prov_cb =
                                                    dev_conf_prov_cb,
                                                  .cloud_data_prov_cb =
                                                    cloud_conf_prov_cb };

int
st_is_easy_setup_finish(void)
{
  st_store_t *store_info = st_store_get_info();
  return store_info->status == true ? 0 : -1;
}

int
st_easy_setup_start(sc_properties *vendor_props, st_easy_setup_cb_t cb)
{
  st_print_log("[ST_ES] st_easy_setup_start in\n");

  if (!cb) {
    return -1;
  }

  g_callback = cb;
  es_connect_type resourcemMask =
    ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE | ES_DEVCONF_RESOURCE;
  if (es_init_enrollee(g_is_secured, resourcemMask, g_callbacks) != ES_OK) {
    st_print_log("[ST_ES] es_init_enrollee error!\n");
    return -1;
  }

  g_easy_setup_status = EASY_SETUP_PROGRESSING;
  st_print_log("[ST_ES] es_init_enrollee Success\n");

  if (vendor_props) {
    if (set_sc_properties(vendor_props) == ES_ERROR) {
      st_print_log("[ST_ES] SetSCProperties Error\n");
      return -1;
    }
  }

  // Set callbacks for Vendor Specific Properties
  es_set_callback_for_userdata(sc_read_userdata_cb, sc_write_userdata_cb,
                               sc_free_userdata);

  // Init /sec/accesspointlist resource
  init_accesspointlist_resource(get_ap_list);

#ifdef OC_SECURITY
  // Set OTM status changed callback.
  oc_sec_otm_set_err_cb(st_otm_state_handler);
#endif

  st_print_log("[ST_ES] st_easy_setup_start out\n");
  return 0;
}

void
st_easy_setup_stop(void)
{
  st_print_log("[ST_ES] st_easy_setup_stop in\n");

  if (es_terminate_enrollee() == ES_ERROR) {
    st_print_log("[ST_ES] es_terminate_enrollee failed!\n");
    return;
  }

  reset_sc_properties();

  // Free scan list
  deinit_accesspointlist_resource();

#ifndef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
    st_wifi_clear_cache();
#endif

  g_callback = NULL;
  g_easy_setup_status = EASY_SETUP_INITIALIZE;
  g_prov_step_check = 0;
  es_set_state(ES_STATE_INIT);

  st_print_log("[ST_ES] st_easy_setup_stop out\n");
}

int
st_gen_ssid(char *ssid, const char *device_name, const char *mnid,
            const char *sid)
{
  unsigned char mac[6] = { 0 };

  if (!oc_get_mac_addr(mac)) {
    st_print_log("[ST_ES] oc_get_mac_addr failed!\n");
    return -1;
  }

  snprintf(ssid, MAX_SSID_LEN, "%s_%s%s%s%d%02X%02X", device_name,
           EASYSETUP_TAG, mnid, sid, 0, mac[4], mac[5]);

  st_print_log("[ST_ES] ssid : %s\n", ssid);
  return 0;
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
    oc_remove_delayed_callback(NULL, easy_setup_timeout_handler);
    es_set_state(ES_STATE_CONNECTED_TO_ENROLLER);
    es_set_error_code(ES_ERRCODE_NO_ERROR);
    g_easy_setup_status = EASY_SETUP_FINISH;
    st_store_t *store_info = st_store_get_info();
    store_info->status = true;
    if (st_store_dump() <= 0) {
      st_print_log("[ST_ES] st_store_dump failed\n");
      g_easy_setup_status = EASY_SETUP_RESET;
    }
    oc_set_delayed_callback(NULL, callback_handler, 0);
  }
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
easy_setup_timeout_handler(void *data)
{
  (void)data;
  st_print_log("[ST_ES] Timeout easy-setup procedure.\n");
  g_easy_setup_status = EASY_SETUP_RESET;
  oc_set_delayed_callback(NULL, callback_handler, 0);
  return OC_EVENT_DONE;
}

#ifdef OC_SECURITY
static void
st_otm_state_handler(oc_sec_otm_err_code_t state)
{
  if (state == OC_SEC_OTM_START) {
    st_print_log("[ST_ES] OTM provisioning started.\n");
    // Set timeout for security OTM procedure.
    oc_set_delayed_callback(NULL, easy_setup_timeout_handler,
                            EASYSETUP_TIMEOUT);
  } else if (state == OC_SEC_OTM_FINISH) {
    st_print_log("[ST_ES] OTM provisioning done.\n");
    oc_remove_delayed_callback(NULL, easy_setup_timeout_handler);
    // Set timeout for easy setup procedure.
    oc_set_delayed_callback(NULL, easy_setup_timeout_handler,
                            EASYSETUP_TIMEOUT);
  } else if (state <= OC_SEC_ERR_PSTAT) {
    st_print_log("[ST_ES] OTM provisioning failed with %d.\n", state);
    oc_remove_delayed_callback(NULL, easy_setup_timeout_handler);
    oc_set_delayed_callback(NULL, easy_setup_timeout_handler, 0);
  }
}
#endif

static void
st_string_copy(oc_string_t *dst, oc_string_t *src)
{
  if (oc_string(*dst)) {
    if (oc_string_len(*dst) == oc_string_len(*src) &&
        strncmp(oc_string(*dst), oc_string(*src), oc_string_len(*dst)) == 0) {
      return;
    } else {
      oc_free_string(dst);
    }
  }
  oc_new_string(dst, oc_string(*src), oc_string_len(*src));
}

static void
wifi_prov_cb(es_wifi_conf_data *wifi_prov_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_WIFI_PROV)
    return;

  st_print_log("[ST_ES] wifi_prov_cb in\n");

  es_set_state(ES_STATE_CONNECTING_TO_ENROLLER);

  if (wifi_prov_data == NULL) {
    st_print_log("[ST_ES] es_wifi_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  st_print_log("[ST_ES] SSID : %s\n", oc_string(wifi_prov_data->ssid));
  st_print_log("[ST_ES] Password : %s\n", oc_string(wifi_prov_data->pwd));
  st_print_log("[ST_ES] AuthType : %d\n", wifi_prov_data->authtype);
  st_print_log("[ST_ES] EncType : %d\n", wifi_prov_data->enctype);

  if (wifi_prov_data->userdata) {
    sc_wifi_conf_properties *data = wifi_prov_data->userdata;
    st_print_log("[ST_ES] DiscoveryChannel : %d\n", data->disc_channel);
  }

  if (!oc_string(wifi_prov_data->ssid) || !oc_string(wifi_prov_data->pwd)) {
    st_print_log("[ST_ES] wifi provision info is not enough!\n");
    return;
  }

  st_store_t *store_info = st_store_get_info();
  st_string_copy(&store_info->accesspoint.ssid, &wifi_prov_data->ssid);
  st_string_copy(&store_info->accesspoint.pwd, &wifi_prov_data->pwd);

  g_prov_step_check |= ST_EASY_SETUP_WIFI_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[ST_ES] wifi_prov_cb out\n");
}

static void
dev_conf_prov_cb(es_dev_conf_data *dev_prov_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_DEV_PROV)
    return;

  st_print_log("[ST_ES] dev_conf_prov_cb in\n");

  if (dev_prov_data == NULL) {
    st_print_log("[ST_ES] es_dev_conf_data is NULL\n");
    return;
  }

  if (dev_prov_data->userdata) {
    sc_dev_conf_properties *data = dev_prov_data->userdata;

    if (!oc_string(data->country))
      return;

    for (uint8_t i = 0; i < oc_string_array_get_allocated_size(data->location);
         ++i) {
      st_print_log("[ST_ES] Location : %s\n",
                   oc_string_array_get_item(data->location, i));
    }

    if (oc_string(data->reg_mobile_dev))
      st_print_log("[ST_ES] Register Mobile Device : %s\n",
                   oc_string(data->reg_mobile_dev));
    if (oc_string(data->country))
      st_print_log("[ST_ES] Country : %s\n", oc_string(data->country));
    if (oc_string(data->language))
      st_print_log("[ST_ES] Language : %s\n", oc_string(data->language));

    if (oc_string(data->gps_location))
      st_print_log("[ST_ES] GPS Location : %s\n",
                   oc_string(data->gps_location));

    if (oc_string(data->utc_date_time))
      st_print_log("[ST_ES] UTC Date time : %s\n",
                   oc_string(data->utc_date_time));

    if (oc_string(data->regional_date_time))
      st_print_log("[ST_ES] Regional time : %s\n",
                   oc_string(data->regional_date_time));

    if (oc_string(data->sso_list))
      printf("[ST_ES] SSO List : %s\n", oc_string(data->sso_list));
  }

  g_prov_step_check |= ST_EASY_SETUP_DEV_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[ST_ES] dev_conf_prov_cb out\n");
}

static void
cloud_conf_prov_cb(es_coap_cloud_conf_data *cloud_prov_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_CLOUD_PROV)
    return;

  st_print_log("[ST_ES] cloud_conf_prov_cb in\n");

  if (cloud_prov_data == NULL || cloud_prov_data->userdata == NULL) {
    st_print_log("[ST_ES] es_coap_cloud_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  if (oc_string(cloud_prov_data->auth_code)) {
    st_print_log("[ST_ES] AuthCode : %s\n",
                 oc_string(cloud_prov_data->auth_code));
  }

  if (oc_string(cloud_prov_data->access_token)) {
    st_print_log("[ST_ES] Access Token : %s\n",
                 oc_string(cloud_prov_data->access_token));
  }

  if (oc_string(cloud_prov_data->auth_provider)) {
    st_print_log("[ST_ES] AuthProvider : %s\n",
                 oc_string(cloud_prov_data->auth_provider));
  }

  if (oc_string(cloud_prov_data->ci_server)) {
    st_print_log("[ST_ES] CI Server : %s\n",
                 oc_string(cloud_prov_data->ci_server));
  }

  sc_cloud_server_conf_properties *data = cloud_prov_data->userdata;
  if (data) {
    st_print_log("[ST_ES] ClientID : %s\n", oc_string(data->client_id));
    st_print_log("[ST_ES] uid : %s\n", oc_string(data->uid));
    st_print_log("[ST_ES] Refresh Token : %s\n",
                 oc_string(data->refresh_token));
  }

  if (!oc_string(cloud_prov_data->access_token) ||
      !oc_string(cloud_prov_data->auth_provider) ||
      !oc_string(cloud_prov_data->ci_server) ||
      !oc_string(data->refresh_token) || !oc_string(data->uid)) {
    st_print_log("[ST_ES] cloud provision info is not enough!");
    return;
  }

  st_store_t *store_info = st_store_get_info();
  st_string_copy(&store_info->cloudinfo.access_token,
                 &cloud_prov_data->access_token);
  st_string_copy(&store_info->cloudinfo.refresh_token, &data->refresh_token);
  st_string_copy(&store_info->cloudinfo.auth_provider,
                 &cloud_prov_data->auth_provider);
  st_string_copy(&store_info->cloudinfo.ci_server, &cloud_prov_data->ci_server);
  st_string_copy(&store_info->cloudinfo.uid, &data->uid);

  g_prov_step_check |= ST_EASY_SETUP_CLOUD_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[ST_ES] cloud_conf_prov_cb out\n");
}

static void
get_ap_list(sec_accesspoint **ap_list) {
  st_wifi_ap_t *scanlist = NULL;
  sec_accesspoint *list_tail = NULL;

  if (!ap_list) {
    return;
  }

  *ap_list = NULL;

  st_print_log("[ST_ES] WiFi scan list -> \n");
#ifdef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
  st_wifi_scan(&scanlist);
#else
  scanlist = st_wifi_get_cache();
#endif

  st_wifi_ap_t *cur = scanlist;
  int cnt = 0;
  while(cur) {
    sec_accesspoint *ap = (sec_accesspoint *) calloc(1, sizeof(sec_accesspoint));
    if (!ap) {
      goto exit;
    }

    if (cur->ssid)
      oc_new_string(&(ap->ssid), cur->ssid, strlen(cur->ssid));
    if (cur->channel)
      oc_new_string(&(ap->channel), cur->channel, strlen(cur->channel));
    if (cur->enc_type)
      oc_new_string(&(ap->enc_type), cur->enc_type, strlen(cur->enc_type));
    if (cur->mac_addr)
      oc_new_string(&(ap->mac_address), cur->mac_addr, strlen(cur->mac_addr));
    if (cur->max_bitrate)
      oc_new_string(&(ap->max_rate), cur->max_bitrate, strlen(cur->max_bitrate));
    if (cur->rssi)
      oc_new_string(&(ap->rssi), cur->rssi, strlen(cur->rssi));
    if (cur->sec_type)
      oc_new_string(&(ap->security_type), cur->sec_type, strlen(cur->sec_type));

    st_print_log("[ST_ES] ssid=%s mac=%s\n", cur->ssid, cur->mac_addr);
    if (!*ap_list) {
      *ap_list = ap;
    } else {
      list_tail->next = ap;
    }
    list_tail = ap;
    cur = cur->next;
    cnt++;
  }

exit:
#ifdef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
  st_wifi_free_scan_list(scanlist);
#endif
  return;
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
