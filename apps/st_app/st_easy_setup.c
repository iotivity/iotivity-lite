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
#include "st_port.h"
#include "st_store.h"

#define EASYSETUP_TAG "E1"
#define EASYSETUP_TIMEOUT (60)

#define st_rep_set_string_with_chk(object, key, value)                         \
  if (value)                                                                   \
    oc_rep_set_text_string(object, key, value);

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

static st_store_t g_store_info;

static st_easy_setup_status_t g_easy_setup_status = EASY_SETUP_INITIALIZE;

static st_prov_step_t g_prov_step_check;

static void wifi_prov_cb(es_wifi_conf_data *event_data);
static void dev_conf_prov_cb(es_dev_conf_data *event_data);
static void cloud_conf_prov_cb(es_coap_cloud_conf_data *event_data);
static bool is_easy_setup_step_done(void);
static oc_event_callback_retval_t easy_setup_finish_handler(void *data);
static oc_event_callback_retval_t easy_setup_timeout_handler(void *data);

static es_provisioning_callbacks_s g_callbacks = {.wifi_prov_cb = wifi_prov_cb,
                                                  .dev_conf_prov_cb =
                                                    dev_conf_prov_cb,
                                                  .cloud_data_prov_cb =
                                                    cloud_conf_prov_cb };

int
st_is_easy_setup_finish(void)
{
  return g_store_info.status == true ? 0 : -1;
}

int
st_easy_setup_start(sc_properties *vendor_props, st_easy_setup_cb_t cb)
{
  st_print_log("[Easy_Setup] st_easy_setup_start in\n");

  if (!cb) {
    return -1;
  }

  g_callback = cb;

  if (st_is_easy_setup_finish() == 0) {
    st_print_log("[Easy_Setup] Easy Setup is already done.\n");
    g_prov_step_check |= ST_EASY_SETUP_DEV_PROV | ST_EASY_SETUP_WIFI_PROV |
                         ST_EASY_SETUP_CLOUD_PROV;
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
    _oc_signal_event_loop();
    return 0;
  }

  g_store_info.status = false;

  es_connect_type resourcemMask =
    ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE | ES_DEVCONF_RESOURCE;
  if (es_init_enrollee(g_is_secured, resourcemMask, g_callbacks) != ES_OK) {
    st_print_log("[Easy_Setup] es_init_enrollee error!\n");
    return -1;
  }

  g_easy_setup_status = EASY_SETUP_PROGRESSING;
  st_print_log("[Easy_Setup] es_init_enrollee Success\n");

  if (vendor_props) {
    if (set_sc_properties(vendor_props) == ES_ERROR) {
      st_print_log("SetSCProperties Error\n");
      return -1;
    }
  }

  // Set callbacks for Vendor Specific Properties
  es_set_callback_for_userdata(sc_read_userdata_cb, sc_write_userdata_cb);
  st_print_log("[Easy_Setup] st_easy_setup_start out\n");

  // Set timeout for easy setup procedure.
  oc_set_delayed_callback(NULL, easy_setup_timeout_handler, EASYSETUP_TIMEOUT);
  _oc_signal_event_loop();

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

  reset_sc_properties();

  g_callback = NULL;

  st_print_log("[Easy_Setup] st_easy_setup_stop out\n");
}

void
st_easy_setup_reset(void)
{
  st_print_log("[Easy_Setup] st_easy_setup_reset in\n");

  st_easy_setup_stop();
  g_easy_setup_status = EASY_SETUP_INITIALIZE;
  g_prov_step_check = 0;
  es_set_state(ES_STATE_INIT);
  st_set_default_store_info();
  st_dump();

  st_print_log("[Easy_Setup] st_easy_setup_reset out\n");
}

int
st_gen_ssid(char *ssid, const char *device_name, const char *mnid,
            const char *sid)
{
  unsigned char mac[6] = { 0 };

  if (!oc_get_mac_addr(mac)) {
    st_print_log("[St_app] oc_get_mac_addr failed!\n");
    return -1;
  }

  snprintf(ssid, MAX_SSID_LEN, "%s_%s%s%s%d%02X%02X", device_name,
           EASYSETUP_TAG, mnid, sid, 0, mac[4], mac[5]);
  ssid[strlen(ssid)] = '\0';

  st_print_log("[St_app] ssid : %s\n", ssid);
  return 0;
}

st_easy_setup_status_t
get_easy_setup_status(void)
{
  return g_easy_setup_status;
}

st_store_t *
get_cloud_informations(void)
{
  if (g_easy_setup_status != EASY_SETUP_FINISH)
    return NULL;

  return &g_store_info;
}

static int
st_decode_ap_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 4 && memcmp(oc_string(t->name), "ssid", 4) == 0) {
        oc_new_string(&g_store_info.accesspoint.ssid,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "pwd", 3) == 0) {
        oc_new_string(&g_store_info.accesspoint.pwd, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }

  return 0;
}

static int
st_decode_cloud_access_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 9 && memcmp(oc_string(t->name), "ci_server", 9) == 0) {
        oc_new_string(&g_store_info.cloudinfo.ci_server,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "auth_provider", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.auth_provider,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "uid", 3) == 0) {
        oc_new_string(&g_store_info.cloudinfo.uid, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 12 &&
                 memcmp(oc_string(t->name), "access_token", 12) == 0) {
        oc_new_string(&g_store_info.cloudinfo.access_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "refresh_token", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.refresh_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }

  return 0;
}

int
st_decode_store_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_BOOL:
      if (len == 6 && memcmp(oc_string(t->name), "status", 6) == 0) {
        g_store_info.status = t->value.boolean;
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    case OC_REP_OBJECT:
      if (len == 11 && memcmp(oc_string(t->name), "accesspoint", 11) == 0) {
        if (st_decode_ap_info(t->value.object) != 0)
          return -1;
      } else if (len == 9 && memcmp(oc_string(t->name), "cloudinfo", 9) == 0) {
        if (st_decode_cloud_access_info(t->value.object) != 0)
          return -1;
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s, %d", oc_string(t->name), t->type);
      return -1;
    }
    t = t->next;
  }

  return 0;
}

void
st_encode_store_info(void)
{
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, status, g_store_info.status);
  oc_rep_set_object(root, accesspoint);
  st_rep_set_string_with_chk(accesspoint, ssid,
                             oc_string(g_store_info.accesspoint.ssid));
  st_rep_set_string_with_chk(accesspoint, pwd,
                             oc_string(g_store_info.accesspoint.pwd));
  oc_rep_close_object(root, accesspoint);
  oc_rep_set_object(root, cloudinfo);
  st_rep_set_string_with_chk(cloudinfo, ci_server,
                             oc_string(g_store_info.cloudinfo.ci_server));
  st_rep_set_string_with_chk(cloudinfo, auth_provider,
                             oc_string(g_store_info.cloudinfo.auth_provider));
  st_rep_set_string_with_chk(cloudinfo, uid,
                             oc_string(g_store_info.cloudinfo.uid));
  st_rep_set_string_with_chk(cloudinfo, access_token,
                             oc_string(g_store_info.cloudinfo.access_token));
  st_rep_set_string_with_chk(cloudinfo, refresh_token,
                             oc_string(g_store_info.cloudinfo.refresh_token));
  oc_rep_close_object(root, cloudinfo);
  oc_rep_end_root_object();
}

void
st_set_default_store_info(void)
{
  g_store_info.status = false;
  if (oc_string(g_store_info.accesspoint.ssid)) {
    oc_free_string(&g_store_info.accesspoint.ssid);
  } else if (oc_string(g_store_info.accesspoint.pwd)) {
    oc_free_string(&g_store_info.accesspoint.pwd);
  } else if (oc_string(g_store_info.cloudinfo.ci_server)) {
    oc_free_string(&g_store_info.cloudinfo.ci_server);
  } else if (oc_string(g_store_info.cloudinfo.auth_provider)) {
    oc_free_string(&g_store_info.cloudinfo.auth_provider);
  } else if (oc_string(g_store_info.cloudinfo.uid)) {
    oc_free_string(&g_store_info.cloudinfo.uid);
  } else if (oc_string(g_store_info.cloudinfo.access_token)) {
    oc_free_string(&g_store_info.cloudinfo.access_token);
  } else if (oc_string(g_store_info.cloudinfo.refresh_token)) {
    oc_free_string(&g_store_info.cloudinfo.refresh_token);
  }
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
    oc_remove_delayed_callback(NULL, easy_setup_timeout_handler);
    st_turn_off_soft_AP();
    st_connect_wifi(oc_string(g_store_info.accesspoint.ssid),
                    oc_string(g_store_info.accesspoint.pwd));
    es_set_state(ES_STATE_CONNECTED_TO_ENROLLER);
    es_set_error_code(ES_ERRCODE_NO_ERROR);
    g_easy_setup_status = EASY_SETUP_FINISH;
    g_store_info.status = true;
    st_dump();
    oc_set_delayed_callback(NULL, callback_handler, 0);
  }
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
easy_setup_timeout_handler(void *data)
{
  (void)data;
  st_print_log("[Easy_Setup] Timeout easy-setup procedure.\n");
  g_easy_setup_status = EASY_SETUP_RESET;
  return OC_EVENT_DONE;
}

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

  st_print_log("[Easy_Setup] wifi_prov_cb in\n");

  es_set_state(ES_STATE_CONNECTING_TO_ENROLLER);

  if (wifi_prov_data == NULL) {
    st_print_log("[Easy_Setup] es_wifi_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  st_print_log("[Easy_Setup] SSID : %s\n", oc_string(wifi_prov_data->ssid));
  st_print_log("[Easy_Setup] Password : %s\n", oc_string(wifi_prov_data->pwd));
  st_print_log("[Easy_Setup] AuthType : %d\n", wifi_prov_data->authtype);
  st_print_log("[Easy_Setup] EncType : %d\n", wifi_prov_data->enctype);

  if (wifi_prov_data->userdata) {
    sc_wifi_conf_properties *data = wifi_prov_data->userdata;
    st_print_log("[Easy_Setup] DiscoveryChannel : %d\n",
                 data->disc_channel);
  }

  if (!oc_string(wifi_prov_data->ssid) || !oc_string(wifi_prov_data->pwd)) {
    st_print_log("[Easy_Setup] wifi provision info is not enough!");
    return;
  }

  st_string_copy(&g_store_info.accesspoint.ssid, &wifi_prov_data->ssid);
  st_string_copy(&g_store_info.accesspoint.pwd, &wifi_prov_data->pwd);

  g_prov_step_check |= ST_EASY_SETUP_WIFI_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[Easy_Setup] wifi_prov_cb out\n");
}

static void
dev_conf_prov_cb(es_dev_conf_data *dev_prov_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_DEV_PROV)
    return;

  st_print_log("[Easy_Setup] dev_conf_prov_cb in\n");

  if (dev_prov_data == NULL) {
    st_print_log("[Easy_Setup] es_dev_conf_data is NULL\n");
    return;
  }

  if (dev_prov_data->userdata) {
    sc_dev_conf_properties *data = dev_prov_data->userdata;

    if (!oc_string(data->country))
      return;

    for (uint8_t i = 0; i < oc_string_array_get_allocated_size(data->location);
         ++i) {
      st_print_log("[Easy_Setup] Location : %s\n",
                   oc_string_array_get_item(data->location, i));
    }

    if (oc_string(data->reg_mobile_dev))
      st_print_log("[Easy_Setup] Register Mobile Device : %s\n",
                   oc_string(data->reg_mobile_dev));
    if (oc_string(data->country))
      st_print_log("[Easy_Setup] Country : %s\n", oc_string(data->country));
    if (oc_string(data->language))
      st_print_log("[Easy_Setup] Language : %s\n", oc_string(data->language));

    if (oc_string(data->gps_location))
      st_print_log("[Easy_Setup] GPS Location : %s\n",
                   oc_string(data->gps_location));

    if (oc_string(data->utc_date_time))
      st_print_log("[Easy_Setup] UTC Date time : %s\n",
                   oc_string(data->utc_date_time));

    if (oc_string(data->regional_date_time))
      st_print_log("[Easy_Setup] Regional time : %s\n",
                   oc_string(data->regional_date_time));

    if (oc_string(data->sso_list))
      printf("[Easy_Setup] SSO List : %s\n", oc_string(data->sso_list));
  }

  g_prov_step_check |= ST_EASY_SETUP_DEV_PROV;
  if (is_easy_setup_step_done()) {
    oc_set_delayed_callback(NULL, easy_setup_finish_handler, 0);
  }
  st_print_log("[Easy_Setup] dev_conf_prov_cb out\n");
}

static void
cloud_conf_prov_cb(es_coap_cloud_conf_data *cloud_prov_data)
{
  if (g_prov_step_check & ST_EASY_SETUP_CLOUD_PROV)
    return;

  st_print_log("[Easy_Setup] cloud_conf_prov_cb in\n");

  if (cloud_prov_data == NULL) {
    st_print_log("es_coap_cloud_conf_data is NULL\n");
    g_easy_setup_status = EASY_SETUP_FAIL;
    oc_set_delayed_callback(NULL, callback_handler, 0);
    return;
  }

  if (oc_string(cloud_prov_data->auth_code)) {
    st_print_log("[Easy_Setup] AuthCode : %s\n",
                 oc_string(cloud_prov_data->auth_code));
  }

  if (oc_string(cloud_prov_data->access_token)) {
    st_print_log("[Easy_Setup] Access Token : %s\n",
                 oc_string(cloud_prov_data->access_token));
  }

  if (oc_string(cloud_prov_data->auth_provider)) {
    st_print_log("[Easy_Setup] AuthProvider : %s\n",
                 oc_string(cloud_prov_data->auth_provider));
  }

  if (oc_string(cloud_prov_data->ci_server)) {
    st_print_log("[Easy_Setup] CI Server : %s\n",
                 oc_string(cloud_prov_data->ci_server));
  }

  sc_cloud_server_conf_properties *data = cloud_prov_data->userdata;
  if (data) {
    st_print_log("[Easy_Setup] ClientID : %s\n", oc_string(data->client_id));
    st_print_log("[Easy_Setup] uid : %s\n", oc_string(data->uid));
    st_print_log("[Easy_Setup] Refresh Token : %s\n",
                 oc_string(data->refresh_token));
  }

  if (!oc_string(cloud_prov_data->access_token) ||
      !oc_string(cloud_prov_data->auth_provider) ||
      !oc_string(cloud_prov_data->ci_server) ||
      !oc_string(data->refresh_token) || !oc_string(data->uid)) {
    st_print_log("[Easy_Setup] cloud provision info is not enough!");
    return;
  }

  st_string_copy(&g_store_info.cloudinfo.access_token,
                 &cloud_prov_data->access_token);
  st_string_copy(&g_store_info.cloudinfo.refresh_token,
                 &data->refresh_token);
  st_string_copy(&g_store_info.cloudinfo.auth_provider,
                 &cloud_prov_data->auth_provider);
  st_string_copy(&g_store_info.cloudinfo.ci_server,
                 &cloud_prov_data->ci_server);
  st_string_copy(&g_store_info.cloudinfo.uid, &data->uid);

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
