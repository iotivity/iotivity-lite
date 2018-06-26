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

#include <stdlib.h>

#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#ifdef OC_SECURITY
#include "security/oc_doxm.h"
#include "security/oc_pstat.h"
#endif
#include "st_cloud_manager.h"
#include "st_data_manager.h"
#include "st_easy_setup.h"
#include "st_fota_manager.h"
#include "st_manager.h"
#include "st_port.h"
#include "st_process.h"
#include "st_resource_manager.h"
#include "st_store.h"

#define SOFT_AP_PWD "1111122222"
#define SOFT_AP_CHANNEL (6)
#define AP_CONNECT_RETRY_LIMIT (20)

static st_status_t g_main_status = ST_STATUS_INIT;
static st_status_cb_t g_st_status_cb = NULL;

// define vendor specific properties.
static const char *st_device_type = "deviceType";
static const char *st_device_sub_type = "deviceSubType";
static const char *st_reg_set_device =
  "{\"wm\":\"00:11:22:33:44:55\",\"pm\":\"00:11:22:33:44:55\",\"bm\":\"00:11:"
  "22:33:44:55\",\"rk\":[\"VOICE\",\"EXTRA\",\"BTHIDPOWERON\"],\"sl\":["
  "\"TV2MOBILE\",\"MOBILE2TV\",\"BTWAKEUP\",\"WOWLAN\",\"BTREMOTECON\","
  "\"DLNADMR\"]}";
static const char *st_network_prov_info =
  "{\"IMEI\":\"123456789012345 / "
  "01\",\"IMSI\":\"123401234567890\",\"MCC_MNC\":\"100_10\",\"SN\":"
  "\"XY0123456XYZ\"}";
static const char *st_pin_number = "pinNumber";
static const char *st_model_number = "Model Number";
static const char *st_protocol_version = "2.0";

// define application specific values.
#ifdef OC_SPEC_VER_OIC
static const char *spec_version = "core.1.1.0";
static const char *data_model_version = "res.1.1.0";
#else  /* OC_SPEC_VER_OIC */
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";
#endif /* !OC_SPEC_VER_OIC */

static sc_properties st_vendor_props;

static sec_provisioning_info g_prov_resource;

static int device_index = 0;

static const char *device_rt = "oic.d.light";
static const char *device_name = "Samsung";

static const char *manufacturer = "xxxx";
static const char *sid = "000";
static const char *vid = "IoT2020";

int quit = 0;

static void set_st_manager_status(st_status_t status);

static void
init_platform_cb(void *data)
{
  (void)data;
  oc_set_custom_platform_property(mnmo, sid);
  oc_set_custom_platform_property(mnpv, "1.0");
  oc_set_custom_platform_property(mnos, "1.0");
  oc_set_custom_platform_property(mnhw, "1.0");
  oc_set_custom_platform_property(mnfv, "1.0");
  oc_set_custom_platform_property(vid, vid);
}

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, init_platform_cb, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  return ret;
}

static void
register_resources(void)
{
  st_register_resources(device_index);
}

void
easy_setup_handler(st_easy_setup_status_t status)
{
  if (status == EASY_SETUP_FINISH) {
    st_print_log("[ST_MGR] Easy setup succeed!!!\n");
    set_st_manager_status(ST_STATUS_EASY_SETUP_DONE);
  } else if (status == EASY_SETUP_RESET) {
    st_print_log("[ST_MGR] Easy setup reset!!!\n");
    set_st_manager_status(ST_STATUS_RESET);
  } else if (status == EASY_SETUP_FAIL) {
    st_print_log("[ST_MGR] Easy setup failed!!!\n");
    set_st_manager_status(ST_STATUS_QUIT);
  }
}

void
cloud_manager_handler(st_cloud_manager_status_t status)
{
  if (status == CLOUD_MANAGER_FINISH) {
    st_print_log("[ST_MGR] Cloud manager succeed!!!\n");
    set_st_manager_status(ST_STATUS_CLOUD_MANAGER_DONE);
  } else if (status == CLOUD_MANAGER_FAIL) {
    st_print_log("[ST_MGR] Cloud manager failed!!!\n");
    set_st_manager_status(ST_STATUS_QUIT);
  } else if (status == CLOUD_MANAGER_RE_CONNECTING) {
    st_print_log("[ST_MGR] Cloud manager re connecting!!!\n");
    set_st_manager_status(ST_STATUS_CLOUD_MANAGER_PROGRESSING);
  } else if (status == CLOUD_MANAGER_RESET) {
    st_print_log("[ST_MGR] Cloud manager reset!!!\n");
    set_st_manager_status(ST_STATUS_RESET);
  }
}

static void
set_sc_prov_info(void)
{
  // Set prov info properties
  int target_size = 1;
  char uuid[MAX_UUID_LENGTH];
  int i = 0;

  g_prov_resource.targets = (sec_provisioning_info_targets *)calloc(
    target_size, sizeof(sec_provisioning_info_targets));

  for (i = 0; i < target_size; i++) {
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);
    oc_new_string(&g_prov_resource.targets[i].target_di, uuid, strlen(uuid));
    oc_new_string(&g_prov_resource.targets[i].target_rt, device_rt,
                  strlen(device_rt));
    g_prov_resource.targets[i].published = false;
  }
  g_prov_resource.targets_size = target_size;
  g_prov_resource.owned = false;
  oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);
  oc_new_string(&g_prov_resource.easysetup_di, uuid, strlen(uuid));

  if (set_sec_prov_info(&g_prov_resource) == ES_ERROR)
    st_print_log("[ST_MGR] SetProvInfo Error\n");

  st_print_log("[ST_MGR] set_sc_prov_info OUT\n");
}

static void
unset_sc_prov_info(void)
{
  // Come from  target_size in set_sc_prov_info
  int target_size = 1, i = 0;

  oc_free_string(&g_prov_resource.easysetup_di);
  for (i = 0; i < target_size; i++) {
    oc_free_string(&g_prov_resource.targets[i].target_di);
    oc_free_string(&g_prov_resource.targets[i].target_rt);
  }

  free(g_prov_resource.targets);
}

static void
st_vendor_props_initialize(void)
{
  memset(&st_vendor_props, 0, sizeof(sc_properties));
  oc_new_string(&st_vendor_props.device_type, st_device_type,
                strlen(st_device_type));
  oc_new_string(&st_vendor_props.device_sub_type, st_device_sub_type,
                strlen(st_device_sub_type));
  st_vendor_props.net_conn_state = NET_STATE_INIT;
  st_vendor_props.disc_channel = WIFI_DISCOVERY_CHANNEL_INIT;
  oc_new_string(&st_vendor_props.reg_set_dev, st_reg_set_device,
                strlen(st_reg_set_device));
  oc_new_string(&st_vendor_props.net_prov_info, st_network_prov_info,
                strlen(st_network_prov_info));
  oc_new_string(&st_vendor_props.pnp_pin, st_pin_number, strlen(st_pin_number));
  oc_new_string(&st_vendor_props.model, st_model_number,
                strlen(st_model_number));
  oc_new_string(&st_vendor_props.es_protocol_ver, st_protocol_version,
                strlen(st_protocol_version));
}

static void
st_vendor_props_shutdown(void)
{
  oc_free_string(&st_vendor_props.device_type);
  oc_free_string(&st_vendor_props.device_sub_type);
  oc_free_string(&st_vendor_props.reg_set_dev);
  oc_free_string(&st_vendor_props.net_prov_info);
  oc_free_string(&st_vendor_props.pnp_pin);
  oc_free_string(&st_vendor_props.model);
  oc_free_string(&st_vendor_props.es_protocol_ver);
}

static void
st_main_reset(void)
{
#ifdef OC_SECURITY
  oc_sec_reset();
#endif /* OC_SECURITY */
  st_store_info_initialize();
  st_store_dump();
}

static oc_event_callback_retval_t
status_callback(void *data)
{
  (void)data;
  if (g_st_status_cb)
    g_st_status_cb(g_main_status);

  return OC_EVENT_DONE;
}

static void
set_st_manager_status(st_status_t status)
{
  g_main_status = status;
  oc_set_delayed_callback(NULL, status_callback, 0);
}

static void
set_main_status_sync(st_status_t status)
{
  st_process_app_sync_lock();
  set_st_manager_status(status);
  st_process_app_sync_unlock();
}

int
st_manager_initialize(void)
{
#ifdef OC_SECURITY
#ifdef __TIZENRT__
  oc_storage_config("/mnt/st_things_creds");
#else
  oc_storage_config("./st_things_creds");
#endif
#endif /* OC_SECURITY */

  if (st_process_init() != 0) {
    st_print_log("[ST_MGR] st_process_init failed.\n");
    return -1;
  }

  if (st_port_specific_init() != 0) {
    st_print_log("[ST_MGR] st_port_specific_init failed!");
    st_process_destroy();
    return -1;
  }

  oc_set_max_app_data_size(3072);
  st_vendor_props_initialize();

  st_unregister_status_handler();
  set_main_status_sync(ST_STATUS_INIT);

  return 0;
}

static int
st_manager_stack_init(void)
{
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = st_process_signal,
#ifdef OC_SERVER
                                       .register_resources = register_resources
#endif
  };

  if (st_store_load() < 0) {
    st_print_log("[ST_MGR] Could not load store informations.\n");
    return -1;
  }

  if (st_data_mgr_info_load() != 0) {
    st_print_log("[ST_MGR] st_data_mgr_info_load failed!\n");
    return -1;
  }

  if (st_is_easy_setup_finish() != 0) {
    // Scan for neighbor wifi access points
    st_start_wifi_scan();

    // Turn on soft-ap
    st_print_log("[ST_MGR] Soft AP turn on.\n");

    char ssid[MAX_SSID_LEN + 1];
    if (st_gen_ssid(ssid, device_name, manufacturer, sid) != 0) {
      return -1;
    }
    st_turn_on_soft_AP(ssid, SOFT_AP_PWD, SOFT_AP_CHANNEL);
  }

  if (oc_main_init(&handler) != 0) {
    st_print_log("[ST_MGR] oc_main_init failed!\n");
    return -1;
  }

  st_data_mgr_info_free();

  char uuid[MAX_UUID_LENGTH] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(0), uuid, MAX_UUID_LENGTH);
  st_print_log("[ST_MGR] uuid : %s\n", uuid);

  set_sc_prov_info();
  st_fota_manager_start();

  int i = 0;
  int device_num = 0;
  device_num = oc_core_get_num_devices();
  for (i = 0; i < device_num; i++) {
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(i);
    st_print_log("[ST_MGR] === device(%d) endpoint info. ===\n", i);
    while (ep) {
      oc_string_t ep_str;
      if (oc_endpoint_to_string(ep, &ep_str) == 0) {
        st_print_log("[ST_MGR] -> %s\n", oc_string(ep_str));
        oc_free_string(&ep_str);
      }
      ep = ep->next;
    }
  }

  if (st_process_start() != 0) {
    st_print_log("[ST_MGR] st_process_start failed.\n");
    return -1;
  }

  return 0;
}

int
st_manager_start(void)
{
  st_store_t *store_info = NULL;
  int conn_cnt = 0;

  while (quit != 1) {
    switch (g_main_status) {
    case ST_STATUS_INIT:
      if (st_manager_stack_init() < 0) {
        return -1;
      }
      store_info = NULL;
      set_main_status_sync(ST_STATUS_EASY_SETUP_START);
      break;
    case ST_STATUS_EASY_SETUP_START:
      if (st_is_easy_setup_finish() == 0) {
        set_main_status_sync(ST_STATUS_EASY_SETUP_DONE);
      } else {
        if (st_easy_setup_start(&st_vendor_props, easy_setup_handler) != 0) {
          st_print_log("[ST_MGR] Failed to start easy setup!\n");
          return -1;
        }
        set_main_status_sync(ST_STATUS_EASY_SETUP_PROGRESSING);
      }
      break;
    case ST_STATUS_EASY_SETUP_PROGRESSING:
    case ST_STATUS_CLOUD_MANAGER_PROGRESSING:
      st_sleep(1);
      st_print_log(".");
      fflush(stdout);
      break;
    case ST_STATUS_EASY_SETUP_DONE:
      st_print_log("\n");
      st_easy_setup_stop();
      store_info = st_store_get_info();
      if (!store_info || !store_info->status) {
        st_print_log("[ST_MGR] could not get cloud informations.\n");
        return -1;
      }
      set_main_status_sync(ST_STATUS_WIFI_CONNECTING);
      break;
    case ST_STATUS_WIFI_CONNECTING:
      st_turn_off_soft_AP();
      st_connect_wifi(oc_string(store_info->accesspoint.ssid),
                      oc_string(store_info->accesspoint.pwd));
      set_main_status_sync(ST_STATUS_WIFI_CONNECTION_CHECKING);
      break;
    case ST_STATUS_WIFI_CONNECTION_CHECKING:
      if (st_cloud_manager_check_connection(&store_info->cloudinfo.ci_server) !=
          0) {
        st_print_log("[ST_MGR] AP is not connected.\n");
        conn_cnt++;
        if (conn_cnt > AP_CONNECT_RETRY_LIMIT) {
          conn_cnt = 0;
          set_main_status_sync(ST_STATUS_RESET);
        } else if (conn_cnt == (AP_CONNECT_RETRY_LIMIT >> 1)) {
          set_main_status_sync(ST_STATUS_WIFI_CONNECTING);
        }
        st_sleep(3);
      } else {
        conn_cnt = 0;
        set_main_status_sync(ST_STATUS_CLOUD_MANAGER_START);
      }
      break;
    case ST_STATUS_CLOUD_MANAGER_START:
      if (st_cloud_manager_start(store_info, device_index,
                                 cloud_manager_handler) != 0) {
        st_print_log("[ST_MGR] Failed to start cloud manager!\n");
        return -1;
      }
      set_main_status_sync(ST_STATUS_CLOUD_MANAGER_PROGRESSING);
      break;
    case ST_STATUS_CLOUD_MANAGER_DONE:
      st_print_log("\n");
      set_main_status_sync(ST_STATUS_DONE);
      break;
    case ST_STATUS_DONE:
      st_sleep(1);
      break;
    case ST_STATUS_RESET:
      st_main_reset();
      st_manager_stop();
      st_print_log("[ST_MGR] reset finished\n");
      set_main_status_sync(ST_STATUS_INIT);
      break;
    case ST_STATUS_QUIT:
      quit = 1;
      break;
    default:
      st_print_log("[ST_MGR] un-supported main step.\n");
      break;
    }
  }

  return 0;
}

void
st_manager_reset(void)
{
  st_process_app_sync_lock();
  st_main_reset();
  st_manager_stop();
  st_print_log("[ST_MGR] reset finished\n");
  set_st_manager_status(ST_STATUS_INIT);
  st_process_app_sync_unlock();
}

void
st_manager_quit(void)
{
  set_main_status_sync(ST_STATUS_QUIT);
}

void
st_manager_stop(void)
{
  unset_sc_prov_info();
  st_process_stop();

  st_easy_setup_stop();
  st_print_log("[ST_MGR] easy setup stop done\n");

  st_cloud_manager_stop(device_index);
  st_print_log("[ST_MGR] cloud manager stop done\n");

  st_fota_manager_stop();
  st_print_log("[ST_MGR] fota manager stop done\n");

  st_store_info_initialize();

  deinit_provisioning_info_resource();

  oc_main_shutdown();
}

void
st_manager_deinitialize(void)
{
  st_unregister_status_handler();
  st_turn_off_soft_AP();
  st_vendor_props_shutdown();
  st_port_specific_destroy();
  st_process_destroy();
}

bool
st_register_otm_confirm_handler(st_otm_confirm_cb_t cb)
{
  if (!cb) {
    st_print_log("Failed to register otm confirm handler\n");
    return false;
  }

#ifdef OC_SECURITY
  oc_sec_set_owner_cb((oc_sec_change_owner_cb_t)cb);
#else
  st_print_log("Un-secured build can't handle otm confirm\n");
  return false;
#endif
  return true;
}

void
st_unregister_otm_confirm_handler(void)
{
#ifdef OC_SECURITY
  oc_sec_set_owner_cb(NULL);
#else
  st_print_log("Un-secured build can't handle otm confirm\n");
#endif
}

bool
st_register_status_handler(st_status_cb_t cb)
{
  if (!cb || g_st_status_cb) {
    st_print_log("Failed to register status handler\n");
    return false;
  }

  g_st_status_cb = cb;
  return true;
}

void
st_unregister_status_handler(void)
{
  g_st_status_cb = NULL;
}
