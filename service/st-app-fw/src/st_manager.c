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

#include "st_manager.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "security/oc_pstat.h"
#include "st_cloud_access.h"
#include "st_easy_setup.h"
#include "st_port.h"
#include "st_process.h"
#include "st_resource_manager.h"
#include "st_store.h"

#define SOFT_AP_PWD "1111122222"
#define SOFT_AP_CHANNEL (6)

typedef enum {
  MAIN_STATUS_INIT,
  MAIN_STATUS_EASY_SETUP,
  MAIN_STATUS_EASY_SETUP_PROGRESSING,
  MAIN_STATUS_EASY_SETUP_DONE,
  MAIN_STATUS_WIFI_CONNECTION_CHECKING,
  MAIN_STATUS_CLOUD_ACCESS,
  MAIN_STATUS_CLOUD_ACCESS_PROGRESSING,
  MAIN_STATUS_CLOUD_ACCESS_DONE,
  MAIN_STATUS_DONE,
  MAIN_STATUS_RESET,
  MAIN_STATUS_QUIT
} st_main_status_t;

static st_main_status_t g_main_status = MAIN_STATUS_INIT;

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

static void
init_platform_cb(CborEncoder *object, void *data)
{
  (void)data;
  oc_set_custom_platform_property(*object, mnmo, sid);
  oc_set_custom_platform_property(*object, mnpv, "1.0");
  oc_set_custom_platform_property(*object, mnos, "1.0");
  oc_set_custom_platform_property(*object, mnhw, "1.0");
  oc_set_custom_platform_property(*object, mnfv, "1.0");
  oc_set_custom_platform_property(*object, vid, vid);
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
    g_main_status = MAIN_STATUS_EASY_SETUP_DONE;
  } else if (status == EASY_SETUP_RESET) {
    st_print_log("[ST_MGR] Easy setup reset!!!\n");
    g_main_status = MAIN_STATUS_RESET;
  } else if (status == EASY_SETUP_FAIL) {
    st_print_log("[ST_MGR] Easy setup failed!!!\n");
    g_main_status = MAIN_STATUS_QUIT;
  }
}

void
cloud_access_handler(st_cloud_access_status_t status)
{
  if (status == CLOUD_ACCESS_FINISH) {
    st_print_log("[ST_MGR] Cloud access succeed!!!\n");
    g_main_status = MAIN_STATUS_CLOUD_ACCESS_DONE;
  } else if (status == CLOUD_ACCESS_RESET) {
    st_print_log("[ST_MGR] Cloud access reset!!!\n");
    g_main_status = MAIN_STATUS_RESET;
  } else if (status == CLOUD_ACCESS_FAIL) {
    st_print_log("[ST_MGR] Cloud access failed!!!\n");
    g_main_status = MAIN_STATUS_QUIT;
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
  st_store_dump();
}

static void
set_main_status_sync(st_main_status_t status)
{
  st_process_app_sync_lock();
  g_main_status = status;
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

  set_main_status_sync(MAIN_STATUS_INIT);

  return 0;
}

static int
st_manager_init_step(void)
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

  if (st_is_easy_setup_finish() != 0) {
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

  char uuid[MAX_UUID_LENGTH] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(0), uuid, MAX_UUID_LENGTH);
  st_print_log("[ST_MGR] uuid : %s\n", uuid);

  set_sc_prov_info();

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
  oc_free_endpoint_list();

  if (st_process_start() != 0) {
    st_print_log("[ST_MGR] st_process_start failed.\n");
    return -1;
  }

  return 0;
}

int
st_manager_start(void)
{
  st_store_t *cloud_info = NULL;

  while (quit != 1) {
    switch (g_main_status) {
    case MAIN_STATUS_INIT:
      if (st_manager_init_step() < 0) {
        return -1;
      }
      cloud_info = NULL;
      set_main_status_sync(MAIN_STATUS_EASY_SETUP);
      break;
    case MAIN_STATUS_EASY_SETUP:
      if (st_easy_setup_start(&st_vendor_props, easy_setup_handler) != 0) {
        st_print_log("[ST_MGR] Failed to start easy setup!\n");
        return -1;
      }
      set_main_status_sync(MAIN_STATUS_EASY_SETUP_PROGRESSING);
      break;
    case MAIN_STATUS_EASY_SETUP_PROGRESSING:
    case MAIN_STATUS_CLOUD_ACCESS_PROGRESSING:
      st_sleep(1);
      st_print_log(".");
      fflush(stdout);
      break;
    case MAIN_STATUS_EASY_SETUP_DONE:
      st_print_log("\n");
      st_easy_setup_stop();
      cloud_info = st_store_get_info();
      if (!cloud_info || !cloud_info->status) {
        st_print_log("[ST_MGR] could not get cloud informations.\n");
        return -1;
      }
      set_main_status_sync(MAIN_STATUS_WIFI_CONNECTION_CHECKING);
      break;
    case MAIN_STATUS_WIFI_CONNECTION_CHECKING:
      if (st_cloud_access_check_connection(&cloud_info->cloudinfo.ci_server) !=
          0) {
        st_print_log("[ST_MGR] AP is not connected.\n");
        st_sleep(3);
      } else {
        set_main_status_sync(MAIN_STATUS_CLOUD_ACCESS);
      }
      break;
    case MAIN_STATUS_CLOUD_ACCESS:
      if (st_cloud_access_start(cloud_info, device_index,
                                cloud_access_handler) != 0) {
        st_print_log("[ST_MGR] Failed to start access cloud!\n");
        return -1;
      }
      set_main_status_sync(MAIN_STATUS_CLOUD_ACCESS_PROGRESSING);
      break;
    case MAIN_STATUS_CLOUD_ACCESS_DONE:
      st_print_log("\n");
      set_main_status_sync(MAIN_STATUS_DONE);
      break;
    case MAIN_STATUS_DONE:
      st_sleep(1);
      break;
    case MAIN_STATUS_RESET:
      st_manager_stop();
      st_main_reset();
      st_print_log("[ST_MGR] reset finished\n");
      set_main_status_sync(MAIN_STATUS_INIT);
      break;
    case MAIN_STATUS_QUIT:
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
  set_main_status_sync(MAIN_STATUS_RESET);
}

void
st_manager_quit(void)
{
  set_main_status_sync(MAIN_STATUS_QUIT);
}

void
st_manager_stop(void)
{
  unset_sc_prov_info();
  st_process_stop();

  st_easy_setup_stop();
  st_print_log("[ST_MGR] easy setup stop done\n");

  st_cloud_access_stop(device_index);
  st_print_log("[ST_MGR] cloud access stop done\n");

  st_store_info_initialize();

  oc_main_shutdown();
}

void
st_manager_deinitialize(void)
{
  st_turn_off_soft_AP();
  st_vendor_props_shutdown();
  st_port_specific_destroy();
  st_process_destroy();
}
