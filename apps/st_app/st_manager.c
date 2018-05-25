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

static provisioning_info_resource g_prov_resource;

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

static bool is_easy_setup_success = false;
void
easy_setup_handler(st_easy_setup_status_t status)
{
  if (status == EASY_SETUP_FINISH) {
    is_easy_setup_success = true;
  } else if (status == EASY_SETUP_FAIL) {
    st_print_log("Easy setup failed!!!\n");
  }
}

static bool is_cloud_access_success = false;
void
cloud_access_handler(st_cloud_access_status_t status)
{
  if (status == CLOUD_ACCESS_FINISH) {
    is_cloud_access_success = true;
  } else if (status == CLOUD_ACCESS_FAIL) {
    st_print_log("Cloud access failed!!!\n");
  } else if (status == CLOUD_ACCESS_DISCONNECTED) {
    st_print_log("Disconnected from cloud!\n");
    is_cloud_access_success = false;
  }
}

static void
set_sc_prov_info(void)
{
  // Set prov info properties
  int target_size = 1;
  char uuid[MAX_UUID_LENGTH];
  int i = 0;

  g_prov_resource.targets = (provisioning_info_targets *)calloc(
    target_size, sizeof(provisioning_info_targets));

  for (i = 0; i < target_size; i++) {
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);
    oc_new_string(&g_prov_resource.targets[i].targetDi, uuid, strlen(uuid));
    oc_new_string(&g_prov_resource.targets[i].targetRt, device_rt,
                  strlen(device_rt));
    g_prov_resource.targets[i].published = false;
  }
  g_prov_resource.targets_size = target_size;
  g_prov_resource.owned = false;
  oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);
  oc_new_string(&g_prov_resource.easysetupdi, uuid, strlen(uuid));

  if (set_properties_for_sc_prov_info(&g_prov_resource) == ES_ERROR)
    st_print_log("SetProvInfo Error\n");

  st_print_log("set_sc_prov_info OUT\n");
}

static void
unset_sc_prov_info(void)
{
  // Come from  target_size in set_sc_prov_info
  int target_size = 1, i = 0;

  oc_free_string(&g_prov_resource.easysetupdi);
  for (i = 0; i < target_size; i++) {
    oc_free_string(&g_prov_resource.targets[i].targetDi);
    oc_free_string(&g_prov_resource.targets[i].targetRt);
  }

  free(g_prov_resource.targets);
}

static void
st_vendor_props_initialize(void)
{
  memset(&st_vendor_props, 0, sizeof(sc_properties));
  oc_new_string(&st_vendor_props.deviceType, st_device_type,
                strlen(st_device_type));
  oc_new_string(&st_vendor_props.deviceSubType, st_device_sub_type,
                strlen(st_device_sub_type));
  st_vendor_props.netConnectionState = NET_STATE_INIT;
  st_vendor_props.discoveryChannel = WIFI_DISCOVERY_CHANNEL_INIT;
  oc_new_string(&st_vendor_props.regSetDev, st_reg_set_device,
                strlen(st_reg_set_device));
  oc_new_string(&st_vendor_props.nwProvInfo, st_network_prov_info,
                strlen(st_network_prov_info));
  oc_new_string(&st_vendor_props.pnpPin, st_pin_number, strlen(st_pin_number));
  oc_new_string(&st_vendor_props.modelNumber, st_model_number,
                strlen(st_model_number));
  oc_new_string(&st_vendor_props.esProtocolVersion, st_protocol_version,
                strlen(st_protocol_version));
}

static void
st_vendor_props_shutdown(void)
{
  oc_free_string(&st_vendor_props.deviceType);
  oc_free_string(&st_vendor_props.deviceSubType);
  oc_free_string(&st_vendor_props.regSetDev);
  oc_free_string(&st_vendor_props.nwProvInfo);
  oc_free_string(&st_vendor_props.pnpPin);
  oc_free_string(&st_vendor_props.modelNumber);
  oc_free_string(&st_vendor_props.esProtocolVersion);
}

static bool
st_main_initialize(void)
{
  if (st_easy_setup_start(&st_vendor_props, easy_setup_handler) != 0) {
    st_print_log("Failed to start easy setup!\n");
    return false;
  }

  st_print_log("easy setup is started.\n");
  while (!is_easy_setup_success && quit != 1) {
    st_process_app_sync_lock();
    if (get_easy_setup_status() == EASY_SETUP_FINISH) {
      st_process_app_sync_unlock();
      break;
    } else if (get_easy_setup_status() == EASY_SETUP_RESET) {
      st_process_app_sync_unlock();
      st_print_log("easy setup timeout!\n");
      goto exit;
    }
    st_process_app_sync_unlock();
    st_sleep(1);
    st_print_log(".");
    fflush(stdout);
  }
  st_print_log("\n");

  if (is_easy_setup_success) {
    st_print_log("easy setup is successfully finished!\n");
    st_easy_setup_stop();
  } else {
    goto exit;
  }

  st_store_t *cloud_info = get_cloud_informations();
  if (!cloud_info) {
    st_print_log("could not get cloud informations.\n");
    goto exit;
  }

  while (st_cloud_access_check_connection(
           oc_string(cloud_info->cloudinfo.ci_server)) != 0 &&
         quit != 1) {
    st_print_log("AP is not connected.\n");
    st_sleep(3);
  }

  // cloud access
  if (st_cloud_access_start(cloud_info, device_index, cloud_access_handler) !=
      0) {
    st_print_log("Failed to access cloud!\n");
    goto exit;
  }

  st_print_log("cloud access started.\n");
  while (!is_cloud_access_success && quit != 1) {
    st_process_app_sync_lock();
    if (get_cloud_access_status(device_index) == CLOUD_ACCESS_FINISH) {
      st_process_app_sync_unlock();
      break;
    }
    st_process_app_sync_unlock();
    st_sleep(1);
    st_print_log(".");
    fflush(stdout);
  }
  st_print_log("\n");

  if (is_cloud_access_success) {
    st_print_log("cloud access successfully finished!\n");
  } else {
    goto exit;
  }
  return true;

exit:
  return false;
}

static void
st_main_deinitialize(void)
{
  if (is_easy_setup_success) {
    st_easy_setup_stop();
    st_print_log("easy setup stop done\n");
  }
  if (is_cloud_access_success) {
    st_cloud_access_stop(device_index);
    st_print_log("cloud access stop done\n");
  }
}

static void
st_main_reset(void)
{
#ifdef OC_SECURITY
  oc_sec_reset();
#endif /* OC_SECURITY */

  st_easy_setup_reset();
  is_easy_setup_success = false;

  st_cloud_access_stop(device_index);
  is_cloud_access_success = false;
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
    st_print_log("st_process_init failed.\n");
    return -1;
  }

  if (st_port_specific_init() != 0) {
    st_print_log("st_port_specific_init failed!");
    st_process_destroy();
    return -1;
  }

  oc_set_max_app_data_size(3072);
  st_vendor_props_initialize();

  return 0;
}

int
st_manager_start(void)
{
  int i = 0;
  int device_num = 0;
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = st_process_signal,
                                       .register_resources =
                                         register_resources };

restart:
  if (st_load() < 0) {
    st_print_log("[ST_App] Could not load store informations.\n");
    return -1;
  }

  if (st_is_easy_setup_finish() != 0) {
    st_print_log("[St_App] Soft AP turn on.\n");
    char ssid[MAX_SSID_LEN + 1];
    if (st_gen_ssid(ssid, device_name, manufacturer, sid) != 0) {
      return -1;
    }
    st_turn_on_soft_AP(ssid, SOFT_AP_PWD, SOFT_AP_CHANNEL);
  }

  if (oc_main_init(&handler) != 0) {
    st_print_log("oc_main_init failed!\n");
    return -1;
  }

  char uuid[MAX_UUID_LENGTH] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(0), uuid, MAX_UUID_LENGTH);
  st_print_log("uuid : %s\n", uuid);

  set_sc_prov_info();

  device_num = oc_core_get_num_devices();
  for (i = 0; i < device_num; i++) {
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(i);
    st_print_log("=== device(%d) endpoint info. ===\n", i);
    while (ep) {
      oc_string_t ep_str;
      if (oc_endpoint_to_string(ep, &ep_str) == 0) {
        st_print_log("-> %s\n", oc_string(ep_str));
        oc_free_string(&ep_str);
      }
      ep = ep->next;
    }
  }
  oc_free_endpoint_list();

  if (st_process_start() != 0) {
    st_print_log("st_process_start failed.\n");
    return -1;
  }

  if (!st_main_initialize()) {
    if (get_easy_setup_status() == EASY_SETUP_RESET) {
      st_main_reset();
      goto reset;
    }
    st_print_log("Failed to start easy setup & cloud access!\n");
    return -1;
  }

  if (st_port_main_loop(&quit) == ST_LOOP_RESET) {
    goto reset;
  }
  return 0;

reset:
  st_main_reset();
  st_print_log("reset finished\n");
  st_manager_stop();
  goto restart;
}

void
st_manager_stop(void)
{
  unset_sc_prov_info();
  st_process_stop();

  st_main_deinitialize();
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
