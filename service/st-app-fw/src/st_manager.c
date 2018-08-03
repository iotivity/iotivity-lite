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
#include "oc_security.h"
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
#ifdef STATE_MODEL
#include "st_state_util.h"
#else
#include "st_status_queue.h"
#endif
#include "st_store.h"

#define EXIT_WITH_ERROR(err)                                                   \
  do {                                                                         \
    st_err_ret = err;                                                          \
    goto exit;                                                                 \
  } while (0);

#define SOFT_AP_PWD "1111122222"
#define SOFT_AP_CHANNEL (6)
#define AP_CONNECT_RETRY_LIMIT (20)

#define ST_BUFFER_SIZE (3072)

extern int st_register_resources(int device);
extern int st_fota_manager_start(void);
extern void st_fota_manager_stop(void);

#ifndef STATE_MODEL
OC_MEMB(st_status_item_s, st_status_item_t, MAX_STATUS_COUNT);

static st_status_t g_main_status = ST_STATUS_IDLE;
#endif
static st_status_cb_t g_st_status_cb = NULL;

static sc_properties st_vendor_props;

static sec_provisioning_info g_prov_resource;

static int device_index = 0;

#ifdef STATE_MODEL

typedef enum {
  ST_STATE_IDLE,
  ST_STATE_READY,
  ST_STATE_EASYSETUP_PROCESSING,
  ST_STATE_WIFI_CONNECTING,
  ST_STATE_CLOUDMANAGER_PROCESSING,
  ST_STATE_RUNNING,
  ST_STATE_MAX // indicate num of state &  no change
} st_state;

typedef st_error_t (*st_state_handler)(st_evt evt);

static st_error_t handler_on_state_idle(st_evt evt);
static st_error_t handler_on_state_ready(st_evt evt);
static st_error_t handler_on_state_easysetup_processing(st_evt evt);
static st_error_t handler_on_state_wifi_connecting(st_evt evt);
static st_error_t handler_on_state_cloudmanager_processing(st_evt evt);
static st_error_t handler_on_state_running(st_evt evt);

// same order of st_state
const st_state_handler g_handler[ST_STATE_MAX] = {
  handler_on_state_idle,
  handler_on_state_ready,
  handler_on_state_easysetup_processing,
  handler_on_state_wifi_connecting,
  handler_on_state_cloudmanager_processing,
  handler_on_state_running
};

st_state g_current_state = ST_STATE_IDLE;

void state_easy_setup_handler(st_easy_setup_status_t status);

#else
static bool g_start_fail = false;

static void set_st_manager_status(st_status_t status);

static void st_manager_evt_stop_handler(void);

static void st_manager_evt_reset_handler(void);
#endif

typedef struct
{
  oc_string_t model_number;
  oc_string_t platform_version;
  oc_string_t os_version;
  oc_string_t hardware_version;
  oc_string_t firmware_version;
  oc_string_t vendor_id;
} platform_cb_data_t;

static platform_cb_data_t platform_cb_data;

static void
free_platform_cb_data(void)
{
  if (oc_string(platform_cb_data.model_number))
    oc_free_string(&platform_cb_data.model_number);
  if (oc_string(platform_cb_data.platform_version))
    oc_free_string(&platform_cb_data.platform_version);
  if (oc_string(platform_cb_data.os_version))
    oc_free_string(&platform_cb_data.os_version);
  if (oc_string(platform_cb_data.hardware_version))
    oc_free_string(&platform_cb_data.hardware_version);
  if (oc_string(platform_cb_data.firmware_version))
    oc_free_string(&platform_cb_data.firmware_version);
  if (oc_string(platform_cb_data.vendor_id))
    oc_free_string(&platform_cb_data.vendor_id);
}

static platform_cb_data_t *
clone_platform_cb_data(st_specification_t *spec)
{
  if (!spec)
    return NULL;
  free_platform_cb_data();
  oc_new_string(&platform_cb_data.model_number,
                oc_string(spec->platform.model_number),
                oc_string_len(spec->platform.model_number));
  oc_new_string(&platform_cb_data.platform_version,
                oc_string(spec->platform.platform_version),
                oc_string_len(spec->platform.platform_version));
  oc_new_string(&platform_cb_data.os_version,
                oc_string(spec->platform.os_version),
                oc_string_len(spec->platform.os_version));
  oc_new_string(&platform_cb_data.hardware_version,
                oc_string(spec->platform.hardware_version),
                oc_string_len(spec->platform.hardware_version));
  oc_new_string(&platform_cb_data.firmware_version,
                oc_string(spec->platform.firmware_version),
                oc_string_len(spec->platform.firmware_version));
  oc_new_string(&platform_cb_data.vendor_id,
                oc_string(spec->platform.vendor_id),
                oc_string_len(spec->platform.vendor_id));
  return &platform_cb_data;
}

static void
init_platform_cb(void *data)
{
  if (!data)
    return;
  platform_cb_data_t *platform = data;
  oc_set_custom_platform_property(mnmo, oc_string(platform->model_number));
  oc_set_custom_platform_property(mnpv, oc_string(platform->platform_version));
  oc_set_custom_platform_property(mnos, oc_string(platform->os_version));
  oc_set_custom_platform_property(mnhw, oc_string(platform->hardware_version));
  oc_set_custom_platform_property(mnfv, oc_string(platform->firmware_version));
  oc_set_custom_platform_property(vid, oc_string(platform->vendor_id));
}

static int
app_init(void)
{
  st_specification_t *spec = st_data_mgr_get_spec_info();
  platform_cb_data_t *platform_data = clone_platform_cb_data(spec);
  int ret = oc_init_platform(oc_string(spec->platform.manufacturer_name),
                             init_platform_cb, platform_data);
  ret |= oc_add_device("/oic/d", oc_string(spec->device.device_type),
                       oc_string(spec->device.device_name),
                       oc_string(spec->device.spec_version),
                       oc_string(spec->device.data_model_version), NULL, NULL);
  return ret;
}

static void
register_resources(void)
{
  if (st_register_resources(device_index) != 0) {
    st_print_log("[ST_MGR] register_resources failed.\n");
  }
}
#ifndef STATE_MODEL
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
    g_start_fail = true;
    set_st_manager_status(ST_STATUS_STOP);
  }
}

void
cloud_manager_handler(st_cloud_manager_status_t status)
{
  if (status == CLOUD_MANAGER_FINISH) {
    st_print_log("[ST_MGR] Cloud manager succeed!!!\n");
    set_st_manager_status(ST_STATUS_DONE);
  } else if (status == CLOUD_MANAGER_FAIL) {
    st_print_log("[ST_MGR] Cloud manager failed!!!\n");
    g_start_fail = true;
    set_st_manager_status(ST_STATUS_STOP);
  } else if (status == CLOUD_MANAGER_RE_CONNECTING) {
    st_print_log("[ST_MGR] Cloud manager re connecting!!!\n");
    set_st_manager_status(ST_STATUS_CLOUD_MANAGER_PROGRESSING);
  } else if (status == CLOUD_MANAGER_RESET) {
    st_print_log("[ST_MGR] Cloud manager reset!!!\n");
    set_st_manager_status(ST_STATUS_RESET);
  }
}
#endif /* !STATE_MODEL */

static void
set_sc_prov_info(void)
{
  // Set prov info properties
  int target_size = 1;
  char uuid[OC_UUID_LEN];
  int i = 0;

  g_prov_resource.targets = (sec_provisioning_info_targets *)calloc(
    target_size, sizeof(sec_provisioning_info_targets));
  if (!g_prov_resource.targets) {
    st_print_log("[ST_MGR] g_prov_resource calloc Error\n");
    return;
  }

  st_specification_t *spec = st_data_mgr_get_spec_info();
  for (i = 0; i < target_size; i++) {
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, OC_UUID_LEN);
    oc_new_string(&g_prov_resource.targets[i].target_di, uuid, strlen(uuid));
    oc_new_string(&g_prov_resource.targets[i].target_rt,
                  oc_string(spec->device.device_type),
                  oc_string_len(spec->device.device_type));
    g_prov_resource.targets[i].published = false;
  }
  g_prov_resource.targets_size = target_size;
  g_prov_resource.owned = false;
  oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, OC_UUID_LEN);
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

  if (oc_string(g_prov_resource.easysetup_di))
    oc_free_string(&g_prov_resource.easysetup_di);

  if (g_prov_resource.targets) {
    for (i = 0; i < target_size; i++) {
      if (oc_string(g_prov_resource.targets[i].target_di))
        oc_free_string(&g_prov_resource.targets[i].target_di);
      if (oc_string(g_prov_resource.targets[i].target_rt))
        oc_free_string(&g_prov_resource.targets[i].target_rt);
    }
    free(g_prov_resource.targets);
    g_prov_resource.targets = NULL;
  }
}

static void
st_vendor_props_initialize(void)
{
  memset(&st_vendor_props, 0, sizeof(sc_properties));
  st_specification_t  *specification = st_data_mgr_get_spec_info();
  if (!specification) {
    st_print_log("[ST_MGR] specification list not exist\n");
    return;
  }

  st_print_log("[ST_MGR] specification model no %s\n",
               oc_string(specification->platform.model_number));
  oc_new_string(&st_vendor_props.model,
                oc_string(specification->platform.model_number),
                oc_string_len(specification->platform.model_number));
}

static void
st_vendor_props_shutdown(void)
{
  if (oc_string(st_vendor_props.model))
    oc_free_string(&st_vendor_props.model);
}

#ifndef STATE_MODEL
static void
st_main_reset(void)
{
#ifdef OC_SECURITY
  oc_sec_reset();
#endif /* OC_SECURITY */
  st_store_info_initialize();
  if (st_store_dump() <= 0) {
    st_print_log("[ST_MGR] st_store_dump failed.\n");
  }
}

static oc_event_callback_retval_t
status_callback(void *data)
{
  if (!data)
    return OC_EVENT_DONE;

  st_status_item_t *status = (st_status_item_t *)data;

  if (g_st_status_cb)
    g_st_status_cb(status->status);

  oc_memb_free(&st_status_item_s, data);
  return OC_EVENT_DONE;
}

static void
set_st_manager_status(st_status_t status)
{
  if (st_status_queue_add(status) != 0) {
    st_print_log("[ST_MGR] st_status_queue_add failed\n");
  }

  st_status_item_t *cb_item = oc_memb_alloc(&st_status_item_s);
  cb_item->status = status;
  oc_set_delayed_callback(cb_item, status_callback, 0);
  _oc_signal_event_loop();
}

static void
set_main_status_sync(st_status_t status)
{
  st_process_app_sync_lock();
  set_st_manager_status(status);
  st_process_app_sync_unlock();
}

st_error_t
st_manager_initialize(void)
{
  if (g_main_status != ST_STATUS_IDLE) {
    if (g_main_status == ST_STATUS_INIT) {
      return ST_ERROR_STACK_ALREADY_INITIALIZED;
    } else {
      return ST_ERROR_STACK_RUNNING;
    }
  }

#ifdef OC_SECURITY
#ifdef __TIZENRT__
  oc_storage_config("/mnt/st_things_creds");
#else
  oc_storage_config("./st_things_creds");
#endif
#endif /* OC_SECURITY */

  if (st_process_init() != 0) {
    st_print_log("[ST_MGR] st_process_init failed.\n");
    return ST_ERROR_OPERATION_FAILED;
  }

  if (st_port_specific_init() != 0) {
    st_print_log("[ST_MGR] st_port_specific_init failed!\n");
    st_process_destroy();
    return ST_ERROR_OPERATION_FAILED;
  }

  if (st_status_queue_initialize() != 0) {
    st_print_log("[ST_MGR] st_status_queue_initialize failed!\n");
    st_process_destroy();
    st_port_specific_destroy();
    return ST_ERROR_OPERATION_FAILED;
  }

  oc_set_max_app_data_size(ST_BUFFER_SIZE);

  st_unregister_status_handler();
  g_main_status = ST_STATUS_INIT;

  return ST_ERROR_NONE;
}
#endif /* !STATE_MODEL */

#ifdef OC_SECURITY
static void
set_otm_method(void)
{
  st_configuration_t *conf = st_data_mgr_get_config_info();

  oc_doxm_method_t otm_method = conf->easy_setup.ownership_transfer_method;
  oc_set_doxm(otm_method);
}
#endif /* OC_SECURITY */

#ifndef STATE_MODEL

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

  st_vendor_props_initialize();

  if (st_is_easy_setup_finish() != 0) {
#ifndef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
    st_wifi_ap_t *ap_list = NULL;
    st_wifi_scan(&ap_list);
    st_wifi_set_cache(ap_list);
#endif

    // Turn on soft-ap
    st_print_log("[ST_MGR] Soft AP turn on.\n");

    char ssid[MAX_SSID_LEN + 1];
    st_specification_t *spec = st_data_mgr_get_spec_info();
    if (st_gen_ssid(ssid, oc_string(spec->device.device_name),
                    oc_string(spec->platform.manufacturer_name),
                    oc_string(spec->platform.model_number)) != 0) {
      return -1;
    }
    st_turn_on_soft_AP(ssid, SOFT_AP_PWD, SOFT_AP_CHANNEL);
  }

  if (oc_main_init(&handler) != 0) {
    st_print_log("[ST_MGR] oc_main_init failed!\n");
    return -1;
  }

#ifdef OC_SECURITY
  set_otm_method();
#endif /* OC_SECURITY */

  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(0), uuid, OC_UUID_LEN);
  st_print_log("[ST_MGR] uuid : %s\n", uuid);

  set_sc_prov_info();
  st_fota_manager_start();
  st_data_mgr_info_free();

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

st_error_t
st_manager_start(void)
{
  st_status_item_t *item = st_status_queue_get_head();
  if (item) {
    st_status_queue_remove_all_items();
  }

  if (g_main_status == ST_STATUS_IDLE) {
    return ST_ERROR_STACK_NOT_INITIALIZED;
  } else if (g_main_status != ST_STATUS_INIT) {
    return ST_ERROR_STACK_RUNNING;
  }

  if (st_status_queue_add(ST_STATUS_INIT) != 0) {
    return ST_ERROR_OPERATION_FAILED;
  }

  st_store_t *store_info = NULL;
  st_error_t st_err_ret = ST_ERROR_NONE;
  int conn_cnt = 0;
  int quit = 0;
  g_start_fail = false;

  while (quit != 1) {
    item = st_status_queue_pop();
    if (!item && quit != 1) {
      st_status_queue_wait_signal();
      continue;
    }
    g_main_status = item->status;
    st_status_queue_free_item(item);

    switch (g_main_status) {
    case ST_STATUS_INIT:
      st_process_app_sync_lock();
      if (st_manager_stack_init() < 0) {
        st_process_app_sync_unlock();
        EXIT_WITH_ERROR(ST_ERROR_OPERATION_FAILED);
      }
      store_info = NULL;
      set_st_manager_status(ST_STATUS_EASY_SETUP_START);
      st_process_app_sync_unlock();
      break;
    case ST_STATUS_EASY_SETUP_START:
      st_process_app_sync_lock();
      if (st_is_easy_setup_finish() == 0) {
        set_st_manager_status(ST_STATUS_EASY_SETUP_DONE);
      } else {
        if (st_easy_setup_start(&st_vendor_props, easy_setup_handler) != 0) {
          st_print_log("[ST_MGR] Failed to start easy setup!\n");
          st_process_app_sync_unlock();
          EXIT_WITH_ERROR(ST_ERROR_OPERATION_FAILED);
        }
        set_st_manager_status(ST_STATUS_EASY_SETUP_PROGRESSING);
      }
      st_process_app_sync_unlock();
      break;
    case ST_STATUS_EASY_SETUP_PROGRESSING:
    case ST_STATUS_CLOUD_MANAGER_PROGRESSING:
      st_print_log("[ST_MGR] Progressing...\n");
      break;
    case ST_STATUS_EASY_SETUP_DONE:
      st_process_app_sync_lock();
      st_easy_setup_stop();
      store_info = st_store_get_info();
      if (!store_info || !store_info->status) {
        st_print_log("[ST_MGR] could not get cloud informations.\n");
        st_process_app_sync_unlock();
        EXIT_WITH_ERROR(ST_ERROR_OPERATION_FAILED);
      }
      set_st_manager_status(ST_STATUS_WIFI_CONNECTING);
      st_process_app_sync_unlock();
      break;
    case ST_STATUS_WIFI_CONNECTING:
      st_process_app_sync_lock();
      st_turn_off_soft_AP();
      st_connect_wifi(oc_string(store_info->accesspoint.ssid),
                      oc_string(store_info->accesspoint.pwd));
      set_st_manager_status(ST_STATUS_WIFI_CONNECTION_CHECKING);
      st_process_app_sync_unlock();
      break;
    case ST_STATUS_WIFI_CONNECTION_CHECKING:
      st_process_app_sync_lock();
      int ret =
        st_cloud_manager_check_connection(&store_info->cloudinfo.ci_server);
      st_process_app_sync_unlock();
      if (ret != 0) {
        st_print_log("[ST_MGR] AP is not connected.\n");
        conn_cnt++;
        if (conn_cnt > AP_CONNECT_RETRY_LIMIT) {
          conn_cnt = 0;
          set_main_status_sync(ST_STATUS_RESET);
        } else if (conn_cnt == (AP_CONNECT_RETRY_LIMIT >> 1)) {
          set_main_status_sync(ST_STATUS_WIFI_CONNECTING);
        } else {
          st_sleep(3);
          if (st_status_queue_add(ST_STATUS_WIFI_CONNECTION_CHECKING) != 0) {
            EXIT_WITH_ERROR(ST_ERROR_OPERATION_FAILED);
          }
        }
      } else {
        conn_cnt = 0;
        set_main_status_sync(ST_STATUS_CLOUD_MANAGER_START);
      }
      break;
    case ST_STATUS_CLOUD_MANAGER_START:
      st_process_app_sync_lock();
      if (st_cloud_manager_start(store_info, device_index,
                                 cloud_manager_handler) != 0) {
        st_print_log("[ST_MGR] Failed to start cloud manager!\n");
        st_process_app_sync_unlock();
        EXIT_WITH_ERROR(ST_ERROR_OPERATION_FAILED);
      }
      set_st_manager_status(ST_STATUS_CLOUD_MANAGER_PROGRESSING);
      st_process_app_sync_unlock();
      break;
    case ST_STATUS_DONE:
      st_print_log("[ST_MGR] Ready to Control ST-Things\n");
      break;
    case ST_STATUS_RESET:
      st_process_stop();
      st_process_app_sync_lock();
      st_manager_evt_reset_handler();
      st_process_app_sync_unlock();
      break;
    case ST_STATUS_STOP:
      quit = 1;
      if (g_start_fail) {
        EXIT_WITH_ERROR(ST_ERROR_OPERATION_FAILED);
      }
      break;
    default:
      st_print_log("[ST_MGR] un-supported main step.\n");
      break;
    }
  }

exit:
  st_process_stop();
  st_process_app_sync_lock();
  st_manager_evt_stop_handler();
  st_status_queue_remove_all_items();
  g_main_status = ST_STATUS_INIT;
  st_process_app_sync_unlock();
  return st_err_ret;
}

st_error_t
st_manager_reset(void)
{
  if (g_main_status == ST_STATUS_IDLE)
    return ST_ERROR_STACK_NOT_INITIALIZED;

  st_process_stop();
  st_process_app_sync_lock();
  st_manager_evt_reset_handler();
  st_process_app_sync_unlock();
  return ST_ERROR_NONE;
}

st_error_t
st_manager_stop(void)
{
  if (g_main_status == ST_STATUS_IDLE) {
    return ST_ERROR_STACK_NOT_INITIALIZED;
  } else if (g_main_status == ST_STATUS_INIT) {
    return ST_ERROR_STACK_NOT_STARTED;
  }
  set_main_status_sync(ST_STATUS_STOP);
  return ST_ERROR_NONE;
}

st_error_t
st_manager_deinitialize(void)
{
  if (g_main_status == ST_STATUS_IDLE) {
    return ST_ERROR_STACK_NOT_INITIALIZED;
  } else if (g_main_status != ST_STATUS_INIT) {
    return ST_ERROR_STACK_RUNNING;
  }

  st_free_device_profile();
  st_unregister_status_handler();
  st_unregister_otm_confirm_handler();
  st_turn_off_soft_AP();
  st_vendor_props_shutdown();
  st_status_queue_deinitialize();
  st_port_specific_destroy();
  st_process_destroy();

  g_main_status = ST_STATUS_IDLE;
  return ST_ERROR_NONE;
}
#endif /* !STATE_MODEL */

bool
st_register_otm_confirm_handler(st_otm_confirm_cb_t cb)
{
  if (!cb) {
    st_print_log("[ST_MGR] Failed to register otm confirm handler\n");
    return false;
  }

#ifdef OC_SECURITY
  oc_sec_set_owner_cb((oc_sec_change_owner_cb_t)cb);
  return true;
#else
  st_print_log("[ST_MGR] Un-secured build can't handle otm confirm\n");
  return false;
#endif
}

void
st_unregister_otm_confirm_handler(void)
{
#ifdef OC_SECURITY
  oc_sec_set_owner_cb(NULL);
#else
  st_print_log("[ST_MGR] Un-secured build can't handle otm confirm\n");
#endif
}

bool
st_register_status_handler(st_status_cb_t cb)
{
  if (!cb) {
    st_print_log("[ST_MGR] Failed to register status - invalid parameter\n");
    return false;
  }
  if (g_st_status_cb) {
    st_print_log(
      "[ST_MGR] Failed to register status handler - already registered\n");
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

bool
st_register_rpk_handler(st_rpk_handle_cpubkey_and_token_cb_t pubkey_cb,
                        st_rpk_handle_priv_key_cb_t privkey_cb)
{
  if (!pubkey_cb || !privkey_cb) {
    st_print_log(
      "[ST_MGR] Failed to register RPK handler - invalid parameter\n");
    return false;
  }

#ifdef OC_SECURITY
  oc_sec_set_cpubkey_and_token_load((oc_sec_get_cpubkey_and_token)pubkey_cb);
  oc_sec_set_own_key_load((oc_sec_get_own_key)privkey_cb);
  return true;
#else  /* OC_SECURITY */
  st_print_log("[ST_MGR] Un-secured build can't handle RPK\n");
  return false;
#endif /* !OC_SECURITY */
}

void
st_unregister_rpk_handler(void)
{
#ifdef OC_SECURITY
  oc_sec_unset_cpubkey_and_token_load();
  oc_sec_unset_own_key_load();
#else  /* OC_SECURITY */
  st_print_log("[ST_MGR] Un-secured build can't handle RPK\n");
#endif /* !OC_SECURITY */
}

#ifndef STATE_MODEL
static void
st_manager_evt_stop_handler(void)
{
  unset_sc_prov_info();

  st_easy_setup_stop();
  st_print_log("[ST_MGR] easy setup stop done\n");

  st_cloud_manager_stop(device_index);
  st_print_log("[ST_MGR] cloud manager stop done\n");

  st_fota_manager_stop();
  st_print_log("[ST_MGR] fota manager stop done\n");

  st_store_info_initialize();

  deinit_provisioning_info_resource();

  oc_main_shutdown();

  free_platform_cb_data();
}

static void
st_manager_evt_reset_handler(void)
{
  st_main_reset();
  st_manager_evt_stop_handler();
  st_status_queue_remove_all_items_without_stop();
  set_st_manager_status(ST_STATUS_INIT);
  st_print_log("[ST_MGR] reset finished\n");
}

#else
static void
st_manager_evt_with_signal(const st_evt evt)
{
  st_evt_push(evt);
  st_process_signal();
}

static int
st_manager_stack_start(void)
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

  st_vendor_props_initialize();

  if (st_is_easy_setup_finish() != 0) {
#ifndef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
    st_wifi_ap_t *ap_list = NULL;
    st_wifi_scan(&ap_list);
    st_wifi_set_cache(ap_list);
#endif

    // Turn on soft-ap
    st_print_log("[ST_MGR] Soft AP turn on.\n");

    char ssid[MAX_SSID_LEN + 1];
    st_specification_t *spec = st_data_mgr_get_spec_info();
    if (st_gen_ssid(ssid, oc_string(spec->device.device_name),
                    oc_string(spec->platform.manufacturer_name),
                    oc_string(spec->platform.model_number)) != 0) {
      return -1;
    }
    st_turn_on_soft_AP(ssid, SOFT_AP_PWD, SOFT_AP_CHANNEL);
  }

  if (oc_main_init(&handler) != 0) {
    st_print_log("[ST_MGR] oc_main_init failed!\n");
    return -1;
  }

#ifdef OC_SECURITY
  set_otm_method();
#endif /* OC_SECURITY */

  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(0), uuid, OC_UUID_LEN);
  st_print_log("[ST_MGR] uuid : %s\n", uuid);

  set_sc_prov_info();
  st_fota_manager_start();
  st_data_mgr_info_free();

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

  return 0;
}

static void
st_manager_stack_stop(void)
{
  unset_sc_prov_info();

  st_easy_setup_stop();
  st_print_log("[ST_MGR] easy setup stop done\n");

  st_cloud_manager_stop(device_index);
  st_print_log("[ST_MGR] cloud manager stop done\n");

  st_fota_manager_stop();
  st_print_log("[ST_MGR] fota manager stop done\n");

  st_store_info_initialize();

  deinit_provisioning_info_resource();

  oc_main_shutdown();

  free_platform_cb_data();
}

static bool
st_manager_stack_reset(void)
{

#ifdef OC_SECURITY
  oc_sec_reset();
#endif /* OC_SECURITY */
  st_store_info_initialize();
  if (st_store_dump() <= 0) {
    st_print_log("[ST_MGR] st_store_dump failed.\n");
    return false;
  }

  st_manager_stack_stop();
  if (st_manager_stack_start() < 0) {
    st_print_log("[ST_MGR] st_manager_stack_start failed.\n");
    return false;
  }

  if (st_easy_setup_start(&st_vendor_props, state_easy_setup_handler) != 0) {
    st_print_log("[ST_MGR] Failed to start easy setup!\n");
    st_manager_stack_stop();
    return false;
  }
  return true;
}

static void
run_status_callback(st_state state)
{
  // to avoid memory leak
  if (g_st_status_cb && ((state == ST_STATE_RUNNING) ||
                         (state == ST_STATE_EASYSETUP_PROCESSING) ||
                         (state == ST_STATE_WIFI_CONNECTING) ||
                         (state == ST_STATE_CLOUDMANAGER_PROCESSING) ||
                         (state == ST_STATE_READY))) {

    st_status_t st_status_item;

    if (state == ST_STATE_RUNNING) {
      st_status_item = ST_STATUS_DONE;
    } else if (state == ST_STATE_EASYSETUP_PROCESSING) {
      st_status_item = ST_STATUS_EASY_SETUP_PROGRESSING;
    } else if (state == ST_STATE_WIFI_CONNECTING) {
      st_status_item = ST_STATUS_WIFI_CONNECTION_CHECKING;
    } else if (state == ST_STATE_CLOUDMANAGER_PROCESSING) {
      st_status_item = ST_STATUS_CLOUD_MANAGER_PROGRESSING;
    } else { // currently, (state == ST_STATE_READY)
      st_status_item = ST_STATUS_STOP;
    }

    g_st_status_cb(st_status_item);
  }
}
static st_state
get_current_state(void)
{
  return g_current_state;
}

static void
set_current_state(st_state state)
{
  if (state != ST_STATE_MAX) {
    g_current_state = state;
    run_status_callback(state);
  }
}

void
state_easy_setup_handler(st_easy_setup_status_t status)
{
  if (status == EASY_SETUP_FINISH) {
    st_print_log("[ST_MGR] Easy setup succeed!!!\n");
    st_print_log("\n");
    st_manager_evt_with_signal(ST_EVT_START_WIFI_CONNECT);
  } else if (status == EASY_SETUP_RESET) {
    st_print_log("[ST_MGR] Easy setup reset!!!\n");
    st_manager_evt_with_signal(ST_EVT_RESET);
  } else if (status == EASY_SETUP_FAIL) {
    st_print_log("[ST_MGR] Easy setup failed!!!\n");
    st_manager_evt_with_signal(ST_EVT_STOP);
  }
}

void
state_cloud_manager_handler(st_cloud_manager_status_t status)
{
  if (status == CLOUD_MANAGER_FINISH) {
    st_print_log("[ST_MGR] Cloud manager succeed!!!\n");
    st_manager_evt_with_signal(ST_EVT_RUN);
  } else if (status == CLOUD_MANAGER_FAIL) {
    st_print_log("[ST_MGR] Cloud manager failed!!!\n");
    st_manager_evt_with_signal(ST_EVT_STOP);
  } else if (status == CLOUD_MANAGER_RE_CONNECTING) {
    st_print_log("[ST_MGR] Cloud manager re connecting!!!\n");
    // nothing.. just waiting
  } else if (status == CLOUD_MANAGER_RESET) {
    st_print_log("[ST_MGR] Cloud manager reset!!!\n");
    st_manager_evt_with_signal(ST_EVT_RESET);
  }
}

static bool
connect_wifi_stored_info(void)
{

  st_store_t *store_info = NULL;
  store_info = st_store_get_info();

  if (!store_info || !store_info->status) {
    st_print_log("[ST_MGR] could not get cloud informations.\n");
    return false;
  }

  st_turn_off_soft_AP();
  st_connect_wifi(oc_string(store_info->accesspoint.ssid),
                  oc_string(store_info->accesspoint.pwd));

  return true;
}

static void
change_ready_to_idle(void)
{
  st_free_device_profile();
  st_unregister_status_handler();
  st_unregister_otm_confirm_handler();
  st_turn_off_soft_AP();
  st_vendor_props_shutdown();
  st_port_specific_destroy();
  st_process_stop();
  st_process_destroy(); //  st_process_state_sync_unlock(); doesn't work after
                        //  destory
}

static st_error_t
do_evt_reset_then_set_state(void)
{
  if (!st_manager_stack_reset()) {
    set_current_state(ST_STATE_READY);
    return ST_ERROR_OPERATION_FAILED;
  } else {
    set_current_state(ST_STATE_EASYSETUP_PROCESSING);
  }
  return ST_ERROR_NONE;
}

static void
do_evt_stop_then_set_state(void)
{
  st_manager_stack_stop();
  set_current_state(ST_STATE_READY);
}

st_error_t
handle_request(st_evt evt)
{
  return g_handler[get_current_state()](evt);
}

static st_error_t
handler_on_state_idle(st_evt evt)
{

  st_error_t st_error_ret = ST_ERROR_NONE;

  if (evt == ST_EVT_INIT) {

#ifdef OC_SECURITY
#ifdef __TIZENRT__
    oc_storage_config("/mnt/st_things_creds");
#else
    oc_storage_config("./st_things_creds");
#endif
#endif /* OC_SECURITY */

    // after init.  signal and st_process_state_sync_lock()  are available  and
    // meaningful
    if (st_process_init() != 0) {
      st_print_log("[ST_MGR] st_process_init failed.\n");
      st_error_ret = ST_ERROR_OPERATION_FAILED;
    } else {

      st_process_start();

      if (st_port_specific_init() != 0) {
        st_print_log("[ST_MGR] st_port_specific_init failed!");

        st_process_destroy();
        // signal and st_process_state_sync_lock()  are unavailable  and
        // unmeaningful
        st_error_ret = ST_ERROR_OPERATION_FAILED;
      } else {
        oc_set_max_app_data_size(ST_BUFFER_SIZE);
        st_unregister_status_handler();
        set_current_state(ST_STATE_READY);
      }
    }
  } else {
    st_error_ret = ST_ERROR_OPERATION_FAILED;
  }
  return st_error_ret;
}

static st_error_t
handler_on_state_ready(st_evt evt)
{
  st_error_t st_error_ret = ST_ERROR_NONE;

  if (evt == ST_EVT_START) {

    if (st_manager_stack_start() < 0) {
      return ST_ERROR_OPERATION_FAILED;
    }

    if (st_is_easy_setup_finish() == 0) {
      if (connect_wifi_stored_info()) {
        set_current_state(ST_STATE_WIFI_CONNECTING);
        st_manager_evt_with_signal(ST_EVT_RETRY_WIFI_CONNECT);
      } else {
        st_manager_stack_stop();
        st_error_ret = ST_ERROR_OPERATION_FAILED;
      }
    } else { // start easysetup
      if (st_easy_setup_start(&st_vendor_props, state_easy_setup_handler) !=
          0) {
        st_print_log("[ST_MGR] Failed to start easy setup!\n");
        st_manager_stack_stop();
        return ST_ERROR_OPERATION_FAILED;
      }
      set_current_state(ST_STATE_EASYSETUP_PROCESSING);
    }

  } else if (evt == ST_EVT_DEINIT) {
    change_ready_to_idle();
    set_current_state(ST_STATE_IDLE);
  } else if (evt == ST_EVT_RESET) {
    st_error_ret = do_evt_reset_then_set_state();
  } else {
    st_error_ret = ST_ERROR_OPERATION_FAILED;
  }

  return st_error_ret;
}

static st_error_t
handler_on_state_easysetup_processing(st_evt evt)
{

  st_error_t st_error_ret = ST_ERROR_NONE;

  if (evt == ST_EVT_STOP) {
    do_evt_stop_then_set_state();
  } else if (evt == ST_EVT_START_WIFI_CONNECT) {

    st_easy_setup_stop();

    if (connect_wifi_stored_info()) {
      set_current_state(ST_STATE_WIFI_CONNECTING);
      st_manager_evt_with_signal(ST_EVT_RETRY_WIFI_CONNECT);
    } else { // failure
      st_manager_stack_stop();

      set_current_state(ST_STATE_READY);
      st_error_ret = ST_ERROR_OPERATION_FAILED;
    }

  } else if (evt == ST_EVT_RESET) {
    st_error_ret = do_evt_reset_then_set_state();
  } else {
    st_error_ret = ST_ERROR_OPERATION_FAILED;
  }

  return st_error_ret;
}

static st_error_t
handler_on_state_wifi_connecting(st_evt evt)
{
  st_error_t st_error_ret = ST_ERROR_NONE;
  static int conn_cnt = 0;

  if (evt == ST_EVT_STOP) {
    do_evt_stop_then_set_state();
  } else if (evt == ST_EVT_RETRY_WIFI_CONNECT) { // available

    st_store_t *store_info = st_store_get_info();
    if (store_info == NULL) {
      st_print_log("[ST_MGR] failure to get store info.\n");
      return ST_ERROR_OPERATION_FAILED;
    }

    if ((conn_cnt < AP_CONNECT_RETRY_LIMIT) &&
        0 != (st_cloud_manager_check_connection(
               &store_info->cloudinfo.ci_server))) {

      conn_cnt++;
      st_print_log("[ST_MGR] AP is not connected.\n");
      st_print_log("[ST_MGR] conn_cnt %d.\n", conn_cnt);

      if (conn_cnt == ((AP_CONNECT_RETRY_LIMIT) >> 1)) {

        if (connect_wifi_stored_info()) {
          store_info = st_store_get_info();
          // to avoid calling recursive
        } else {
          // fail.
          conn_cnt = AP_CONNECT_RETRY_LIMIT;
        }
      }

      st_manager_evt_with_signal(ST_EVT_RETRY_WIFI_CONNECT);
      st_sleep(3);

    } else {
      if (conn_cnt >= AP_CONNECT_RETRY_LIMIT) {
        st_error_ret = ST_ERROR_OPERATION_FAILED;
        // failure
      } else {
        // connect
        if (st_cloud_manager_start(store_info, device_index,
                                   state_cloud_manager_handler) != 0) {
          st_print_log("[ST_MGR] Failed to start cloud manager!\n");
          // do something
          st_error_ret = ST_ERROR_OPERATION_FAILED;
        } else {

          set_current_state(ST_STATE_CLOUDMANAGER_PROCESSING);
        }
      }
      conn_cnt = 0;
    }

  } else if (evt == ST_EVT_RESET) {
    st_error_ret = do_evt_reset_then_set_state();
  } else {
    st_error_ret = ST_ERROR_OPERATION_FAILED;
  }

  return st_error_ret;
}

static st_error_t
handler_on_state_cloudmanager_processing(st_evt evt)
{

  st_error_t st_error_ret = ST_ERROR_NONE;

  if (evt == ST_EVT_STOP) {
    do_evt_stop_then_set_state();
  } else if (evt == ST_EVT_RUN) {
    // to save memory
    set_current_state(ST_STATE_RUNNING);
  } else if (evt == ST_EVT_RESET) {
    st_error_ret = do_evt_reset_then_set_state();
  } else {
    st_error_ret = ST_ERROR_OPERATION_FAILED;
  }
  return st_error_ret;
}

static st_error_t
handler_on_state_running(st_evt evt)
{

  st_error_t st_error_ret = ST_ERROR_NONE;

  if (evt == ST_EVT_STOP) {
    do_evt_stop_then_set_state();
  } else if (evt == ST_EVT_RESET) {
    st_error_ret = do_evt_reset_then_set_state();
  } else {
    st_error_ret = ST_ERROR_OPERATION_FAILED;
  }

  return st_error_ret;
}

st_error_t
st_manager_initialize(void)
{
  st_state current_state = get_current_state();

  if (current_state != ST_STATE_IDLE) {
    if (current_state == ST_STATE_READY) {
      return ST_ERROR_STACK_ALREADY_INITIALIZED;
    } else {
      return ST_ERROR_STACK_RUNNING;
    }
  }
  return handle_request(ST_EVT_INIT);
}

st_error_t
st_manager_start(void)
{
  st_state current_state = get_current_state();

  if (current_state == ST_STATE_IDLE) {
    return ST_ERROR_STACK_NOT_INITIALIZED;
  } else if (current_state == ST_STATE_READY) {
    return handle_request(ST_EVT_START);
  }

  return ST_ERROR_STACK_RUNNING;
}

st_error_t
st_manager_stop(void)
{
  st_state current_state = get_current_state();

  if (current_state == ST_STATE_IDLE) {
    return ST_ERROR_STACK_NOT_INITIALIZED;
  } else if (current_state == ST_STATE_READY) {
    return ST_ERROR_STACK_NOT_STARTED;
  }
  return handle_request(ST_EVT_STOP);
}

st_error_t
st_manager_deinitialize(void)
{
  st_state current_state = get_current_state();

  if (current_state == ST_STATE_IDLE) {
    return ST_ERROR_STACK_NOT_INITIALIZED;
  } else if (current_state == ST_STATE_READY) {
    return handle_request(ST_EVT_DEINIT);
  }
  return ST_ERROR_STACK_RUNNING;
}

st_error_t
st_manager_reset(void)
{
  st_error_t st_error_ret = ST_ERROR_NONE;
  st_state current_state = get_current_state();

  if (current_state == ST_STATE_IDLE)
    return ST_ERROR_STACK_NOT_INITIALIZED;

  // Instead of  st_manager_evt_with_signal(ST_EVT_RESET);
  // It works directly because  pushing evt cannot work due to reboot in RTOS.
  st_process_app_sync_lock();
  handle_request(ST_EVT_RESET);
  st_process_app_sync_unlock();

  return st_error_ret;
}
#endif /* STATE_MODEL */