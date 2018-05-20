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

#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "security/oc_pstat.h"
#include "st_cloud_access.h"
#include "st_easy_setup.h"
#include "st_port.h"
#include "st_store.h"

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

static const char *switch_rsc_uri = "/capability/switch/main/0";
static const char *switch_rsc_rt = "x.com.st.powerswitch";
static const char *switchlevel_rsc_uri = "/capability/switchLevel/main/0";
static const char *switchlevel_rsc_rt = "oic.r.light.dimming";
static const char *color_temp_rsc_uri = "/capability/colorTemperature/main/0";
static const char *color_temp_rsc_rt = "x.com.st.color.temperature";
static const char *resource_name = "Samsung's Light";

static const char *device_rt = "oic.d.light";
static const char *device_name = "Samsung";

static const char *manufacturer = "xxxx";

static bool discoverable = true;
static bool observable = true;

st_mutex_t mutex = NULL;
st_cond_t cv = NULL;
struct timespec ts;

st_mutex_t app_mutex = NULL;
oc_resource_t *switch_resource;
oc_link_t *publish_res;

int quit = 0;

static char power[10] = "on";
static int dimmingSetting = 50;

static int ct = 50;
static int range[2] = { 0, 100 };
oc_string_t name;

oc_define_interrupt_handler(observe)
{
  oc_notify_observers(switch_resource);
}

static void
init_platform_cb(CborEncoder *object, void *data)
{
  (void)data;
  oc_set_custom_platform_property(*object, mnmo, "5021");
  oc_set_custom_platform_property(*object, mnpv, "1.0");
  oc_set_custom_platform_property(*object, mnos, "1.0");
  oc_set_custom_platform_property(*object, mnhw, "1.0");
  oc_set_custom_platform_property(*object, mnfv, "1.0");
  oc_set_custom_platform_property(*object, vid, "IoT2020");
}

static int
app_init(void)
{
  oc_activate_interrupt_handler(observe);
  int ret = oc_init_platform(manufacturer, init_platform_cb, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  oc_new_string(&name, resource_name, strlen(resource_name));
  return ret;
}

static void
switch_construct(oc_request_t *request, oc_interface_mask_t interface)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_text_string(root, power, power);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

static void
switch_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                   void *user_data)
{
  (void)user_data;

  st_print_log("switch_get_handler:\n");
  switch_construct(request, interface);
  oc_send_response(request, OC_STATUS_OK);
}

static void
switch_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                    void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("switch_post_handler:\n");
  st_print_log("  Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    st_print_log("  %s :", oc_string(rep->name));

    switch (rep->type) {
    case OC_REP_STRING:
      if (strcmp(oc_string(rep->name), "power") == 0) {
        strcpy(power, oc_string(rep->value.string));
        st_print_log(" %s\n", power);
      }
      break;
    default:
      st_print_log(" NULL\n");
      break;
    }
    rep = rep->next;
  }
  switch_construct(request, interface);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
switchlevel_construct(oc_request_t *request, oc_interface_mask_t interface)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_int(root, dimmingSetting, dimmingSetting);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

static void
switchlevel_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)user_data;

  st_print_log("switchlevel_get_handler:\n");
  switchlevel_construct(request, interface);
  oc_send_response(request, OC_STATUS_OK);
}

static void
switchlevel_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                         void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("switchlevel_post_handler:\n");
  st_print_log("  Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    st_print_log("  %s :", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      if (strcmp(oc_string(rep->name), "dimmingSetting") == 0) {
        dimmingSetting = rep->value.integer;
        st_print_log(" %d\n", dimmingSetting);
      }
      break;
    default:
      st_print_log(" NULL\n");
      break;
    }
    rep = rep->next;
  }
  switchlevel_construct(request, interface);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
color_temp_construct(oc_request_t *request, oc_interface_mask_t interface)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_int(root, ct, ct);
    oc_rep_set_int_array(root, range, range, 2);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

static void
color_temp_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                       void *user_data)
{
  (void)user_data;

  st_print_log("color_temp_get_handler:\n");
  color_temp_construct(request, interface);
  oc_send_response(request, OC_STATUS_OK);
}

static void
color_temp_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("color_temp_post_handler:\n");
  st_print_log("  Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    st_print_log("  %s :", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      if (strcmp(oc_string(rep->name), "ct") == 0) {
        ct = rep->value.integer;
        st_print_log(" %d\n", ct);
      }
      break;
    default:
      st_print_log(" NULL\n");
      break;
    }
    rep = rep->next;
  }
  color_temp_construct(request, interface);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
register_resources(void)
{
  switch_resource = oc_new_resource(NULL, switch_rsc_uri, 1, 0);
  oc_resource_bind_resource_type(switch_resource, switch_rsc_rt);
  oc_resource_bind_resource_interface(switch_resource, OC_IF_A);
  oc_resource_set_default_interface(switch_resource, OC_IF_BASELINE);
  oc_resource_set_discoverable(switch_resource, discoverable);
  oc_resource_set_observable(switch_resource, observable);
  oc_resource_set_request_handler(switch_resource, OC_GET, switch_get_handler,
                                  NULL);
  oc_resource_set_request_handler(switch_resource, OC_POST, switch_post_handler,
                                  NULL);
  oc_add_resource(switch_resource);

  oc_resource_t *level = oc_new_resource(NULL, switchlevel_rsc_uri, 1, 0);
  oc_resource_bind_resource_type(level, switchlevel_rsc_rt);
  oc_resource_bind_resource_interface(level, OC_IF_A);
  oc_resource_set_discoverable(level, discoverable);
  oc_resource_set_observable(level, observable);
  oc_resource_set_request_handler(level, OC_GET, switchlevel_get_handler, NULL);
  oc_resource_set_request_handler(level, OC_POST, switchlevel_post_handler,
                                  NULL);
  oc_add_resource(level);

  oc_resource_t *temperature = oc_new_resource(NULL, color_temp_rsc_uri, 1, 0);
  oc_resource_bind_resource_type(temperature, color_temp_rsc_rt);
  oc_resource_bind_resource_interface(temperature, OC_IF_A);
  oc_resource_bind_resource_interface(temperature, OC_IF_S);
  oc_resource_set_default_interface(temperature, OC_IF_BASELINE);
  oc_resource_set_discoverable(temperature, discoverable);
  oc_resource_set_observable(temperature, observable);
  oc_resource_set_request_handler(temperature, OC_GET, color_temp_get_handler,
                                  NULL);
  oc_resource_set_request_handler(temperature, OC_POST, color_temp_post_handler,
                                  NULL);
  oc_add_resource(temperature);

  publish_res = oc_new_link(switch_resource);
  oc_link_t *publish_res1 = oc_new_link(level);
  oc_link_t *publish_res2 = oc_new_link(temperature);
  oc_list_add((oc_list_t)publish_res, publish_res1);
  oc_list_add((oc_list_t)publish_res, publish_res2);

  register_sc_provisioning_info_resource();
}

static void
signal_event_loop(void)
{
  st_mutex_lock(mutex);
  st_cond_signal(cv);
  st_mutex_unlock(mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event;

  while (quit != 1) {
    st_mutex_lock(app_mutex);
    next_event = oc_main_poll();
    st_mutex_unlock(app_mutex);
    st_mutex_lock(mutex);
    if (next_event == 0) {
      st_cond_wait(cv, mutex);
    } else {
      st_cond_timedwait(cv, mutex, next_event);
    }
    st_mutex_unlock(mutex);
  }

  st_thread_exit(NULL);
  return NULL;
}

void
print_menu(void)
{
  st_mutex_lock(app_mutex);
  st_print_log("=====================================\n");
  st_print_log("1. Reset device\n");
  st_print_log("0. Quit\n");
  st_print_log("=====================================\n");
  st_mutex_unlock(app_mutex);
}

static bool is_easy_setup_success = false;
void
easy_setup_handler(st_easy_setup_status_t status)
{
  if (status == EASY_SETUP_FINISH) {
    is_easy_setup_success = true;
  } else if (status == EASY_SETUP_RESET) {
    // TODO
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
    oc_uuid_to_str(oc_core_get_device_id(switch_resource->device), uuid,
                   MAX_UUID_LENGTH);
    oc_new_string(&g_prov_resource.targets[i].targetDi, uuid, strlen(uuid));
    oc_new_string(&g_prov_resource.targets[i].targetRt, device_rt,
                  strlen(device_rt));
    g_prov_resource.targets[i].published = false;
  }
  g_prov_resource.targets_size = target_size;
  g_prov_resource.owned = false;
  oc_uuid_to_str(oc_core_get_device_id(switch_resource->device), uuid,
                 MAX_UUID_LENGTH);
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
  set_sc_prov_info();
}

static void
st_vendor_props_shutdown(void)
{
  unset_sc_prov_info();
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
    st_mutex_lock(app_mutex);
    if (get_easy_setup_status() == EASY_SETUP_FINISH) {
      st_mutex_unlock(app_mutex);
      break;
    }
    st_mutex_unlock(app_mutex);
    st_sleep(1);
    st_print_log(".");
    fflush(stdout);
  }
  st_print_log("\n");

  if (is_easy_setup_success) {
    st_print_log("easy setup is successfully finished!\n");
  } else {
    return false;
  }

  st_store_t *cloud_info = get_cloud_informations();
  if (!cloud_info) {
    st_print_log("could not get cloud informations.\n");
    return false;
  }

  while (st_cloud_access_check_connection(
           oc_string(cloud_info->cloudinfo.ci_server)) != 0 &&
         quit != 1) {
    st_print_log("AP is not connected.\n");
    st_sleep(3);
  }

  // cloud access
  if (st_cloud_access_start(cloud_info, publish_res, switch_resource->device,
                            cloud_access_handler) != 0) {
    st_print_log("Failed to access cloud!\n");
    return false;
  }

  st_print_log("cloud access started.\n");
  while (!is_cloud_access_success && quit != 1) {
    st_mutex_lock(app_mutex);
    if (get_cloud_access_status(switch_resource->device) ==
        CLOUD_ACCESS_FINISH) {
      st_mutex_unlock(app_mutex);
      break;
    }
    st_mutex_unlock(app_mutex);
    st_sleep(1);
    st_print_log(".");
    fflush(stdout);
  }
  st_print_log("\n");

  if (is_cloud_access_success) {
    st_print_log("cloud access successfully finished!\n");
  } else {
    return false;
  }

  return true;
}

static void
st_main_reset(void)
{
#ifdef OC_SECURITY
  oc_sec_reset();
#endif /* OC_SECURITY */

  st_easy_setup_reset();
  is_easy_setup_success = false;

  st_cloud_access_stop(switch_resource->device);
  is_cloud_access_success = false;
}

int
main(void)
{
  int init = 0;
  int device_num = 0;
  int i = 0;
  st_set_sigint_handler(handle_signal);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

#ifdef OC_SECURITY
  oc_storage_config("./st_things_creds");
#endif /* OC_SECURITY */

  mutex = st_mutex_init();
  if (!mutex) {
    st_print_log("st_mutex_init failed!\n");
    return -1;
  }

  app_mutex = st_mutex_init();
  if (!app_mutex) {
    st_print_log("st_mutex_init failed!\n");
    st_mutex_destroy(mutex);
    return -1;
  }

  cv = st_cond_init();
  if (!cv) {
    st_print_log("st_cond_init failed!\n");
    st_mutex_destroy(mutex);
    st_mutex_destroy(app_mutex);
    return -1;
  }

  oc_set_max_app_data_size(3072);

  while (quit != 1) {
    if (st_load() < 0) {
      st_print_log("[ST_App] Could not load store informations.\n");
      return -1;
    }

    if (st_is_easy_setup_finish() != 0) {
      st_print_log("[St_App] Soft AP turn on.\n");
      st_easy_setup_turn_on_soft_AP();
    }

    init = oc_main_init(&handler);
    if (init < 0) {
      st_print_log("oc_main_init failed!(%d)\n", init);
      goto exit;
    }

    char uuid[MAX_UUID_LENGTH] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(0), uuid, MAX_UUID_LENGTH);
    st_print_log("uuid : %s\n", uuid);

    st_vendor_props_initialize();

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

    st_thread_t thread = st_thread_create(process_func, NULL);
    if (!thread) {
      st_print_log("Failed to create main thread\n");
      init = -1;
      goto exit;
    }

    if (!st_main_initialize()) {
      st_print_log("Failed to start easy setup & cloud access!\n");
      init = -1;
      goto exit;
    }

    char key[10];
    while (quit != 1) {
      print_menu();
      fflush(stdin);
      if (!scanf("%s", &key)) {
        st_print_log("scanf failed!!!!\n");
        quit = 1;
        handle_signal(0);
        break;
      }

      if (!is_easy_setup_success || !is_cloud_access_success) {
        st_print_log("Not initialized\n");
        continue;
      }

      st_mutex_lock(app_mutex);
      switch (key[0]) {
      case '1':
        st_main_reset();
        st_mutex_unlock(app_mutex);
        goto reset;
      case '0':
        quit = 1;
        handle_signal(0);
        break;
      default:
        st_print_log("unsupported command.\n");
        break;
      }
      st_mutex_unlock(app_mutex);
    }
  reset:
    st_print_log("reset finished\n");

    st_thread_destroy(thread);
    thread = NULL;
    st_print_log("st_thread_destroy finish!\n");
  }

exit:

  device_num = oc_core_get_num_devices();
  for (i = 0; i < device_num; i++) {
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(i);
    oc_free_server_endpoints(ep);
  }

  oc_link_t *next;
  while (publish_res) {
    next = oc_list_item_next(publish_res);
    oc_delete_link(publish_res);
    publish_res = next;
  }
  st_easy_setup_stop();
  st_print_log("easy setup stop done\n");

  st_cloud_access_stop(switch_resource->device);
  st_print_log("cloud access stop done\n");

  oc_free_string(&name);
  st_vendor_props_shutdown();
  oc_main_shutdown();

  st_cond_destroy(cv);
  st_mutex_destroy(app_mutex);
  st_mutex_destroy(mutex);
  return 0;
}
