/****************************************************************************
 *
 * Copyright 2023 ETRI All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * Created on: July 28, 2023,
 *        Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "oc_api.h"
#include "oc_log.h"
#include "oc_bridge.h"
#include "oc_core_res.h"
#include "oc_config.h"
#include "oc_bridge.h"
#include "bridge_manager.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"

#include <dlfcn.h>
#include <unistd.h>
#include <jansson.h>


static pthread_t g_main_event_handler;
static pthread_mutex_t g_app_sync_lock;
static pthread_mutex_t g_main_cv_lock;
static pthread_cond_t g_cv;

/* OS specific definition for lock/unlock */
#define app_mutex_lock(m) pthread_mutex_lock(&m)
#define app_mutex_unlock(m) pthread_mutex_unlock(&m)

OC_ATOMIC_INT8_T g_quit = 0;

/*
 * bridge manager configuration item list
 */
#define SETTING_FILENAME "settings.json"
#define KEY_SETTING_ITEM_PLUGIN_PATH "pluginPath"
#define PLUGIN_PATH_LEN 1025
#define ECONAME_LEN 1025

/*
 * ecosystem callback function names which should be exposed by each ecosystem plugin
 */
#define CB_INIT_PLUGIN "InitPlugin"
#define CB_SHUTDOWN_PLUGIN "ShutdownPlugin"

/*
 * test codes for vod manipulation
 */
#ifdef OC_BRG_DEBUG
#define USE_VIRTUAL_DEVICE_LOOKUP 1
#define UUID_LEN 37

static bool discover_vitual_devices = true;
static bool display_ascii_ui = false;

typedef struct virtual_light_t
{
  const char device_name[32];
  const char uuid[UUID_LEN];
  const char eco_system[32];
  bool on;
  bool discovered;
  bool added_to_bridge;
} virtual_light_t;

#define VOD_COUNT 5
struct virtual_light_t virtual_lights[VOD_COUNT] = {
  { "Light-1", "1b32e152-3756-4fb6-b3f2-d8db7aafe39f", "matter", true, false,
    false },
  { "Light-2", "f959f6fd-8d08-4766-849b-74c3eec5e041", "matter", false, false,
    false },
  { "Light-3", "686ef93d-36e0-47fc-8316-fbd7045e850a", "matter", true, false,
    false },
  { "Light-4", "02feb15a-bf94-4f33-9794-adfb25c7bc60", "ble", false, false,
    false },
  { "Light-5", "e2f0109f-ef7d-496a-9676-d3d87b38e52f", "ble", true, false,
    false }
};

#define C_RESET OC_PRINTF("\x1B[0m")
#define C_YELLOW OC_PRINTF("\x1B[1;33m")

static void
print_ascii_lights_ui()
{
  OC_PRINTF("\n");

  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      if (virtual_lights[i].on) {
        C_YELLOW;
      }
      OC_PRINTF(" %s ", (virtual_lights[i].on) ? " _ " : " _ ");
      if (virtual_lights[i].on) {
        C_RESET;
      }
    } else {
      OC_PRINTF("     ");
    }
  }
  OC_PRINTF("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      if (virtual_lights[i].on) {
        C_YELLOW;
      }
      OC_PRINTF(" %s ", (virtual_lights[i].on) ? "(*)" : "(~)");
      if (virtual_lights[i].on) {
        C_RESET;
      }
    } else {
      OC_PRINTF("     ");
    }
  }
  OC_PRINTF("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      if (virtual_lights[i].on) {
        C_YELLOW;
      }
      OC_PRINTF(" %s ", (virtual_lights[i].on) ? " # " : " # ");
      if (virtual_lights[i].on) {
        C_RESET;
      }
    } else {
      OC_PRINTF("     ");
    }
  }
  OC_PRINTF("\n");
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered) {
      OC_PRINTF(" %s ", (virtual_lights[i].on) ? "ON " : "OFF");
    } else {
      OC_PRINTF(" N/A ");
    }
  }
  OC_PRINTF("\n");
}


virtual_light_t *
lookup_virtual_light(size_t device_index)
{
  oc_virtual_device_t *virtual_device_info =
      oc_bridge_get_vod_mapping_info(device_index);
  for (size_t i = 0; i < VOD_COUNT; ++i) {
    if ((strncmp(virtual_lights[i].eco_system, oc_string(virtual_device_info->econame), 32) == 0)
        && (memcmp(virtual_lights[i].uuid, virtual_device_info->v_id, virtual_device_info->v_id_size) == 0)) {
        return &virtual_lights[i];
    }
  }
  return NULL;
}

static void
get_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)user_data;
  const virtual_light_t *light = NULL;
#if USE_VIRTUAL_DEVICE_LOOKUP
  light = lookup_virtual_light(request->resource->device);
#else
  light = (virtual_light_t *)user_data;
#endif

  oc_status_t resp = OC_STATUS_OK;
  oc_rep_begin_root_object();
  if (light) {
    switch (iface_mask) {
    case OC_IF_BASELINE:
      oc_process_baseline_interface(request->resource);
      /* fall through */
    case OC_IF_A:
    case OC_IF_RW:
      oc_rep_set_boolean(root, value, light->on);
      break;
    default:
      resp = OC_STATUS_BAD_REQUEST;
      break;
    }
  } else {
    resp = OC_STATUS_BAD_REQUEST;
  }
  oc_rep_end_root_object();
  oc_send_response(request, resp);
}

static void
post_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  virtual_light_t *light = NULL;
#if USE_VIRTUAL_DEVICE_LOOKUP
  light = lookup_virtual_light(request->resource->device);
#else
  light = (virtual_light_t *)user_data;
#endif
  OC_PRINTF("POST_BinarySwitch\n");
  if (light) {
    const oc_rep_t *rep = request->request_payload;
    if (rep != NULL) {
      switch (rep->type) {
      case OC_REP_BOOL:
        oc_rep_get_bool(rep, "value", &light->on);
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        break;
      }
    }
    if (display_ascii_ui) {
      print_ascii_lights_ui();
    }
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
put_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *user_data)
{
  post_binary_switch(request, iface_mask, user_data);
}

void
register_binaryswitch_resource(const char *name, const char *uri,
                               size_t device_index, void *user_data)
{
  oc_resource_t *r = oc_new_resource(name, uri, 1, device_index);
  oc_resource_bind_resource_type(r, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(r, OC_IF_A);
  oc_resource_set_default_interface(r, OC_IF_A);
  oc_resource_set_discoverable(r, true);
  oc_resource_set_request_handler(r, OC_GET, get_binary_switch, user_data);
  oc_resource_set_request_handler(r, OC_POST, post_binary_switch, user_data);
  oc_resource_set_request_handler(r, OC_PUT, put_binary_switch, user_data);
  oc_add_resource(r);
}


void
poll_for_discovered_devices()
{
  size_t virtual_device_index;
  for (size_t i = 0; i < VOD_COUNT; i++) {
    if (virtual_lights[i].discovered && !virtual_lights[i].added_to_bridge) {
      OC_PRINTF("Adding %s to bridge\n", virtual_lights[i].device_name);
      app_mutex_lock(g_app_sync_lock);

      virtual_device_index = oc_bridge_add_virtual_device(
        (const uint8_t *)virtual_lights[i].uuid, OC_UUID_LEN,
        virtual_lights[i].eco_system, "/oic/d", "oic.d.light",
        virtual_lights[i].device_name, "ocf.2.0.0",
        "ocf.res.1.0.0, ocf.sh.1.0.0", NULL, NULL);

      if (virtual_device_index != 0) {
#if USE_VIRTUAL_DEVICE_LOOKUP
        register_binaryswitch_resource(virtual_lights[i].device_name,
                                       "/bridge/light/switch",
                                       virtual_device_index, NULL);
#else
        register_binaryswitch_resource(
          virtual_lights[i].device_name, "/bridge/light/switch",
          virtual_device_index, &virtual_lights[i]);
#endif
        // the immutable_device_identifier ("piid")
        oc_uuid_t piid;
        oc_str_to_uuid(virtual_lights[i].uuid, &piid);
        oc_set_immutable_device_identifier(virtual_device_index, &piid);
      }

      app_mutex_unlock(g_app_sync_lock);
      virtual_lights[i].added_to_bridge = true;
    }
  }
}

void
disconnect_light(unsigned int index)
{
  virtual_lights[index].discovered = false;
  virtual_lights[index].added_to_bridge = false;

  size_t device = oc_bridge_get_virtual_device_index(
    (const uint8_t *)virtual_lights[index].uuid, OC_UUID_LEN,
    virtual_lights[index].eco_system);

  if (device != 0) {
    if (oc_bridge_remove_virtual_device(device) == 0) {
      OC_PRINTF("%s removed from the bridge\n", virtual_lights[index].device_name);
    } else {
      OC_PRINTF("FAILED to remove %s from the bridge\n",
            virtual_lights[index].device_name);
    }
  } else {
    OC_PRINTF("FAILED to find virtual light to remove.");
  }
}

void
discover_light(unsigned int index)
{
  virtual_lights[index].discovered = !virtual_lights[index].discovered;
  // virtual_lights[index].discovered = true;
  // TODO4ME Move the poll code into its own thread.

  if (virtual_lights[index].discovered && discover_vitual_devices) {
    poll_for_discovered_devices();
  } else {
    if (!virtual_lights[index].discovered) {
      disconnect_light(index);
    }
  }
}

void
display_summary(void)
{
  for (size_t i = 0; i < VOD_COUNT; i++) {
    char di_str[OC_UUID_LEN] = "\0";
    if (virtual_lights[i].added_to_bridge) {
      size_t device = oc_bridge_get_virtual_device_index(
        (const uint8_t *)virtual_lights[i].uuid, OC_UUID_LEN,
        virtual_lights[i].eco_system);
      if (device != 0) {
        const oc_uuid_t *id = oc_core_get_device_id(device);
        oc_uuid_to_str(id, di_str, OC_UUID_LEN);
      } else {
        strcpy(di_str, "ERROR FETCHING");
      }
    }

    OC_PRINTF("%s:\n", virtual_lights[i].device_name);
    OC_PRINTF("\tVirtual Device ID :%s\n", virtual_lights[i].uuid);
    OC_PRINTF("\teconame: %s\n", virtual_lights[i].eco_system);
    OC_PRINTF("\tlight switch is: %s\n", (virtual_lights[i].on ? "ON" : "OFF"));
    OC_PRINTF("\tAdded to bridge: %s\n",
          (virtual_lights[i].discovered ? "discovered" : "not discovered"));
    OC_PRINTF("\tOCF Device ID: %s\n",
          (virtual_lights[i].added_to_bridge ? di_str : "N/A"));
  }
  OC_PRINTF((discover_vitual_devices) ? "ACTIVELY DISCOVERING DEVICES\n"
                                  : "NOT DISCOVERING DEVICES\n");
}

#endif /* OC_BRG_DEBUG */


static int
app_init(void)
{
  int ret = oc_init_platform("ETRI", NULL, NULL);
  ret |= oc_bridge_add_bridge_device("MatterBridge", "ocf.2.2.6",
                                     "ocf.res.1.0.0, ocf.sh.1.0.0", NULL, NULL);
  return ret;
}


static void
signal_event_handler(void)
{
  app_mutex_lock(g_main_cv_lock);
  pthread_cond_signal(&g_cv);
  app_mutex_unlock(g_main_cv_lock);
}


static void
handle_signal(int signal)
{
  (void)signal;
  OC_ATOMIC_STORE8(g_quit, 1);
  signal_event_handler();
}


static void *
main_event_handler_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event_mt;

  while (OC_ATOMIC_LOAD8(g_quit) != 1) {
    app_mutex_lock(g_app_sync_lock);
    next_event_mt = oc_main_poll_v1();
    app_mutex_unlock(g_app_sync_lock);

    app_mutex_lock(g_main_cv_lock);
    if (next_event_mt == 0) {
      pthread_cond_wait(&g_cv, &g_main_cv_lock);
    } else {
      struct timespec next_event = {1,0};
      oc_clock_time_t next_event_cv;
      if (oc_clock_monotonic_time_to_posix(next_event_mt, CLOCK_MONOTONIC,
                                            &next_event_cv)) {
        next_event = oc_clock_time_to_timespec(next_event_cv);
      }
      pthread_cond_timedwait(&g_cv, &g_main_cv_lock, &next_event);
    }
    app_mutex_unlock(g_main_cv_lock);
  }

  OC_BRG_LOG("exiting thread...");

  pthread_exit(0);
}


static bool
directoryFound(const char *path)
{
  struct stat info;
  if (stat(path, &info) != 0) {
    return false;
  }
  if (info.st_mode & S_IFDIR) {
    return true;
  }
  return false;
}


/*
 * json object for vod list
 */
json_t *g_json_vodinfo_list;


/*
 * ecosystem specific cli command set list
 */
OC_LIST(g_ecosystem_cli_commandset);
OC_MEMB(g_cli_commandset_instance_memb, ecosystem_cli_commandset_t, 1);

/*
 * bridge manager config information
 */
static json_t *g_config_root = NULL;
static json_t *g_config_plugin_path = NULL;


int
init_bridge_manager(void)
{
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_handler };

  oc_set_con_res_announced(false);
  oc_set_max_app_data_size(13312);
#ifdef OC_STORAGE
  if (!directoryFound("bridge_creds")) {
    printf("Creating bridge_creds directory for persistant storage.");
    mkdir("bridge_creds", 0755);
  }
  oc_storage_config("./bridge_creds/");
#endif /* OC_STORAGE */

  init = oc_main_init(&handler);
  OC_BRG_LOG("=> %s: result of oc_main_init(): %d", __func__, init);
  if (init < 0)
    return init;
  OC_BRG_LOG("=> %s: oc_main_init() is done", __func__);

  if (pthread_create(&g_main_event_handler, NULL, &main_event_handler_thread, NULL) != 0) {
    return -1;
  }
  OC_BRG_LOG("=> %s: pthread_create() is done", __func__);

  /* load bridge manager config file */
  g_config_root = json_load_file(SETTING_FILENAME, 0, NULL);
  if (!g_config_root) {
      OC_BRG_ERR("Error reading and parsing bridge manager config file.");
      return -1;
  }

  g_config_plugin_path = json_object_get(g_config_root, KEY_SETTING_ITEM_PLUGIN_PATH);
  if (!json_is_string(g_config_plugin_path)) {
    OC_BRG_ERR("configuration file syntax error!");
    return -1;
  }

  return 0;
}


void
shutdown_bridge_manager(void)
{
  /*
   * TODO4MEDONE <Nov 5, 2023> shutdown_bridge_manager() : add codes to unload all plugins..
   */

  /* 1. unload all loaded plugins.. */
  ecosystem_cli_commandset_t *cli_commandset;
  ecosystem_cli_commandset_t *t;
  char *econame = NULL;

  cli_commandset = (ecosystem_cli_commandset_t *)oc_list_head(g_ecosystem_cli_commandset);

  OC_BRG_LOG("shutting down all translator plugins..");
  while (cli_commandset) {
    t = cli_commandset;
    cli_commandset = cli_commandset->next;

    /* run plugin-specific shutdown runction */
    if (econame)
      free(econame);

    econame = (char *)malloc(oc_string_len(t->econame)+1);
    strcpy(econame, oc_string(t->econame));

    OC_BRG_LOG("module \"%s\" is shuttting down..", econame);

    if (t->shutdown(t) < 0) {
      OC_BRG_ERR("plugin (%s_translator_plugin) shutdown error!\n", econame);
    }
    OC_BRG_LOG("module \"%s\" shutdown..", econame);

    /* close plugin */
    dlclose(t->dl_plugin_handle);
    OC_BRG_LOG("dlclose module \"%s\"", econame);

    /* remove from ecosystem commandset list */
    oc_list_remove(g_ecosystem_cli_commandset, t);
    OC_BRG_LOG("removing module \"%s\" from list", econame);

    /* free memory */
    oc_memb_free(&g_cli_commandset_instance_memb, t);
    OC_BRG_LOG("freeing memory of module \"%s\" from list", econame);
  }

  if (econame)
    free(econame);

  /* 2. shutdown iotivity-lite */
  handle_signal(0);

  pthread_join(g_main_event_handler, NULL);
  OC_BRG_LOG("pthread_join finish!\n");

  oc_main_shutdown();

  pthread_mutex_destroy(&g_main_cv_lock);
  pthread_mutex_destroy(&g_app_sync_lock);

  /* close config json parser */
  json_decref(g_config_root);

  return;
}


/*---------------------------------------------------------------------------*/
/*
 *  APIs for CLI commands exposed by Bridge Manager
 */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/*
 *  vod command
 */
/*---------------------------------------------------------------------------*/
/*
 * find "obj_name" in "parent" object, and return "key_name" in the "obj_name"
 */
static json_t *
_get_json_item_in_object(const json_t *parent, const char *obj_name, const char *key_name)
{
  const json_t *obj;
  json_t *key;

  if (!(obj = json_object_get(parent, obj_name))) {
    OC_BRG_ERR("object \"%s\" is not found!", obj_name);
    return NULL;
  }

  if (!(key = json_object_get(obj, key_name))) {
    OC_BRG_ERR("key \"%s\" is not found!", key_name);
    return NULL;
  }

  return key;
}


static void
_free_json_obj(json_t *json_obj)
{
  if (!json_obj) {
    return;
  }

  json_t *value;
  const char *key;
  int index;

  switch (json_typeof(json_obj)) {
  case JSON_OBJECT:
    json_object_foreach(json_obj, key, value) {
      _free_json_obj(value);
    }
    json_decref(json_obj);
    break;

  case JSON_ARRAY:
    json_array_foreach(json_obj, index, value) {
      _free_json_obj(value);
    }
    json_decref(json_obj);
    break;

  default:
    /* free all other primitive types... */
    json_decref(json_obj);
    break;
  }
}


static json_t *
_create_json_obj_for_vod(oc_virtual_device_t *vod_mapping_item)
{
  oc_device_info_t *device;
  oc_endpoint_t *ep_item;
  oc_resource_t *rsc_item;
  oc_string_t ep_str;
  char di[OC_UUID_LEN];

  json_t *json_vod_item;
  json_t *json_ep_list;
  json_t *json_uri_list;

  /* find Device corresponding to the VOD mapping entry */
  if (!(device = oc_core_get_device_info(vod_mapping_item->index))) {
    OC_BRG_ERR("vod mapping entry for device (%zd) is not found!", vod_mapping_item->index);
    return NULL;
  }

  /* create new json obc for this VOD */
  if (!(json_vod_item = json_object())) {
    OC_BRG_ERR("creating json obj for new VOD failed!");
    return NULL;
  }

  /* econame */
  json_object_set_new(json_vod_item, "econame", json_string(oc_string(vod_mapping_item->econame)));

  /* di */
  oc_uuid_to_str(&device->di, di, OC_UUID_LEN);
  OC_BRG_LOG("current device index: %zd, vod_mapping_item->v_id: %s, device id: %s",
      vod_mapping_item->index, vod_mapping_item->v_id, di);
  json_object_set_new(json_vod_item, "di", json_string(di));

  /* device_name */
  json_object_set_new(json_vod_item, "device_name", json_string(oc_string(device->name)));

  /* endpoint list */
  if (!(json_ep_list = json_array())) {
    OC_BRG_ERR("creating json array obj for EP list failed!");
    _free_json_obj(json_vod_item);
    return NULL;
  }
  ep_item = oc_connectivity_get_endpoints(vod_mapping_item->index);
  while (ep_item) {
    if (oc_endpoint_to_string(ep_item, &ep_str) < 0) {
      OC_BRG_ERR("converting EP to string failed!");
      _free_json_obj(json_vod_item);
      return NULL;
    }
    OC_BRG_LOG("ep: %s", oc_string(ep_str));
    json_array_append_new(json_ep_list, json_string(oc_string(ep_str)));
    oc_free_string(&ep_str);
    ep_item = ep_item->next;
  }
  json_object_set_new(json_vod_item, "ep_list", json_ep_list);

  /* resource uri list */
  if (!(json_uri_list = json_array())) {
    OC_BRG_ERR("creating json array obj for URI list failed!");
    _free_json_obj(json_vod_item);
    return NULL;
  }
  rsc_item = oc_ri_get_app_resource_by_device(vod_mapping_item->index, true);
  while(rsc_item) {
    json_array_append_new(json_uri_list, json_string(oc_string(rsc_item->uri)));
    OC_BRG_LOG("new Resource %s was added!", oc_string(rsc_item->uri));
    rsc_item = oc_ri_get_app_resource_by_device(vod_mapping_item->index, false);
  }
  json_object_set_new(json_vod_item, "uri_list", json_uri_list);

  /* is_online */
  json_object_set_new(json_vod_item, "is_online", json_boolean(vod_mapping_item->is_vod_online));

  return json_vod_item;
}


char *
vod(char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  const json_t *json_subcmd;
  oc_virtual_device_t *vod_mapping_item;

  CLI_JSON_LOADS(parsed_command_json_str, NULL);

  json_subcmd = _get_json_item_in_object(json_root, KEY_SUBCMD, KEY_CMDSTR);

  if (!strcmp(json_string_value(json_subcmd), VALUE_SUBCMD_VOD_LIST)) {
    /*
     * vod list
     */
    /* free current vodinfo list */
    _free_json_obj(g_json_vodinfo_list);

    /* traverse vod mapping list (g_vod_mapping_list) */
    g_json_vodinfo_list = json_array();
    vod_mapping_item = oc_vod_map_get_mapping_list();
    while (vod_mapping_item) {
      if (json_array_append_new(g_json_vodinfo_list, _create_json_obj_for_vod(vod_mapping_item)) < 0) {
        OC_BRG_ERR("creation of json object for VOD (device index: %zd) is failed!", vod_mapping_item->index);
        CLI_JSON_CLOSE();
        return NULL;
      }
      vod_mapping_item = vod_mapping_item->next;
    }
    return json_dumps(g_json_vodinfo_list, JSON_INDENT(2));
  } else if (!strcmp(json_string_value(json_subcmd), VALUE_SUBCMD_VOD_ADD)) {
    /*
     * vod add
     */
    oc_uuid_t uuid;
    size_t device_index;
    const json_t *json_econame_list;
    size_t econame_list_size;

    /*
     * json_root["subcmd"]["value"] : device ids of VOD to be added
     */
    json_econame_list = _get_json_item_in_object(json_root, KEY_SUBCMD, KEY_VALUE);
    econame_list_size = json_array_size(json_econame_list);

    for (int i=0; i<econame_list_size; i++) {
      OC_BRG_LOG("Devide ID of VOD to be online: %s", json_string_value(json_array_get(json_econame_list, i)));

      oc_str_to_uuid(json_string_value(json_array_get(json_econame_list, i)), &uuid);
      if (oc_core_get_device_index(uuid, &device_index) < 0) {
        OC_BRG_ERR("There is no Device whose device ID is %s!", json_string_value(json_array_get(json_econame_list, i)));
        continue;
      }

      if (oc_bridge_add_vod(device_index) < 0) {
        OC_BRG_ERR("Making VOD (Device ID: %s) online failed!", json_string_value(json_array_get(json_econame_list, i)));
        continue;
      }
    }
  } else if (!strcmp(json_string_value(json_subcmd), VALUE_SUBCMD_VOD_DELETE)) {
    /*
     * vod delete
     */
    oc_uuid_t uuid;
    size_t device_index;
    const json_t *json_econame_list;
    size_t econame_list_size;

    /*
     * json_root["subcmd"]["value"] : device ids of VOD to be removed
     */
    json_econame_list = _get_json_item_in_object(json_root, KEY_SUBCMD, KEY_VALUE);
    econame_list_size = json_array_size(json_econame_list);

    for (int i=0; i<econame_list_size; i++) {
      OC_BRG_LOG("Devide ID of VOD to be offline: %s", json_string_value(json_array_get(json_econame_list, i)));

      oc_str_to_uuid(json_string_value(json_array_get(json_econame_list, i)), &uuid);
      if (oc_core_get_device_index(uuid, &device_index) < 0) {
        OC_BRG_ERR("There is no Device whose device ID is %s!", json_string_value(json_array_get(json_econame_list, i)));
        continue;
      }

      if (oc_bridge_remove_virtual_device(device_index) < 0) {
        OC_BRG_ERR("Removing VOD (Device ID: %s) failed!", json_string_value(json_array_get(json_econame_list, i)));
        continue;
      }
    }
  }

  CLI_JSON_CLOSE();

  return NULL;
}


/*
 * @brief check if this module has already been loaded or not
 *
 * @param module_name Name of plugin to be searched
 * @return NULL: if this module has not been loaded
 *         not NULL: this module has been loaded (return value is pointer to existing commandset)
 */
static ecosystem_cli_commandset_t *
_is_module_loaded(const char *module_name)
{
  ecosystem_cli_commandset_t *cli_commandset;

  cli_commandset = (ecosystem_cli_commandset_t *)oc_list_head(g_ecosystem_cli_commandset);
  while (cli_commandset) {
    if (!strcmp(oc_string(cli_commandset->econame), module_name)) {
      return cli_commandset;
    }

    cli_commandset = cli_commandset->next;
  }
  return NULL;
}




/*---------------------------------------------------------------------------*/
/*
 *  module command
 */
/*---------------------------------------------------------------------------*/
/*
 * list current available module
 */
static void
_module_list()
{
  ecosystem_cli_commandset_t *cli_commandset;

  cli_commandset = (ecosystem_cli_commandset_t *)oc_list_head(g_ecosystem_cli_commandset);
  while (cli_commandset) {
    OC_PRINTF("%s ", oc_string(cli_commandset->econame));
    cli_commandset = cli_commandset->next;
  }
  OC_PRINTF("\n");
}


/*
 * @brief load ecosystem plugin module
 *
 * @param json_root Deserialized json object including command info typed by a user
 * @return 0: success, <0:failure
 */
static int
_module_load(const json_t *json_root)
{
  int result = -1;
  ecosystem_cli_commandset_t *cli_commandset;
  const json_t *json_module_list;
  size_t module_list_size;
  char plugin_path[PLUGIN_PATH_LEN];

  json_module_list = _get_json_item_in_object(json_root, KEY_SUBCMD, KEY_VALUE);
  module_list_size = json_array_size(json_module_list);

  int path_len;
  for (int i=0; i<module_list_size; i++) {
    /* skip if there is any alread loaded module with same econame */
    if (_is_module_loaded(json_string_value(json_array_get(json_module_list, i)))) {
      OC_BRG_LOG("module \"%s\" is already loaded!", json_string_value(json_array_get(json_module_list, i)));
      continue;
    }

    /* 1. create new commandset for ecosystem module */
    cli_commandset = (ecosystem_cli_commandset_t *)oc_memb_alloc(&g_cli_commandset_instance_memb);
    OC_LIST_STRUCT_INIT(cli_commandset, eco_commands);

    /* 2. load ecosystem translation module */
    path_len = snprintf(plugin_path, PLUGIN_PATH_LEN, "%s/%s/%s_translator_plugin.so",
        json_string_value(g_config_plugin_path),
        /* TODO4ME <Jan 2, 2024> _module_load(): replace "out" with json_string_value(json_array_get(json_module_list, i)), */
        json_string_value(json_array_get(json_module_list, i)),
        json_string_value(json_array_get(json_module_list, i)));

    if (path_len > PLUGIN_PATH_LEN) {
      OC_BRG_ERR("path of plugin is truncated (\"%s\"), because its length exceeded buf size of path string (%d) !", plugin_path, PLUGIN_PATH_LEN);
      return result;
    }

    cli_commandset->dl_plugin_handle = dlopen(plugin_path, RTLD_NOW);
    if (!cli_commandset->dl_plugin_handle) {
      OC_BRG_ERR("plugin (%s_translator_plugin) loading error! (%s)\n", json_string_value(json_array_get(json_module_list, i)), dlerror());
      oc_memb_free(&g_cli_commandset_instance_memb, cli_commandset);
      return result;
    }

    /* set init/shutdown callback of plugin */
    cli_commandset->init = (cb_init_plugin_t)dlsym(cli_commandset->dl_plugin_handle, CB_INIT_PLUGIN);
    cli_commandset->shutdown = (cb_shutdown_plugin_t)dlsym(cli_commandset->dl_plugin_handle, CB_SHUTDOWN_PLUGIN);
    if (!cli_commandset->init || !cli_commandset->shutdown) {
      OC_BRG_ERR("plugin (%s_translator_plugin) loading error! (%s)\n", json_string_value(json_array_get(json_module_list, i)), dlerror());
      dlclose(cli_commandset->dl_plugin_handle);
      oc_memb_free(&g_cli_commandset_instance_memb, cli_commandset);
      return result;
    }

    /* 3. init plugin */
    if (cli_commandset->init(cli_commandset) < 0) {
      OC_BRG_ERR("plugin (%s_translator_plugin) initialization error!\n", json_string_value(json_array_get(json_module_list, i)));
      if (dlclose(cli_commandset->dl_plugin_handle)) {
        OC_BRG_ERR("plugin (%s_translator_plugin) closing error!", json_string_value(json_array_get(json_module_list, i)));
      }
      oc_memb_free(&g_cli_commandset_instance_memb, cli_commandset);
      return result;
    }

    /* 4. add new ecosystem-specific commandset to list */
    oc_list_add(g_ecosystem_cli_commandset, cli_commandset);

    OC_BRG_LOG("plugin module \"%s\" is loaded successfully!", json_string_value(json_array_get(json_module_list, i)));
  }

  result = 0;
  return result;
}


/*
 * @brief unload ecosystem plugin module
 *
 * @param json_root Deserialized json object including command info typed by a user
 */
static void
_module_unload(const json_t *json_root)
{
  ecosystem_cli_commandset_t *cli_commandset;
  const json_t *json_module_list;
  size_t module_list_size;

  json_module_list = _get_json_item_in_object(json_root, KEY_SUBCMD, KEY_VALUE);
  module_list_size = json_array_size(json_module_list);

  for (int i=0; i<module_list_size; i++) {
    if ((cli_commandset = _is_module_loaded(json_string_value(json_array_get(json_module_list, i))))) {
      /* run plugin-specific shutdown runction */
      if (cli_commandset->shutdown(cli_commandset) < 0) {
        OC_BRG_ERR("plugin (%s_translator_plugin) shutdown error!\n", json_string_value(json_array_get(json_module_list, i)));
      } else {
        OC_BRG_LOG("module %s shutdown", json_string_value(json_array_get(json_module_list, i)));
      }

      /* close plugin */
      if (dlclose(cli_commandset->dl_plugin_handle)) {
        OC_BRG_ERR("plugin (%s_translator_plugin) closing error!", json_string_value(json_array_get(json_module_list, i)));
      } else {
        OC_BRG_LOG("module %s is closed", json_string_value(json_array_get(json_module_list, i)));
      }

      /* remove from ecosystem commandset list */
      oc_list_remove(g_ecosystem_cli_commandset, cli_commandset);

      /* free memory */
      oc_memb_free(&g_cli_commandset_instance_memb, cli_commandset);
    }
  }
}


int
module(char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  int result = -1;
  const json_t *json_subcmd;

  CLI_JSON_LOADS(parsed_command_json_str, -1);

  json_subcmd = _get_json_item_in_object(json_root, KEY_SUBCMD, KEY_CMDSTR);

  if (!strcmp(json_string_value(json_subcmd), VALUE_SUBCMD_MODULE_LIST)) {
    /*
     * module list ...
     */
    _module_list();
  } else if (!strcmp(json_string_value(json_subcmd), VALUE_SUBCMD_MODULE_LOAD)) {
    /*
     * module load ...
     */
    if (_module_load(json_root) < 0)
      goto out;
  } else if (!strcmp(json_string_value(json_subcmd), VALUE_SUBCMD_MODULE_UNLOAD)) {
    /*
     * module unload...
     */
    _module_unload(json_root);
  }

  result = 0;

out:
  CLI_JSON_CLOSE();
  return result;
}


/*---------------------------------------------------------------------------*/
/*
 *  cd command
 */
/*---------------------------------------------------------------------------*/
int
cd(char *module_name)
{
  char json_str[1024];
  snprintf(json_str,
      sizeof(json_str),
      "{\"cmd\": {\"cmd_str\": \"module\", \"value\": null}, \"subcmd\": {\"cmd_str\": \"load\", \"value\": [\"%s\"]}, \"options\": []}",
      module_name);

  /* check if this module is already loaded
   * if not, try to load module */
  if (!_is_module_loaded(module_name)) {
    if (module(json_str) < 0) {
      OC_BRG_ERR("module \"%s\" loading failed!\n", module_name);
      return -1;
    } else {
      OC_PRINTF("module \"%s\" is loaded successfully\n", module_name);
    }
  } else {
    OC_BRG_LOG("module \"%s\" is already loaded!", module_name);
  }

  return 0;
}


/*---------------------------------------------------------------------------*/
/*
 *  retrieve command
 */
/*---------------------------------------------------------------------------*/
int
retrieve(char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  int result = -1;
  const char *econame;
  const ecosystem_cli_commandset_t *cli_commandset;

  CLI_JSON_LOADS(parsed_command_json_str, -1);

  /* 0. decide which ecosystem this command belongs to */
  econame = CLI_JSON_STRING_VALUE(json_root, KEY_ECONAME);

  if (!(cli_commandset = _is_module_loaded(econame))) {
    OC_BRG_ERR("module \"%s\" is not loaded!", econame);
    goto out;
  }
  OC_BRG_LOG("loaded module \"%s\" is found!", econame);

  if (cli_commandset->retrieve(parsed_command_json_str) < 0) {
    OC_BRG_ERR("Running %s::retrieve failed!", econame);
    goto out;
  }

  result = 0;

out:
  CLI_JSON_CLOSE();
  return result;
}


/*---------------------------------------------------------------------------*/
/*
 *  update command
 */
/*---------------------------------------------------------------------------*/
int
update(char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  int result = -1;
  const char *econame;
  const ecosystem_cli_commandset_t *cli_commandset;

  CLI_JSON_LOADS(parsed_command_json_str, -1);

  /* 0. decide which ecosystem this command belongs to */
  econame = CLI_JSON_STRING_VALUE(json_root, KEY_ECONAME);

  if (!(cli_commandset = _is_module_loaded(econame))) {
    OC_BRG_ERR("module \"%s\" is not loaded!", econame);
    goto out;
  }
  OC_BRG_LOG("loaded module \"%s\" is found!", econame);

  if (cli_commandset->update(parsed_command_json_str) < 0) {
    OC_BRG_ERR("Running %s::retrieve failed!", econame);
    goto out;
  }

  result = 0;

out:
  CLI_JSON_CLOSE();
  return result;
}


/*---------------------------------------------------------------------------*/
/*
 *  ecosystem-specific command
 */
/*---------------------------------------------------------------------------*/

/*
 * @brief Find ecosystem-specific command info corresponding to "cmd_str"
 *
 * @param cli_commandset Ecosystem-specific command set
 * @param cmd_str Ecosystem-specific command string
 * @return NULL: failure, not NULL: found command (cli_command_t)
 */
static cli_command_t *
_get_ecosystem_command(const ecosystem_cli_commandset_t *cli_commandset, const char *cmd_str)
{
  cli_command_t *cli_command;

  cli_command = (cli_command_t *)oc_list_head(cli_commandset->eco_commands);

  while (cli_command) {
    if (!strcmp(oc_string(cli_command->cmd_str), cmd_str)) {
      return cli_command;
    }
    cli_command = cli_command->next;
  }

  return NULL;
}


int run_ecosystem_command(char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  int result = -1;
  const char *econame;
  const char *cmd_str;
  const ecosystem_cli_commandset_t *cli_commandset;
  const cli_command_t *cli_command;

  CLI_JSON_LOADS(parsed_command_json_str, -1);

  /* 0. decide which ecosystem this command belongs to */
  econame = CLI_JSON_STRING_VALUE(json_root, KEY_ECONAME);

  if (!(cli_commandset = _is_module_loaded(econame))) {
    OC_BRG_ERR("module \"%s\" is not loaded!", econame);
    goto out;
  }
  OC_BRG_LOG("loaded module \"%s\" is found!", econame);

  /* 2. get cli_command */
  cmd_str = json_string_value(_get_json_item_in_object(json_root, KEY_CMD, KEY_CMDSTR));
  if (!(cli_command = _get_ecosystem_command(cli_commandset, cmd_str))) {
    OC_BRG_ERR("module \"%s\" does not support \"%s\" command!", econame, cmd_str);
    goto out;
  }
  OC_BRG_LOG("module \"%s\" supports \"%s\" command", econame, cmd_str);

  /* 3. run command */
  if (cli_command->func(parsed_command_json_str) < 0) {
    OC_BRG_ERR("Running %s::%s failed!", econame, cmd_str);
    goto out;
  }

  result = 0;

out:
  CLI_JSON_CLOSE();

  return result;
}


/*
 * for testting purpose
 */
#ifdef OC_BRG_DEBUG
void add_vods_test()
{
  discover_light(0u);
  discover_light(1u);
  discover_light(2u);
  discover_light(3u);
  display_summary();
}
#endif
