/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "oc_bridge.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_core_res_internal.h"
#include "oc_vod_map.h"
#include "port/oc_log.h"
#include "port/oc_assert.h"

#ifdef OC_SECURITY
#include "security/oc_store.h"
#endif // OC_SECURITY

/*
 * internal struct that holds the values that build the oic.r.vodlist
 * properties.
 */
typedef struct oc_vods_t
{
  struct oc_vods_t *next;
  oc_string_t name;
  oc_uuid_t di;
  oc_string_t econame;
} oc_vods_t;

OC_LIST(oc_vods_list_t);
static oc_resource_t *bridge_res;

#define OC_PRINT_VODSLIST                                                      \
  OC_DBG("\"vods\": [");                                                       \
  oc_vods_t *print_vod_item = (oc_vods_t *)oc_list_head(oc_vods_list_t);       \
  while (print_vod_item) {                                                     \
    OC_DBG("  {");                                                             \
    OC_DBG("    \"n\": \"%s\"", oc_string(print_vod_item->name));              \
    char di_uuid[OC_UUID_LEN];                                                 \
    oc_uuid_to_str(&print_vod_item->di, di_uuid, OC_UUID_LEN);                 \
    OC_DBG("    \"di\": \"%s\"", di_uuid);                                     \
    OC_DBG("    \"econame\": \"%s\"", oc_string(print_vod_item->econame));     \
    if (print_vod_item->next) {                                                \
      OC_DBG("  },");                                                          \
    } else {                                                                   \
      OC_DBG("  }");                                                           \
    }                                                                          \
    print_vod_item = print_vod_item->next;                                     \
  }

static bool
oc_bridge_is_virtual_device(size_t device_index)
{
  oc_resource_t *r = oc_core_get_resource_by_index(OCF_D, device_index);
  for (size_t i = 0; i < oc_string_array_get_allocated_size(r->types); ++i) {
    if (strncmp(oc_string_array_get_item(r->types, i), "oic.d.virtual", 14) ==
        0) {
      return true;
    }
  }
  return false;
}

void
add_virtual_device_to_vods_list(const char *name, const oc_uuid_t *di,
                                const char *econame)
{
  oc_vods_t *vod = (oc_vods_t *)malloc(sizeof(oc_vods_t));
  oc_new_string(&vod->name, name, strlen(name));
  oc_uuid_copy(&vod->di, di);
  oc_new_string(&vod->econame, econame, strlen(econame));
  oc_list_add(oc_vods_list_t, vod);
  OC_DBG("oc_bridge: adding %s [%s] from oic.r.vodslist", name, econame);
  OC_PRINT_VODSLIST;
}

void
remove_virtual_device_from_vods_list(const oc_uuid_t *di)
{
  oc_vods_t *vod_item = (oc_vods_t *)oc_list_head(oc_vods_list_t);
  while (vod_item) {
    if (memcmp(&vod_item->di, di, 16) == 0) {
      oc_list_remove(oc_vods_list_t, vod_item);
      OC_DBG("oc_bridge: removing %s [%s] from oic.r.vodslist",
             oc_string(vod_item->name), oc_string(vod_item->econame));
      oc_free_string(&vod_item->name);
      oc_free_string(&vod_item->econame);
      free(vod_item);
      break;
    }
    vod_item = vod_item->next;
  }
  OC_PRINT_VODSLIST;
}

static void
get_bridge(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  (void)user_data;
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_R:
    oc_rep_set_array(root, vods);
    char di_str[OC_UUID_LEN];
    oc_vods_t *vod_item = (oc_vods_t *)oc_list_head(oc_vods_list_t);
    while (vod_item) {
      oc_rep_object_array_begin_item(vods);
      oc_rep_set_text_string(vods, n, oc_string(vod_item->name));
      oc_uuid_to_str(&vod_item->di, di_str, OC_UUID_LEN);
      oc_rep_set_text_string(vods, di, di_str);
      oc_rep_set_text_string(vods, econame, oc_string(vod_item->econame));
      oc_rep_object_array_end_item(vods);
      vod_item = vod_item->next;
    }
    oc_rep_close_array(root, vods);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

#ifdef OC_SECURITY
/*
 * For bridging the doxm_owned_changed callback is responsible for two tasks:
 * 1. Making sure unowned VODs connect or disconnect from the network based
 *    on the doxm status of the bridge device
 * 2. Updating the oic.r.vodslist when ownership status of the virtual devices
 *    is change
 */
void
doxm_owned_changed(const oc_uuid_t *device_uuid, size_t device_index,
                   bool owned, void *user_data)
{
  (void)user_data;
  /* Bridge Device */
  if (bridge_res->device == device_index) {
    if (owned) {
      /*
       *walk all devices
       * if device is unowned and a virtual device then call connection_init
       * assumption all virtual devices have a higher device index than bridge
       */
      for (size_t device = device_index + 1; device < oc_core_get_num_devices();
           ++device) {
        if (oc_uuid_is_nil(&oc_core_get_device_info(device)->di)) {
          continue;
        }
        if (!oc_is_owned_device(device)) {
          if (oc_bridge_is_virtual_device(device)) {
            if (oc_connectivity_init(device) < 0) {
              oc_abort("error initializing connectivity for device");
            }
            OC_DBG("oc_bridge: init connectivity for virtual device %zd",
                   device);
          }
        }
      }
    }
    /* Bridge device is unowned */
    else {
      /*
       * Reset all virtual device information.
       * walk all devices
       * if device is a virtual device call reset and connection_shutdown
       * reset the vod_map
       * assumption all virtual devices have a higher device index than bridge
       */
      for (size_t device = device_index + 1; device < oc_core_get_num_devices();
           ++device) {
        if (oc_bridge_is_virtual_device(device)) {
          oc_reset_device(device);
          oc_connectivity_shutdown(device);
        }
      }
      /* TODO: add way to remove virtual device before reseting the vod_map */
      /*
      oc_vod_map_reset();
      OC_DBG("oc_bridge: bridge reset, reseting all connected virtual devices");
      */
    }
  }
  /* Device other than Bridge Device */
  else {
    if (owned) {
      if (oc_bridge_is_virtual_device(device_index)) {
        oc_device_info_t *device_info = oc_core_get_device_info(device_index);
        oc_string_t econame;
        oc_vod_map_get_econame(&econame, device_index);
        add_virtual_device_to_vods_list(oc_string(device_info->name),
                                        device_uuid, oc_string(econame));
        OC_DBG("oc_bridge: adding %s [%s] to oic.r.vodslist",
               oc_string(device_info->name), oc_string(econame));
      }
    } else {
      /*
       * attempt to remove the unowned device from the vods_list if the uuid
       * does not exist the on the vods list nothing will happen.
       */
      remove_virtual_device_from_vods_list(device_uuid);
    }
    /* notify any observers that the vodslist has been updated */
    if (oc_is_owned_device(bridge_res->device)) {
      oc_notify_observers(bridge_res);
    }
  }
}
#endif // OC_SECURITY

int
oc_bridge_add_bridge_device(const char *name, const char *spec_version,
                            const char *data_model_version,
                            oc_add_device_cb_t add_device_cb, void *data)
{
  int ret_value = oc_add_device("/oic/d", "oic.d.bridge", name, spec_version,
                                data_model_version, add_device_cb, data);
  if (ret_value != 0) {
    return ret_value;
  }

  size_t bridge_device_index = oc_core_get_num_devices() - 1;

  bridge_res = oc_new_resource(name, "/bridge/vodlist", 1, bridge_device_index);
  oc_resource_bind_resource_type(bridge_res, "oic.r.vodlist");
  oc_resource_bind_resource_interface(bridge_res, OC_IF_R);
  oc_resource_set_default_interface(bridge_res, OC_IF_R);
  oc_resource_set_discoverable(bridge_res, true);
  // TODO do we need to make the oic.r.vodlist periodic observable?
  oc_resource_set_periodic_observable(bridge_res, 30);
  oc_resource_set_request_handler(bridge_res, OC_GET, get_bridge, NULL);
  if (!oc_add_resource(bridge_res)) {
    return -1;
  }
  oc_vod_map_init();

#ifdef OC_SECURITY
  oc_add_ownership_status_cb(&doxm_owned_changed, NULL);
#endif // OC_SECURITY
  return 0;
}

size_t
oc_bridge_add_virtual_device(const uint8_t *virtual_device_id,
                             size_t virtual_device_id_size, const char *econame,
                             const char *uri, const char *rt, const char *name,
                             const char *spec_version,
                             const char *data_model_version,
                             oc_add_device_cb_t add_device_cb, void *data)
{
  size_t vd_index =
    oc_vod_map_add_id(virtual_device_id, virtual_device_id_size, econame);

  oc_device_info_t *device = oc_core_add_new_device_at_index(
    uri, rt, name, spec_version, data_model_version, vd_index, add_device_cb,
    data);
  if (!device) {
    return 0;
  }

  if (oc_uuid_is_nil(&device->piid)) {
    oc_gen_uuid(&device->piid);
#ifdef OC_SECURITY
    oc_sec_dump_unique_ids(vd_index);
#endif /* OC_SECURITY */
  }
  /*
   * According to the security specification:
   * An Unowned VOD shall not accept DTLS connection attempts nor TLS connection
   * attempts nor any other requests, including discovery requests, while the
   * Bridge (that created that VOD) is Unowned.
   *
   * For that reason only init connectivity if the bridge device is owned or
   * if the virtual device is already owned.
   *
   * The `doxm_owned_changed` callback is responsible for calling
   * oc_connectivity_init and oc_connectivity_shutdown  for virtual devices
   * when the ownership of the bridge device changes.
   */
#ifdef OC_SECURITY
  if (oc_is_owned_device(bridge_res->device) || oc_is_owned_device(vd_index)) {
    if (oc_connectivity_init(vd_index) < 0) {
      oc_abort("error initializing connectivity for device");
    }
    OC_DBG("oc_bridge: init connectivity for virtual device %zd", vd_index);
  }
#else
  if (oc_connectivity_init(vd_index) < 0) {
    oc_abort("error initializing connectivity for device");
  }
#endif /* OC_SECURITY */

  oc_device_bind_resource_type(vd_index, "oic.d.virtual");

#ifdef OC_SECURITY
  if (oc_is_owned_device(vd_index)) {
    add_virtual_device_to_vods_list(name, oc_core_get_device_id(vd_index),
                                    econame);
    oc_notify_observers(bridge_res);
  }
#endif // OC_SECURITY
  return vd_index;
}

int
oc_bridge_remove_virtual_device(size_t device_index)
{
  if (oc_bridge_is_virtual_device(device_index)) {
    remove_virtual_device_from_vods_list(oc_core_get_device_id(device_index));
    oc_connectivity_shutdown(device_index);
    return 0;
  }
  return -1;
}

int
oc_bridge_delete_virtual_device(size_t device_index)
{
  if (oc_bridge_is_virtual_device(device_index)) {
    oc_uuid_t nil_uuid = { { 0 } };
    oc_set_immutable_device_identifier(device_index, &nil_uuid);
    oc_core_remove_device_at_index(device_index);
    oc_vod_map_remove_id(device_index);
    return 0;
  }
  return -1;
}

size_t
oc_bridge_get_virtual_device_index(const uint8_t *virtual_device_id,
                                   size_t virtual_device_id_size,
                                   const char *econame)
{
  return oc_vod_map_get_id_index(virtual_device_id, virtual_device_id_size,
                                 econame);
}

oc_virtual_device_t *
oc_bridge_get_virtual_device_info(size_t virtual_device_index)
{
  return oc_vod_map_get_virtual_device(virtual_device_index);
}
