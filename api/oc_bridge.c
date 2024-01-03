/******************************************************************
 *
 * Copyright 2020 Intel Corporation
 * Copyright 2023 ETRI Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_BRIDGE

#include "oc_bridge.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_core_res_internal.h"
#include <oc_vod_map.h>
#include "port/oc_log_internal.h"
#include "port/oc_assert.h"

#ifdef OC_SECURITY
#include "oc_store.h"
#endif // OC_SECURITY

/*
 * internal struct that holds the values that build the `oic.r.vodlist`
 * properties.
 */
#if 0
typedef struct oc_vods_s
{
  struct oc_vods_s *next;
  oc_string_t name;
  oc_uuid_t di;
  oc_string_t econame;
} oc_vods_t;
#endif

OC_LIST(g_vods);
static oc_resource_t *g_vodlist_res;

#define OC_PRINT_VODSLIST                                                      \
  OC_DBG("\"vods\": [");                                                       \
  oc_vods_t *print_vod_item = (oc_vods_t *)oc_list_head(g_vods);       \
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
    if (strncmp(oc_string_array_get_item(r->types, i), "oic.d.virtual", strlen("oic.d.virtual")) ==
        0) {
      return true;
    }
  }
  return false;
}

static void
add_virtual_device_to_vods_list(const char *name, const oc_uuid_t *di,
                                const char *econame)
{
  oc_vods_t *vod = (oc_vods_t *)malloc(sizeof(oc_vods_t));
  oc_new_string(&vod->name, name, strlen(name));
//  oc_uuid_copy(&vod->di, di);
  memcpy(&vod->di, di, sizeof(oc_uuid_t));
  oc_new_string(&vod->econame, econame, strlen(econame));

#if 0
  /* find corresponding VOD mapping entry */
  size_t device_index;
  if (oc_core_get_device_index(vod->di , &device_index) < 0) {
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(&vod->di, uuid, OC_UUID_LEN);
    OC_DBG("oc_bridge: failed to find Device whose ID is (%s)", uuid);
  }

  /* mark that this VOD is online */
  oc_virtual_device_t *vod_mapping_item = oc_bridge_get_virtual_device_info(device_index);
#endif

  /* mark this vod is online... */
  oc_virtual_device_t *vod_mapping_item = oc_bridge_get_vod_mapping_info2(vod);
  if (vod_mapping_item) {
    vod_mapping_item->is_vod_online = true;
  } else {
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(&vod->di, uuid, OC_UUID_LEN);
    OC_DBG("oc_bridge: failed to find Device whose ID is (%s)", uuid);
  }

  oc_list_add(g_vods, vod);

  OC_DBG("=====> oc_bridge: adding %s [%s] from oic.r.vodlist", name, econame);
  OC_PRINT_VODSLIST;
}

/*
 * remove VOD from `oic.r.vodlist` Resource
 */
static void
remove_virtual_device_from_vods_list(const oc_uuid_t *di)
{
  oc_vods_t *vod_item = (oc_vods_t *)oc_list_head(g_vods);
  while (vod_item) {
    if (memcmp(&vod_item->di, di, 16) == 0) {

      /* mark this vod is offline */
      oc_virtual_device_t *vod_mapping_item = oc_bridge_get_vod_mapping_info2(vod_item);
      if (vod_mapping_item) {
        vod_mapping_item->is_vod_online = false;
      } else {
        char uuid[OC_UUID_LEN];
        oc_uuid_to_str(&vod_item->di, uuid, OC_UUID_LEN);
        OC_DBG("oc_bridge: failed to find Device whose ID is (%s)", uuid);
      }

      oc_list_remove(g_vods, vod_item);
      OC_DBG("=====> oc_bridge: removing %s [%s] from oic.r.vodlist",
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
    oc_vods_t *vod_item = (oc_vods_t *)oc_list_head(g_vods);
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
static void
doxm_owned_changed(const oc_uuid_t *device_uuid, size_t device_index,
                   bool owned, void *user_data)
{
  (void)user_data;
  /* Bridge Device */
  if (g_vodlist_res->device == device_index) {
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
            oc_connectivity_ports_t ports;
            memset(&ports, 0, sizeof(ports));

            OC_DBG("=====> Bridge is owned, VOD %ld connection is being initialized!!", device);

            if (oc_connectivity_init(device, ports) < 0) {
              oc_abort("error initializing connectivity for device");
            }
            OC_DBG("======> oc_bridge: init connectivity for virtual device %zd",
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
          oc_virtual_device_t *vod_mapping_item = oc_bridge_get_vod_mapping_info(device);
          if (vod_mapping_item) {
            vod_mapping_item->is_vod_online = false;
          }

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
      /*
       * if corresponding non-OCF device is still in paired
       * while this VOD is offboard and onboard again.
       *
       * the device ID of corresponding OCF Device stored in non-OCF
       * device cache could point wrong OCF Device..
       *
       * => NOP!!!. onboard/offboard DON"T delete oc_device_info_t
       * from g_oc_device_info[] array!!
       */
      if (oc_bridge_is_virtual_device(device_index)) {
        oc_device_info_t *device_info = oc_core_get_device_info(device_index);
        oc_string_t econame;
        oc_vod_map_get_econame(&econame, device_index);
        add_virtual_device_to_vods_list(oc_string(device_info->name),
                                        device_uuid, oc_string(econame));
        OC_DBG("======> oc_bridge: adding %s [%s] to oic.r.vodslist",
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
    if (oc_is_owned_device(g_vodlist_res->device)) {
      oc_notify_observers(g_vodlist_res);
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

  g_vodlist_res = oc_new_resource(name, "/bridge/vodlist", 1, bridge_device_index);
  oc_resource_bind_resource_type(g_vodlist_res, "oic.r.vodlist");
  oc_resource_bind_resource_interface(g_vodlist_res, OC_IF_R);
  oc_resource_set_default_interface(g_vodlist_res, OC_IF_R);
  oc_resource_set_discoverable(g_vodlist_res, true);
  /*
   * TODO4ME <2023/7/24> do we need to make the oic.r.vodlist periodic observable?
   * oc_resource_set_periodic_observable(g_vodlist_res, 30);
   */
  oc_resource_set_request_handler(g_vodlist_res, OC_GET, get_bridge, NULL);
  if (!oc_add_resource(g_vodlist_res)) {
    return -1;
  }

  /*
   * - initialize VOD mapping list : `g_vod_mapping_list.vods`
   * - initialize `g_vod_mapping_list.next_index` with `g_device_count`
   * - load existing `g_vod_mapping_list` from disk
   */
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
  /*
   * add new VOD mapping entry (identified by vod_id) to the proper position of
   * `oc_vod_mapping_list_t.vods` list, and update
   * `g_vod_mapping_list.next_index`
   *
   * vd_index : index of `g_oc_device_info[]` which new Device for the VOD
   * will be stored.
   */
  size_t vd_index =
    oc_vod_map_add_mapping_entry(virtual_device_id, virtual_device_id_size, econame);

  oc_add_new_device_t cfg = {
      .uri = uri,
      .rt = rt,
      .name = name,
      .spec_version = spec_version,
      .data_model_version = data_model_version,
      .add_device_cb = add_device_cb,
      .add_device_cb_data = data,
  };

  /*
   * add corresponding new Device (`oc_device_info_t`) to `g_oc_device_info[vd_index]`
   */
  oc_device_info_t *device = oc_core_add_new_device_at_index(cfg, vd_index);

  if (!device) {
    return 0;
  }

  /*
   * FIXME4ME <2023/12/11> oc_bridge_add_virtual_device() : do we need this code?
   */
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
  if (oc_is_owned_device(g_vodlist_res->device) || oc_is_owned_device(vd_index)) {
    oc_connectivity_ports_t ports;
    memset(&ports, 0, sizeof(ports));
    if (oc_connectivity_init(vd_index, ports) < 0) {
      oc_abort("error initializing connectivity for device");
    }
    OC_DBG("=====> oc_bridge: init connectivity for virtual device %zd", vd_index);
  }
#else
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(ports));
  if (oc_connectivity_init(vd_index, ports) < 0) {
    oc_abort("error initializing connectivity for device");
  }
#endif /* OC_SECURITY */

  oc_device_bind_resource_type(vd_index, "oic.d.virtual");

#ifdef OC_SECURITY
  if (oc_is_owned_device(vd_index)) {
    add_virtual_device_to_vods_list(name, oc_core_get_device_id(vd_index),
                                    econame);
    oc_notify_observers(g_vodlist_res);
  }
#endif // OC_SECURITY
  return vd_index;
}


/*
 * DONE4ME <Oct 24, 2023> new_function() : add new function that add vod to "oic.r.vodlist:vods" only
 */
/*
 * @brief add new vodentry for an existing VOD to "oic.r.vodlist:vods".
 *        This function is usually called after `oc_bridge_remove_virtual_device()`
 *        is called.
 *        This function DOES NOT add new Device to `g_oc_device_info[]`, but
 *        just re-registre existing VOD to "oic.r.vodlist:vods" list.
 *
 * @param device_index
 * @return 0: success, -1: failure
 */
int
oc_bridge_add_vod(size_t device_index)
{
  oc_device_info_t *device;
  oc_virtual_device_t *vod_mapping_item;

  if (!(vod_mapping_item = oc_bridge_get_vod_mapping_info(device_index))) {
    OC_ERR("oc_bridge: failed to find VOD mapping entry which is corresponding to the Device (device index: %ld)", device_index);
    return -1;
  }

  if (!(device = oc_core_get_device_info(device_index))) {
    OC_ERR("oc_bridge: failed to find Device whose index is %ld", device_index);
    return -1;
  }

#ifdef OC_SECURITY
  if (oc_is_owned_device(g_vodlist_res->device) || oc_is_owned_device(device_index)) {
    oc_connectivity_ports_t ports;
    memset(&ports, 0, sizeof(ports));
    if (oc_connectivity_init(device_index, ports) < 0) {
      oc_abort("error initializing connectivity for device");
    }
    OC_DBG("oc_bridge: init connectivity for virtual device %ld", device_index);
  }
#else
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(ports));
  if (oc_connectivity_init(device_index, ports) < 0) {
    oc_abort("error initializing connectivity for device");
  }
#endif /* OC_SECURITY */


#ifdef OC_SECURITY
  if (oc_is_owned_device(device_index)) {
    add_virtual_device_to_vods_list(oc_string(device->name), oc_core_get_device_id(device_index),
                                    oc_string(vod_mapping_item->econame));
    oc_notify_observers(g_vodlist_res);
  }
#endif // OC_SECURITY

    return 0;
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
  /* 1. remove this from oic.r.vodlist:vods */
  oc_bridge_remove_virtual_device(device_index);

  /* 2. destroy Device and remove from VOD mapping list */
  if (oc_bridge_is_virtual_device(device_index)) {
    oc_uuid_t nil_uuid = { { 0 } };
    oc_set_immutable_device_identifier(device_index, &nil_uuid);
    oc_core_remove_device_at_index(device_index);
    oc_vod_map_remove_mapping_entry(device_index);
    return 0;
  }
  return -1;
}

size_t
oc_bridge_get_virtual_device_index(const uint8_t *virtual_device_id,
                                   size_t virtual_device_id_size,
                                   const char *econame)
{
  return oc_vod_map_get_vod_index(virtual_device_id, virtual_device_id_size,
                                 econame);
}

oc_virtual_device_t *
oc_bridge_get_vod_mapping_info(size_t virtual_device_index)
{
  return oc_vod_map_get_mapping_entry(virtual_device_index);
}

oc_virtual_device_t *
oc_bridge_get_vod_mapping_info2(oc_vods_t *vod)
{
  /* find corresponding VOD mapping entry */
  size_t device_index;
  if (oc_core_get_device_index(vod->di , &device_index) < 0) {
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(&vod->di, uuid, OC_UUID_LEN);
    OC_ERR("oc_bridge: failed to find Device whose ID is (%s)", uuid);
    return NULL;
  }

  return oc_vod_map_get_mapping_entry(device_index);
}


/*
 * @brief return entry of "oic.r.vodlist:vods" list
 * @param di Device id of the VOD to be returned
 * @return VOD entry [oc_vods_t]
 */
oc_vods_t *
oc_bridge_get_vod(oc_uuid_t di)
{
  oc_vods_t *item;

  item = (oc_vods_t *)oc_list_head(g_vods);

  while (item) {
    if (!oc_uuid_is_equal(item->di, di)) {
      return item;
    }
    item = item->next;
  }

  return NULL;
}



oc_vods_t *
oc_bridge_get_vod_list(void)
{
  return oc_list_head(g_vods);
}

void
oc_bridge_print_device_list(void)
{
  size_t device_count = oc_core_get_num_devices();
  char di[OC_UUID_LEN];
  char piid[OC_UUID_LEN];

  for (size_t i=0; i<device_count; i++) {
    oc_uuid_to_str(&oc_core_get_device_info(i)->di, di, OC_UUID_LEN);
    oc_uuid_to_str(&oc_core_get_device_info(i)->piid, piid, OC_UUID_LEN);
    printf("[ Device Index : %ld ]\n  |_ Device ID: %s\n  |_ PIID: %s\n  |_ Name: %s\n  |_ ICV: %s\n  |_ DMV: %s\n  |_ Enable: %d\n",
        i,
        di,
        piid,
        oc_string(oc_core_get_device_info(i)->name),
        oc_string(oc_core_get_device_info(i)->icv),
        oc_string(oc_core_get_device_info(i)->dmv),
        !oc_core_get_device_info(i)->is_removed);
  }
}


#endif /* OC_HAS_FEATURE_BRIDGE */
