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

#ifdef OC_SECURITY
#include "security/oc_store.h"
#endif // OC_SECURITY

OC_LIST(oc_vods_list_t);
static oc_resource_t *bridge_res;

void
add_virtual_device_to_vods_list(const char *name, const oc_uuid_t *di,
                                const char *econame)
{
  oc_vods_t *vod = (oc_vods_t *)malloc(sizeof(oc_vods_t));
  oc_new_string(&vod->name, name, strlen(name));
  vod->di = di;
  oc_new_string(&vod->econame, econame, strlen(econame));
  oc_list_add(oc_vods_list_t, vod);
}

void
remove_virtual_device_from_vods_list(const oc_uuid_t *di)
{
  oc_vods_t *vod_item = (oc_vods_t *)oc_list_head(oc_vods_list_t);
  while (vod_item) {
    if (memcmp(vod_item->di, di, 16) == 0) {
      oc_list_remove(oc_vods_list_t, vod_item);
      oc_free_string(&vod_item->name);
      oc_free_string(&vod_item->econame);
      free(vod_item);
      break;
    }
    vod_item = vod_item->next;
  }
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
    oc_vods_t *vods_list = (oc_vods_t *)oc_list_head(oc_vods_list_t);
    while (vods_list) {
      oc_rep_object_array_begin_item(vods);
      oc_rep_set_text_string(vods, n, oc_string(vods_list->name));
      oc_uuid_to_str(vods_list->di, di_str, OC_UUID_LEN);
      oc_rep_set_text_string(vods, di, di_str);
      oc_rep_set_text_string(vods, econame, oc_string(vods_list->econame));
      oc_rep_object_array_end_item(vods);
      vods_list = vods_list->next;
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
void
doxm_owned_changed(const oc_uuid_t *device_uuid, size_t device_index,
                   bool owned, void *user_data)
{
  (void)user_data;
  if (owned) {
    oc_resource_t *r = oc_core_get_resource_by_index(OCF_D, device_index);
    for (size_t i = 0; i < oc_string_array_get_allocated_size(r->types); i++) {
      if (strncmp(oc_string_array_get_item(r->types, i), "oic.d.virtual", 14) ==
          0) {
        oc_device_info_t *device_info = oc_core_get_device_info(device_index);
        oc_string_t econame;
        oc_vod_map_get_econame(&econame, device_index);
        add_virtual_device_to_vods_list(oc_string(device_info->name),
                                        device_uuid, oc_string(econame));
      }
    }
  } else {
    remove_virtual_device_from_vods_list(device_uuid);
  }
  oc_notify_observers(bridge_res);
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

int
oc_bridge_add_virtual_device(const uint8_t *virtual_device_id,
                             size_t virtual_device_id_size, const char *econame,
                             const char *uri, const char *rt, const char *name,
                             const char *spec_version,
                             const char *data_model_version,
                             oc_add_device_cb_t add_device_cb, void *data)
{
  (void)virtual_device_id;

  size_t vd_index =
    oc_vod_map_add_id(virtual_device_id, virtual_device_id_size, econame);

  oc_device_info_t *device = oc_core_add_new_device_at_index(
    uri, rt, name, spec_version, data_model_version, vd_index, add_device_cb,
    data);
  if (!device) {
    return -1;
  }

  oc_device_bind_resource_type(vd_index, "oic.d.virtual");

#ifdef OC_SECURITY
  if (oc_is_owned_device(vd_index)) {
    add_virtual_device_to_vods_list(name, oc_core_get_device_id(vd_index),
                                    econame);
    oc_notify_observers(bridge_res);
  }
#endif // OC_SECURITY
  return 0;
}
