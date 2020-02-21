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
#include "port/oc_log.h"
#include "security/oc_store.h"

OC_LIST(oc_vods_list_t);

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
    oc_vods_t *vods_list = (oc_vods_t *)oc_list_head(oc_vods_list_t);
    while (vods_list) {
      // bridge and vod should be owned before they are added to the
      // oc_vods_list_t adding to the oc_vods_list_t likely needs to be
      // done based on security the doxm code.
      oc_rep_object_array_begin_item(vods);
      oc_rep_set_text_string(vods, n, oc_string(vods_list->name));
      oc_rep_set_text_string(vods, di, vods_list->di);
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

  oc_resource_t *bridge_res =
    oc_new_resource(name, "/bridge/vodlist", 1, bridge_device_index);
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
  return 0;
}

/*
 * TODO must figure out a way to index each device. Just calling oc_add_device
 * will create a new index device.
 *
 * I am leaning toward using a map similar to this
 * {
 *   {"vid":"virtual_device_id-1", "index":1},
 *   {"vid":"virtual_device_id-2", "index":2}
 * }
 */
int
oc_bridge_add_virtual_device(const char *virtual_device_id, const char *uri,
                             const char *rt, const char *name,
                             const char *spec_version,
                             const char *data_model_version,
                             oc_add_device_cb_t add_device_cb, void *data)
{
  (void)virtual_device_id;
  int ret_value = oc_add_device(uri, rt, name, spec_version, data_model_version,
                                add_device_cb, data);
  if (ret_value < 0) {
    return ret_value;
  }
  oc_device_bind_resource_type(oc_core_get_num_devices() - 1, "oic.d.virtual");
  return ret_value;
}
