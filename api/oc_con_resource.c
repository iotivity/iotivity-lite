/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
 *
 ******************************************************************/

#include "api/oc_con_resource_internal.h"
#include "api/oc_core_res_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_server_api_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_rep.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>
#include <stdbool.h>

static bool g_announce_con_res = false;

bool
oc_get_con_res_announced(void)
{
  return g_announce_con_res;
}

void
oc_set_con_res_announced(bool announce)
{
  g_announce_con_res = announce;
}

static void
con_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                 void *data)
{
  (void)data;
  assert((iface_mask & OC_CON_IF_MASK) != 0);

  size_t device = request->resource->device;
  oc_rep_start_root_object();

  if (iface_mask == OC_IF_BASELINE) {
    oc_process_baseline_interface(request->resource);
  }
  /* oic.wk.d attribute n shall always be the same value as
    oic.wk.con attribute n. */
  oc_device_info_t *info = oc_core_get_device_info(device);
  if (info != NULL) {
    oc_rep_set_text_string_v1(root, n, oc_string(info->name),
                              oc_string_len(info->name));
  }

  const oc_resource_t *dev = oc_core_get_resource_by_index(OCF_D, device);
  if (dev->tag_locn > 0) {
    const char *locn = oc_enum_locn_to_str(dev->tag_locn);
    if (locn != NULL) {
      // see oc_locns in oc_enums.c and choose a constant at least as big as the
      // longest string
#define OC_LOCN_MAXLEN (32)
      oc_rep_set_text_string_v1(root, locn, locn,
                                oc_strnlen(locn, OC_LOCN_MAXLEN));
    }
  }

  oc_rep_end_root_object();
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

static void
con_resource_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *data)
{
  (void)iface_mask;
  size_t device = request->resource->device;
  const oc_string_t *name = NULL;
  const oc_string_t *locn = NULL;
  for (const oc_rep_t *rep = request->request_payload; rep != NULL;
       rep = rep->next) {
    if (rep->type != OC_REP_STRING || oc_string_len(rep->value.string) == 0) {
      oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
      return;
    }

    if (oc_rep_is_property(rep, OC_CON_PROP_NAME,
                           OC_CHAR_ARRAY_LEN(OC_CON_PROP_NAME))) {
      name = &rep->value.string;
      continue;
    }

    if (oc_rep_is_property(rep, OC_CON_PROP_LOCATION,
                           OC_CHAR_ARRAY_LEN(OC_CON_PROP_LOCATION))) {
      locn = &rep->value.string;
      continue;
    }

    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  oc_resource_t *dev = oc_core_get_resource_by_index(OCF_D, device);
  if (dev == NULL) {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  bool changed = false;
  if (name != NULL) {
    oc_core_device_set_name(device, oc_string(*name), oc_string_len(*name));
#if defined(OC_SERVER)
    oc_notify_resource_changed_delayed_ms(dev, 0);
#endif /* OC_SERVER */
    oc_rep_start_root_object();
    oc_device_info_t *info = oc_core_get_device_info(device);
    oc_rep_set_text_string_v1(root, n, oc_string(info->name),
                              oc_string_len(info->name));
    oc_rep_end_root_object();
    changed = true;
  }

  if (locn != NULL) {
    if (dev->tag_locn == 0) {
      oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
      return;
    }

    bool oc_defined = false;
    oc_locn_t oc_locn = oc_str_to_enum_locn(*locn, &oc_defined);
    if (!oc_defined) {
      oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
      return;
    }
    oc_resource_tag_locn(dev, oc_locn);
    changed = true;
  }

  if (!changed) {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  if (data != NULL) {
    oc_con_write_cb_t cb = *(oc_con_write_cb_t *)(&data);
    cb(device, request->request_payload);
  }

  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
}

#ifdef OC_SERVER

void
oc_set_con_write_cb(oc_con_write_cb_t callback)
{
  for (size_t i = 0; i < oc_core_get_num_devices(); i++) {
    oc_resource_t *res = oc_core_get_resource_by_index(OCF_CON, i);
    if (res != NULL) {
      res->post_handler.user_data = *(void **)(&callback);
    }
  }
}

#endif /* OC_SERVER */

void
oc_create_con_resource(size_t device)
{
  oc_core_populate_resource(OCF_CON, device, OC_CON_URI, OC_CON_IF_MASK,
                            OC_CON_DEFAULT_IF, OC_CON_PROPERTY_MASK,
                            con_resource_get, con_resource_post,
                            con_resource_post, /*delete*/ NULL, 1, OC_CON_RT);
}
