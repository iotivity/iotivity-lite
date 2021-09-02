/*
 // Copyright (c) 2019 Intel Corporation
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
 // You may obtain a copy of the License at
 //
 //      http://www.apache.org/licenses/LICENSE-2.0
 //
 // Unless required by applicable law or agreed to in writing, software
 // distributed under the License is distributed on an "AS IS" BASIS,
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
 */

#include "oc_api.h"
#ifdef OC_MNT
#include "api/oc_mnt.h"
#include "oc_core_res.h"
#include <stdio.h>
#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#endif /* OC_SECURITY */

void
get_mnt(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, fr, false);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

void
post_mnt(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  bool fr = false, success = false;
  if (oc_rep_get_bool(request->request_payload, "fr", &fr)) {
    if (fr) {
#ifdef OC_SECURITY
      if (oc_pstat_reset_device(request->resource->device, false)) {
        success = true;
      }
#else  /* OC_SECURITY */
      success = true;
#endif /* !OC_SECURITY */
    }
  }

  if (success) {
    oc_rep_new(request->response->response_buffer->buffer,
               OC_MAX_APP_DATA_SIZE);
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, fr, false);
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

void
oc_create_maintenance_resource(size_t device)
{
  OC_DBG("oc_introspection: Initializing maintehance resource");

  oc_core_populate_resource(
    OCF_MNT, device, "oic/mnt", OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
    OC_SECURE | OC_DISCOVERABLE, get_mnt, 0, post_mnt, 0, 1, "oic.wk.mnt");
}
#endif /* OC_MNT */
