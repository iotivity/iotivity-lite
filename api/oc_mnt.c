/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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
 ****************************************************************************/

#include "oc_api.h"

#ifdef OC_MNT

#include "api/oc_core_res_internal.h"
#include "api/oc_mnt_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_core_res.h"
#include "oc_ri.h"
#include "port/oc_log_internal.h"
#include "util/oc_compiler.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

#include <stdio.h>

static int
mnt_encode(const oc_resource_t *resource, oc_interface_mask_t iface)
{
  oc_rep_start_root_object();
  if (iface == OC_IF_BASELINE) {
    oc_process_baseline_interface(resource);
  }
  oc_rep_set_boolean(root, fr, false);
  oc_rep_end_root_object();
  return oc_rep_get_cbor_errno();
}

static void
mnt_resource_get(oc_request_t *request, oc_interface_mask_t iface, void *data)
{
  (void)data;
  CborError err = mnt_encode(request->resource, iface);
  if (err != CborNoError) {
    OC_ERR("oc_mnt: encoding of resource payload failed(error=%d)", (int)err);
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

static void
mnt_resource_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *data)
{
  (void)iface_mask;
  (void)data;

  bool fr = false;
  bool success = false;
  if (oc_rep_get_bool(request->request_payload, "fr", &fr) && fr) {
#ifdef OC_SECURITY
    success = oc_reset_device_v1(request->resource->device, false);
#else  /* !OC_SECURITY */
    success = true;
#endif /* OC_SECURITY */
  }

  if (!success) {
    OC_ERR("oc_mnt: invalid POST request");
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  oc_rep_new_realloc_v1(&request->response->response_buffer->buffer,
                        request->response->response_buffer->buffer_size,
                        OC_MAX_APP_DATA_SIZE);
#else  /* !OC_DYNAMIC_ALLOCATION */
  oc_rep_new_v1(request->response->response_buffer->buffer,
                request->response->response_buffer->buffer_size);
#endif /* OC_DYNAMIC_ALLOCATION */
  int err = mnt_encode(request->resource, iface_mask);
  if (err != CborNoError) {
    OC_ERR("oc_mnt: encoding resource payload failed(error=%d)", (int)err);
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  request->response->response_buffer->buffer =
    oc_rep_shrink_encoder_buf(request->response->response_buffer->buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
}

void
oc_create_maintenance_resource(size_t device)
{
  OC_DBG("oc_mnt: Initializing maintenance resource");
  int interfaces = OC_IF_RW | OC_IF_BASELINE;
  oc_interface_mask_t default_interface = OC_IF_RW;
  assert((interfaces & default_interface) == default_interface);
  int properties = OC_SECURE | OC_DISCOVERABLE;
  oc_core_populate_resource(OCF_MNT, device, OCF_MNT_URI, interfaces,
                            default_interface, properties, mnt_resource_get,
                            /*put*/ NULL, mnt_resource_post, /*delete*/ NULL, 1,
                            OCF_MNT_RT);
}

bool
oc_is_maintenance_resource_uri(oc_string_view_t uri)
{
  return oc_resource_match_uri(OC_STRING_VIEW(OCF_MNT_URI), uri);
}

#endif /* OC_MNT */
