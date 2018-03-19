/*
 // Copyright (c) 2017 Intel Corporation
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

#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"

static void
oc_core_introspection_data_handler(oc_request_t *request,
                                   oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;

  /* The buffer below contains a CBOR-encoded "empty" swagger description of
   * introspection data to return to clients. This is applicable ONLY to
   * applications that do not expose any non-core (or SVR) resources.
   */

  uint8_t introspection_empty[] = {
    0xBF, 0x67, 0x73, 0x77, 0x61, 0x67, 0x67, 0x65, 0x72, 0x63, 0x32, 0x2E,
    0x30, 0x64, 0x69, 0x6E, 0x66, 0x6F, 0xBF, 0x65, 0x74, 0x69, 0x74, 0x6C,
    0x65, 0x72, 0x65, 0x6D, 0x70, 0x74, 0x79, 0x20, 0x73, 0x77, 0x61, 0x67,
    0x67, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6C, 0x65, 0x67, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6F, 0x6E, 0x66, 0x76, 0x31, 0x2E, 0x30, 0x2E, 0x30, 0xFF,
    0x67, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x65, 0x73, 0x9F, 0x64, 0x68, 0x74,
    0x74, 0x70, 0xFF, 0x68, 0x63, 0x6F, 0x6E, 0x73, 0x75, 0x6D, 0x65, 0x73,
    0x9F, 0x70, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F,
    0x6E, 0x2F, 0x6A, 0x73, 0x6F, 0x6E, 0xFF, 0x68, 0x70, 0x72, 0x6F, 0x64,
    0x75, 0x63, 0x65, 0x73, 0x9F, 0x70, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63,
    0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x6A, 0x73, 0x6F, 0x6E, 0xFF, 0x65,
    0x70, 0x61, 0x74, 0x68, 0x73, 0xBF, 0xFF, 0x6B, 0x64, 0x65, 0x66, 0x69,
    0x6E, 0x69, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0xBF, 0xFF, 0xFF
  };

  /* Copy bytes into the response buffer that is set as the CoAP payload of
   * the response message.
   */

  memcpy(request->response->response_buffer->buffer, introspection_empty,
         sizeof(introspection_empty));
  request->response->response_buffer->response_length =
    sizeof(introspection_empty);
  request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
}

static void
oc_core_introspection_wk_handler(oc_request_t *request,
                                 oc_interface_mask_t interface, void *data)
{
  (void)data;

  /* We are interested in only a single coap:// endpoint on this logical device.
   */

  oc_endpoint_t *eps = oc_connectivity_get_endpoints(request->resource->device);
  oc_string_t ep, uri;
  memset(&uri, 0, sizeof(oc_string_t));
  while (eps != NULL) {
    if (!(eps->flags & SECURED)) {
      if (oc_endpoint_to_string(eps, &ep) == 0) {
        oc_concat_strings(&uri, oc_string(ep), "/oc/introspection");
        oc_free_string(&ep);
        break;
      }
    }
    eps = eps->next;
  }
  oc_free_endpoint_list();

  if (oc_string_len(uri) <= 0) {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  oc_rep_start_root_object();

  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R: {
    oc_rep_set_array(root, urlInfo);
    oc_rep_object_array_start_item(urlInfo);
    oc_rep_set_text_string(urlInfo, content-type, "application/cbor");
    oc_rep_set_text_string(urlInfo, protocol, "coap");
    oc_rep_set_text_string(urlInfo, url, oc_string(uri));
    oc_rep_object_array_end_item(urlInfo);
    oc_rep_close_array(root, urlInfo);
  } break;
  default:
    break;
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);

  oc_free_string(&uri);
}

void
oc_create_introspection_resource(int device)
{
  OC_DBG("oc_introspection: Initializing introspection resource\n");
  oc_core_populate_resource(OCF_INTROSPECTION_WK, device, "oc/wk/introspection",
                            OC_IF_R | OC_IF_BASELINE, OC_IF_R, OC_DISCOVERABLE,
                            oc_core_introspection_wk_handler, 0, 0, 0, 1,
                            "oic.wk.introspection");
  oc_core_populate_resource(OCF_INTROSPECTION_DATA, device, "oc/introspection",
                            OC_IF_BASELINE, OC_IF_BASELINE, 0,
                            oc_core_introspection_data_handler, 0, 0, 0, 1,
                            "oic.introspection.data");
}
