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

#include "oc_introspection.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_introspection_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include "oc_config.h"

#ifndef OC_IDD_API
#include "server_introspection.dat.h"
#else /* OC_IDD_API */

#if !defined(OC_STORAGE) && defined(OC_IDD_API)
#error Preprocessor macro OC_IDD_API is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_IDD_API is defined.
#endif

#define MAX_TAG_LENGTH 20

static void
gen_idd_tag(const char *name, size_t device_index, char *idd_tag)
{
  int idd_tag_len =
    snprintf(idd_tag, MAX_TAG_LENGTH, "%s_%zd", name, device_index);
  idd_tag_len =
    (idd_tag_len < MAX_TAG_LENGTH) ? idd_tag_len + 1 : MAX_TAG_LENGTH;
  idd_tag[idd_tag_len] = '\0';
}

void
oc_set_introspection_data(size_t device, uint8_t *IDD, size_t IDD_size)
{
  char idd_tag[MAX_TAG_LENGTH];
  gen_idd_tag("IDD", device, idd_tag);
  oc_storage_write(idd_tag, IDD, IDD_size);
}
#endif /*OC_IDD_API*/

static void
oc_core_introspection_data_handler(oc_request_t *request,
                                   oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  OC_DBG("in oc_core_introspection_data_handler");

  long IDD_size = 0;
#ifndef OC_IDD_API
  if (introspection_data_size < OC_MAX_APP_DATA_SIZE) {
    memcpy(request->response->response_buffer->buffer, introspection_data,
           introspection_data_size);
    IDD_size = introspection_data_size;
  } else {
    IDD_size = -1;
  }
#else  /* OC_IDD_API */
  char idd_tag[MAX_TAG_LENGTH];
  gen_idd_tag("IDD", request->resource->device, idd_tag);
  IDD_size = oc_storage_read(
    idd_tag, request->response->response_buffer->buffer, OC_MAX_APP_DATA_SIZE);
#endif /* OC_IDD_API */

  if (IDD_size >= 0 && IDD_size < OC_MAX_APP_DATA_SIZE) {
    request->response->response_buffer->response_length = (uint16_t)IDD_size;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else {
    OC_ERR(
      "oc_core_introspection_data_handler : %ld is too big for buffer %ld \n",
      IDD_size, OC_MAX_APP_DATA_SIZE);
    request->response->response_buffer->response_length = (uint16_t)0;
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_INTERNAL_SERVER_ERROR);
  }
}

static void
oc_core_introspection_wk_handler(oc_request_t *request,
                                 oc_interface_mask_t iface_mask, void *data)
{
  (void)data;

  int interface_index =
    (request->origin) ? request->origin->interface_index : -1;
  enum transport_flags conn =
    (request->origin && (request->origin->flags & IPV6)) ? IPV6 : IPV4;
  /* We are interested in only a single coap:// endpoint on this logical device.
   */
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(request->resource->device);
  oc_string_t ep, uri;
  memset(&uri, 0, sizeof(oc_string_t));
  while (eps != NULL) {
    if ((interface_index == -1 || eps->interface_index == interface_index) &&
        !(eps->flags & SECURED) && (eps->flags == conn)) {
      if (oc_endpoint_to_string(eps, &ep) == 0) {
        oc_concat_strings(&uri, oc_string(ep), "/oc/introspection");
        oc_free_string(&ep);
        break;
      }
    }
    eps = eps->next;
  }

  if (oc_string_len(uri) <= 0) {
    OC_ERR("could not obtain introspection resource uri");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  oc_rep_start_root_object();

  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R: {
    oc_rep_set_array(root, urlInfo);
    oc_rep_object_array_start_item(urlInfo);
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

  OC_DBG("got introspection resource uri %s", oc_string(uri));
  oc_free_string(&uri);
}

void
oc_create_introspection_resource(size_t device)
{
  OC_DBG("oc_introspection: Initializing introspection resource");

  oc_core_populate_resource(
    OCF_INTROSPECTION_WK, device, "oc/wk/introspection",
    OC_IF_R | OC_IF_BASELINE, OC_IF_R, OC_SECURE | OC_DISCOVERABLE,
    oc_core_introspection_wk_handler, 0, 0, 0, 1, "oic.wk.introspection");
  oc_core_populate_resource(OCF_INTROSPECTION_DATA, device, "oc/introspection",
                            OC_IF_BASELINE, OC_IF_BASELINE, 0,
                            oc_core_introspection_data_handler, 0, 0, 0, 1,
                            "x.org.openconnectivity.oic.introspection.data");
}
