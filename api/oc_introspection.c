/****************************************************************************
 *
 * Copyright (c) 2017 Intel Corporation
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

#include "util/oc_features.h"

#ifdef OC_INTROSPECTION

#include "api/oc_core_res_internal.h"
#include "api/oc_endpoint_internal.h"
#include "api/oc_introspection_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_server_api_internal.h"
#include "api/oc_storage_internal.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_introspection.h"
#include "port/oc_log_internal.h"
#include "port/oc_storage_internal.h"
#include "util/oc_macros_internal.h"

#ifdef OC_HAS_FEATURE_CRC_ENCODER
#include "port/oc_storage_internal.h"
#include "util/oc_crc_internal.h"
#endif /* OC_HAS_FEATURE_CRC_ENCODER */

#ifndef OC_IDD_API
#include "server_introspection.dat.h"
#else /* OC_IDD_API */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_STORAGE
#error Preprocessor macro OC_IDD_API is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_IDD_API is defined.
#endif /* !OC_STORAGE */

void
oc_set_introspection_data(size_t device, const uint8_t *IDD, size_t IDD_size)
{
  char idd_tag[OC_STORAGE_SVR_TAG_MAX];
  if (oc_storage_gen_svr_tag(OC_INTROSPECTION_WK_STORE_NAME, device, idd_tag,
                             sizeof(idd_tag)) < 0) {
    OC_ERR("cannot set introspection data: failed to generate tag");
    return;
  }
  long rr = oc_storage_write(idd_tag, IDD, IDD_size);
  if (rr < 0) {
    OC_ERR("cannot set introspection data: failed to write data");
    return;
  }
  OC_DBG("\tIntrospection data set written data size: %ld [bytes]\n", rr);
}

#endif /* !OC_IDD_API */

long
oc_introspection_get_data(size_t device, uint8_t *buffer, size_t buffer_size)
{
#ifdef OC_IDD_API
  char idd_tag[OC_STORAGE_SVR_TAG_MAX];
  if (oc_storage_gen_svr_tag(OC_INTROSPECTION_WK_STORE_NAME, device, idd_tag,
                             sizeof(idd_tag)) < 0) {
    OC_ERR("cannot get introspection data: failed to generate tag");
    return -1;
  }
  if (buffer == NULL) {
    return oc_storage_size(idd_tag);
  }
  long ret = oc_storage_read(idd_tag, buffer, buffer_size);
  if (ret < 0) {
    OC_ERR("cannot get introspection data: failed to read data(error=%ld)",
           ret);
    return -1;
  }
  return ret;
#else  /* !OC_IDD_API */
  (void)device;
  if (buffer == NULL) {
    return introspection_data_size;
  }
  if (introspection_data_size < buffer_size) {
    memcpy(buffer, introspection_data, introspection_data_size);
    return introspection_data_size;
  }
  OC_ERR("cannot get introspection data: buffer size too small");
  return -1;
#endif /* OC_IDD_API */
}

static void
introspection_data_handler_cbor(oc_request_t *request)
{
  long IDD_size = oc_introspection_get_data(
    request->resource->device, request->response->response_buffer->buffer,
    request->response->response_buffer->buffer_size);
  if (IDD_size < 0) {
    OC_ERR(
      "oc_core_introspection_data_handler: failed to get introspection data");
    oc_send_response_internal(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                              APPLICATION_VND_OCF_CBOR, 0, true);
    return;
  }
  oc_send_response_internal(request, OC_STATUS_OK, APPLICATION_VND_OCF_CBOR,
                            IDD_size, true);
}

#ifdef OC_HAS_FEATURE_CRC_ENCODER
static void
introspection_data_handler_crc(oc_request_t *request)
{
  uint64_t crc = 0;
#ifdef OC_IDD_API
  char idd_tag[OC_STORAGE_SVR_TAG_MAX];
  if (oc_storage_gen_svr_tag(OC_INTROSPECTION_WK_STORE_NAME,
                             request->resource->device, idd_tag,
                             sizeof(idd_tag)) < 0) {
    OC_ERR("cannot encode introspection data: failed to generate tag");
    return;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  long ret = oc_storage_size(idd_tag);
  if (ret == -ENOENT || ret == 0) {
    OC_DBG("no introspection data");
    return;
  }
  if (ret < 0) {
    OC_ERR(
      "cannot encode introspection data: failed to get data size(error=%ld)",
      ret);
    return;
  }

  uint8_t *idd_data = calloc(1, (size_t)ret);
  ret = oc_storage_read(idd_tag, idd_data, (size_t)ret);
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t idd_data[4096] = { 0 };
  long ret = oc_storage_read(idd_tag, idd_data, OC_ARRAY_SIZE(idd_data));
#endif /* OC_DYNAMIC_ALLOCATION */
  if (ret <= 0) {
    OC_ERR("cannot encode introspection data: failed to read data(error=%ld)",
           ret);
#ifdef OC_DYNAMIC_ALLOCATION
    free(idd_data);
#endif /* OC_DYNAMIC_ALLOCATION */
    return;
  }
  crc = oc_crc64(0, idd_data, (size_t)ret);
#ifdef OC_DYNAMIC_ALLOCATION
  free(idd_data);
#endif /* OC_DYNAMIC_ALLOCATION */
#else  /* !OC_IDD_API */
  crc = oc_crc64(0, introspection_data, introspection_data_size);
#endif /* OC_IDD_API */
  if (oc_rep_encoder_write_uint(oc_rep_global_encoder(), oc_rep_get_encoder(),
                                crc) != CborNoError) {
    OC_ERR("cannot encode introspection data: failed to encode data");
  }

  request->response->response_buffer->response_length = sizeof(crc);
  request->response->response_buffer->code = CONTENT_2_05;
}

#endif /* OC_HAS_FEATURE_CRC_ENCODER */

static void
oc_core_introspection_data_handler(oc_request_t *request,
                                   oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  OC_DBG("in oc_core_introspection_data_handler");
  oc_rep_encoder_type_t et = oc_rep_encoder_get_type();
  if (et == OC_REP_CBOR_ENCODER) {
    introspection_data_handler_cbor(request);
    return;
  }

#ifdef OC_HAS_FEATURE_CRC_ENCODER
  if (et == OC_REP_CRC_ENCODER) {
    introspection_data_handler_crc(request);
    return;
  }
#endif /* OC_HAS_FEATURE_CRC_ENCODER */

  OC_DBG("oc_core_introspection_data_handler: cannot encode introspection data "
         "by encoder %d",
         et);
  oc_send_response_internal(request, OC_IGNORE, APPLICATION_VND_OCF_CBOR, 0,
                            false);
}

bool
oc_introspection_wk_get_uri(size_t device, int interface_index,
                            transport_flags flags, oc_string_t *uri)
{
  /* We are interested in only a single coap:// endpoint on this logical device.
   */
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(device);
  while (eps != NULL) {
    if ((interface_index == -1 ||
         eps->interface_index == (unsigned)interface_index) &&
        (eps->flags == flags)) {
      oc_string64_t ep;
      if (oc_endpoint_to_string64(eps, &ep)) {
        oc_concat_strings(uri, oc_string(ep), OC_INTROSPECTION_DATA_URI);
        return true;
      }
    }
    eps = eps->next;
  }
  return false;
}

static void
introspection_wk_encode(const char *uri, size_t uri_len,
                        const oc_resource_t *resource, bool include_baseline)
{
  oc_rep_start_root_object();
  if (include_baseline) {
    oc_process_baseline_interface(resource);
  }
  oc_rep_set_array(root, urlInfo);
  oc_rep_object_array_start_item(urlInfo);
  oc_rep_set_text_string_v1(urlInfo, protocol, "coap",
                            OC_CHAR_ARRAY_LEN("coap"));
  oc_rep_set_text_string_v1(urlInfo, url, uri, uri_len);
  oc_rep_object_array_end_item(urlInfo);
  oc_rep_close_array(root, urlInfo);
  oc_rep_end_root_object();
}

static void
oc_core_introspection_wk_handler(oc_request_t *request,
                                 oc_interface_mask_t iface_mask, void *data)
{
  (void)data;

  int if_index =
    (request->origin != NULL) ? (int)request->origin->interface_index : -1;
#ifdef OC_IPV4
  transport_flags flags =
    (request->origin != NULL && (request->origin->flags & IPV6)) ? IPV6 : IPV4;
#else  /* !OC_IPV4 */
  transport_flags flags = IPV6;
#endif /* OC_IPV4 */
  oc_string_t uri;
  memset(&uri, 0, sizeof(oc_string_t));
  if (!oc_introspection_wk_get_uri(request->resource->device, if_index, flags,
                                   &uri)) {
    OC_ERR("could not obtain introspection resource uri");
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  introspection_wk_encode(oc_string(uri), oc_string_len(uri), request->resource,
                          (iface_mask & OC_IF_BASELINE) != 0);
  oc_send_response_with_callback(request, OC_STATUS_OK, true);

  OC_DBG("got introspection resource uri %s", oc_string(uri));
  oc_free_string(&uri);
}

void
oc_create_introspection_resource(size_t device)
{
  OC_DBG("oc_introspection: Initializing introspection resource");

  oc_core_populate_resource(
    OCF_INTROSPECTION_WK, device, OC_INTROSPECTION_WK_URI,
    OC_INTROSPECTION_WK_IF_MASK, OC_INTROSPECTION_WK_DEFAULT_IF,
    OC_SECURE | OC_DISCOVERABLE, oc_core_introspection_wk_handler, /*put*/ NULL,
    /*post*/ NULL,
    /*delete*/ NULL, 1, OC_INTROSPECTION_WK_RT);

  oc_core_populate_resource(
    OCF_INTROSPECTION_DATA, device, OC_INTROSPECTION_DATA_URI,
    OC_INTROSPECTION_DATA_IF_MASK, OC_INTROSPECTION_DATA_DEFAULT_IF,
    /*properties*/ 0, oc_core_introspection_data_handler,
    /*put*/ NULL,
    /*post*/ NULL, /*delete*/ NULL, 1, OC_INTROSPECTION_DATA_RT);
}

#endif /* OC_INTROSPECTION */
