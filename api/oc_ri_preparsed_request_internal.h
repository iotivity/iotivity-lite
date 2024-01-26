/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
 ***************************************************************************/

#ifndef OC_RI_PREPARSED_REQUEST_INTERNAL_H
#define OC_RI_PREPARSED_REQUEST_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "messaging/coap/coap_internal.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "util/oc_features.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  oc_string_view_t uri_path;
  oc_string_view_t uri_query;
  oc_content_format_t cf;
  oc_content_format_t accept;
  oc_resource_t *cur_resource;
  oc_interface_mask_t iface_query;
#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
  bool resource_is_collection;
#endif /* OC_COLLECTIONS && OC_SERVER */
} oc_ri_preparsed_request_obj_t;

/**
 * @brief Parse the request header, set the resource, and store the values in
 * the preparsed_request.
 *
 * @param request The source request for parsing.
 * @param preparsed_request_obj Object to store the preparsed request values.
 * @param endpoint To set the OCF version.
 */
void oc_ri_prepare_request(const coap_packet_t *request,
                           oc_ri_preparsed_request_obj_t *preparsed_request_obj,
                           oc_endpoint_t *endpoint) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_RI_PREPARSED_REQUEST_INTERNAL_H */
