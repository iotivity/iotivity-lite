/****************************************************************************
 *
 * Copyright (c) 2021 Intel Corporation
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

#ifndef OC_SERVER_API_INTERNAL_H
#define OC_SERVER_API_INTERNAL_H

#include "oc_ri.h"

#ifdef OC_CLOUD
#include "oc_api.h"
#endif /* OC_CLOUD */

#ifdef OC_RES_BATCH_SUPPORT
#include "oc_endpoint.h"
#include "oc_uuid.h"
#include <cbor.h>
#endif /* OC_RES_BATCH_SUPPORT */

#ifdef OC_CLOUD

/**
 * @brief Callback invoked on resource before it is deleted by
 * oc_delayed_delete_resource.
 *
 * @param resource Resource to be deleted
 */
typedef void (*oc_delete_resource_cb_t)(oc_resource_t *resource);

/**
 * Sets the callback that gets invoked by oc_delayed_delete_resource
 * before each resource is deleted.
 *
 * @param callback The callback to set or NULL to unset it. If the function
 *                 is invoked a second time, then the previously set callback is
 *                 simply replaced.
 */
void oc_set_on_delayed_delete_resource_cb(oc_delete_resource_cb_t callback);

#endif /* OC_CLOUD */

#ifdef OC_RES_BATCH_SUPPORT

/**
 * The OCF URI is specified in the following form:
 * ocf://<authority>/<path>?<query>
 * https://openconnectivity.org/specs/OCF_Core_Specification_v2.2.5.pdf
 * section 6.2.2:
 */
#define OC_MAX_OCF_URI_SIZE (OC_UUID_LEN + 6 + 256)

void oc_discovery_create_batch_for_resource(CborEncoder *links_array,
                                            oc_resource_t *resource,
                                            const oc_endpoint_t *endpoint);

#endif /* OC_RES_BATCH_SUPPORT */

typedef bool (*oc_process_baseline_interface_filter_fn_t)(
  const char *property_name, void *data);

/**
 * @brief Encode baseline resource properties to global encoder
 *
 * @param resource resource to encode (cannot be NULL)
 * @param filter property filtering function (if NULL then all properties are
 * accepted)
 * @param filter_data custom user data sent to the property filtering function
 */
void oc_process_baseline_interface_with_filter(
  const oc_resource_t *resource,
  oc_process_baseline_interface_filter_fn_t filter, void *filter_data);

/** Setup response for the request */
void oc_send_response_internal(oc_request_t *request, oc_status_t response_code,
                               oc_content_format_t content_format,
                               size_t response_length, bool trigger_cb);

#endif /* OC_SERVER_API_INTERNAL_H */
