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

#include "oc_endpoint_internal.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"

#ifdef OC_RES_BATCH_SUPPORT
#include <cbor.h>
#endif /* OC_RES_BATCH_SUPPORT */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Remove callback (if it exists) and schedule it again
void oc_reset_delayed_callback(void *cb_data, oc_trigger_t callback,
                               uint16_t seconds) OC_NONNULL(2);
void oc_reset_delayed_callback_ms(void *cb_data, oc_trigger_t callback,
                                  uint64_t milliseconds) OC_NONNULL(2);

/// Remove scheduled notifications
void oc_notify_clear(const oc_resource_t *resource) OC_NONNULL();

/// Resource has been added, notify relevant modules
void oc_notify_resource_added(oc_resource_t *resource) OC_NONNULL();

/// Resource has been removed, notify relevant modules
void oc_notify_resource_removed(oc_resource_t *resource) OC_NONNULL();

/// Resource has been changed, notify relevant modules
void oc_notify_resource_changed_delayed_ms(oc_resource_t *resource,
                                           uint64_t milliseconds) OC_NONNULL();

#ifdef OC_RES_BATCH_SUPPORT

/**
 * The OCF URI is specified in the following form:
 * ocf://<authority>/<path>?<query>
 * https://openconnectivity.org/specs/OCF_Core_Specification_v2.2.5.pdf
 * section 6.2.2:
 */
#define OC_MAX_OCF_URI_SIZE ((sizeof(OC_SCHEME_OCF) - 1) + OC_UUID_LEN + 256)

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
  oc_process_baseline_interface_filter_fn_t filter, void *filter_data)
  OC_NONNULL(1);

/** Setup response for the request */
bool oc_send_response_internal(oc_request_t *request, oc_status_t response_code,
                               oc_content_format_t content_format,
                               size_t response_length, bool trigger_cb)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_SERVER_API_INTERNAL_H */
