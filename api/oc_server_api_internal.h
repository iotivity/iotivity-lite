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

#ifdef OC_CLOUD

#include "oc_api.h"

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
                                            oc_endpoint_t *endpoint);
#endif /* OC_RES_BATCH_SUPPORT */

#endif /* OC_SERVER_API_INTERNAL_H */
