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

#ifndef OC_INTROSPECTION_INTERNAL_H
#define OC_INTROSPECTION_INTERNAL_H

#include "oc_endpoint.h"
#include "util/oc_compiler.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_INTROSPECTION_WK_URI "/oc/wk/introspection"
#define OC_INTROSPECTION_WK_RT "oic.wk.introspection"
#define OC_INTROSPECTION_WK_IF_MASK (OC_IF_R | OC_IF_BASELINE)
#define OC_INTROSPECTION_WK_DEFAULT_IF (OC_IF_R)
#define OC_INTROSPECTION_WK_STORE_NAME "IDD"

#define OC_INTROSPECTION_DATA_URI "/oc/introspection"
#define OC_INTROSPECTION_DATA_RT "x.org.openconnectivity.oic.introspection.data"
#define OC_INTROSPECTION_DATA_IF_MASK (OC_IF_BASELINE)
#define OC_INTROSPECTION_DATA_DEFAULT_IF (OC_IF_BASELINE)

/**
 * @brief Get the introspection data for the device
 *
 * @param device index of the device to get the introspection data from
 * @param buffer buffer to store the introspection data
 * @param buffer_size size of the buffer
 * @return long size of the introspection data
 * @return -1 on error
 *
 * @note if buffer is NULL, the function will return the size of the
 * introspection data
 */
long oc_introspection_get_data(size_t device, uint8_t *buffer,
                               size_t buffer_size);

/**
 * @brief Find endpoint from given device with the given transport flags and
 * interface index and generate uri of the introspection resource on the
 * endpoint.
 *
 * @param device device index
 * @param interface_index interface index (-1 to ignore interface)
 * @param flags transport flags of the endpoint
 * @param[out] uri variable to store the uri (cannot be NULL)
 */
bool oc_introspection_wk_get_uri(size_t device, int interface_index,
                                 transport_flags flags, oc_string_t *uri)
  OC_NONNULL();

/**
 * @brief Create the oic.wk.introspection and
 * x.org.openconnectivity.oic.introspection.data resources
 *
 * @param device index of the device to which the resources will be added
 */
void oc_create_introspection_resource(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_INTROSPECTION_INTERNAL_H */
