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

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_INTROSPECTION_WK_URI "/oc/wk/introspection"
#define OC_INTROSPECTION_WK_RT "oic.wk.introspection"
#define OC_INTROSPECTION_WK_IF_MASK (OC_IF_R | OC_IF_BASELINE)
#define OC_INTROSPECTION_WK_DEFAULT_IF (OC_IF_R)

#define OC_INTROSPECTION_DATA_URI "/oc/introspection"
#define OC_INTROSPECTION_DATA_RT "x.org.openconnectivity.oic.introspection.data"
#define OC_INTROSPECTION_DATA_IF_MASK (OC_IF_BASELINE)
#define OC_INTROSPECTION_DATA_DEFAULT_IF (OC_IF_BASELINE)

/**
 * @brief Creation of the oic.wk.introspection resource.
 *
 * @param device index of the device to which the resource is to be created
 */
void oc_create_introspection_resource(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_INTROSPECTION_INTERNAL_H */
