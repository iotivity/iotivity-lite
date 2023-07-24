/****************************************************************************
 *
 * Copyright (c) 2017-2019 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd.
 * Copyright (c) 2021 Cable Televesion Laboratories Ltd.
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

#ifndef OC_PYTHON_INTERNAL_H
#define OC_PYTHON_INTERNAL_H

#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

bool encode_resource_discovery_payload(char *buffer, size_t buffer_size,
                                       const char *uri, const char *types,
                                       oc_interface_mask_t iface_mask)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_PYTHON_INTERNAL_H */
