/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifndef OC_RESOURCE_INTERNAL_H
#define OC_RESOURCE_INTERNAL_H

#include "oc_ri.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check if given resource is initialized.
 *
 * @param resource resource to check (cannot be NULL)
 * @return true resource is initialized
 * @return false resource is uninitialized
 */
bool oc_resource_is_initialized(const oc_resource_t *resource);

#ifdef __cplusplus
}
#endif

#endif /* OC_RESOURCE_INTERNAL_H */
