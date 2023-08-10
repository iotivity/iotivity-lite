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
#include "util/oc_compiler.h"
#include <stdbool.h>
#include <stdint.h>

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
bool oc_resource_is_initialized(const oc_resource_t *resource) OC_NONNULL();

/**
 * @brief Callback invoked for each resource iterated by oc_resources_iterate.
 *
 * @param resource resource to process
 * @param data custom user data provided to oc_resources_iterate
 * @return true to continue iteration
 * @return false to stop iteration
 */
typedef bool (*oc_resource_iterate_fn_t)(oc_resource_t *resource, void *data);

/**
 * @brief Iterate over all resources of given device and invoke given callback.
 *
 * @param device device to iterate
 * @param includePlatform true to include platform resources
 * @param fn callback invoked for each resource (cannot be NULL)
 * @param data custom user data passed to \p fn
 *
 * @note if \p fn returns false then iteration is stopped immediately and the
 * remaining resources are not iterated
 */
void oc_resources_iterate(size_t device, bool includePlatform,
                          oc_resource_iterate_fn_t fn, void *data)
  OC_NONNULL(3);

#ifdef __cplusplus
}
#endif

#endif /* OC_RESOURCE_INTERNAL_H */
