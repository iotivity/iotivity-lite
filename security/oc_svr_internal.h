/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

#ifndef OC_SVR_INTERNAL_H
#define OC_SVR_INTERNAL_H

#include "util/oc_features.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize secure vertical resources.
 */
void oc_sec_svr_create(void);

#ifdef OC_HAS_FEATURE_DEVICE_ADD

/**
 * @brief add SVR for the Device which is added dynamically.
 *        new Device should be added to `g_oc_device_info[]`
 *        before calling this function.
 *
 * @param device_index index of `g_oc_device_info[]` where new Device is
 *            stored
 * @param needs_realloc indicates whether reallocation of memory for SVR is
 *            needed or not
 */
void oc_sec_svr_create_new_device(size_t device_index, bool needs_realloc);

/**
 * @brief update SVR with stored values,
 *        if there is no store data, initialize with default value.
 *
 * @param device_index index of Device stored in `g_oc_device_info[]`
 */
void oc_sec_svr_init_new_device(size_t device_index);

#endif /* OC_HAS_FEATURE_DEVICE_ADD */

/**
 * @brief Deinitialize secure vertical resources;
 */
void oc_sec_svr_free(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_SVR_INTERNAL_H */
