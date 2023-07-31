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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize secure vertical resources.
 */
void oc_sec_svr_create(void);

/*
 * modifiedbyme <2023/7/28> add func proto : oc_sec_svr_create_new_device()
 */
#ifdef OC_HAS_FEATURE_BRIDGE
/**
 * @brief add SVR for the Device which is added dynamically.
 *        new Device should be added to `g_oc_device_info[]`
 *        before calling this function.
 */
void oc_sec_svr_create_new_device(void);
#endif /* OC_HAS_FEATURE_BRIDGE */


/**
 * @brief Deinitialize secure vertical resources;
 */
void oc_sec_svr_free(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_SVR_INTERNAL_H */
