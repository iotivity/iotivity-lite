/****************************************************************************
 *
 * Copyright (c) 2017 Intel Corporation
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
/**
  @file
*/
#ifndef OC_BUFFER_SETTINGS_H
#define OC_BUFFER_SETTINGS_H

#include "oc_export.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief sets the size of the MTU to be used
 *
 * @param mtu_size size in bytes
 * @return int 0-success
 */
OC_API
int oc_set_mtu_size(size_t mtu_size);

/**
 * @brief retrieve the currently used MTU size
 *
 * @return long the MTU size in bytes
 */
OC_API
long oc_get_mtu_size(void);

/**
 * @brief set max application data size (e.g. buffer size of the messages)
 *
 * @param size size in bytes
 */
OC_API
void oc_set_max_app_data_size(size_t size);

/**
 * @brief retrieve the max application data size
 *
 * @return long size in bytes
 */
OC_API
long oc_get_max_app_data_size(void);

/**
 * @brief set min application data size (e.g. initialization buffer size of the
 * messages)
 *
 * @param size size in bytes
 */
OC_API
void oc_set_min_app_data_size(size_t size);

/**
 * @brief retrieve the min application data size
 *
 * @return long size in bytes
 */
OC_API
long oc_get_min_app_data_size(void);

/**
 * @brief retrieve the block size
 *
 * @return long the block size in bytes
 */
OC_API
long oc_get_block_size(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_BUFFER_SETTINGS_H */
