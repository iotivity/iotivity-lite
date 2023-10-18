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

#ifndef OC_PORT_STORAGE_INTERNAL_H
#define OC_PORT_STORAGE_INTERNAL_H

#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief disable the storage
 * @return 0 on success
 * @return <0 on failure
 */
int oc_storage_reset(void);

/**
 * @brief get the storage path
 *
 * @param[out] buffer buffer to store the path
 * @param buffer_size size of the buffer
 *
 * @return true if storage path is set
 * @return false otherwise
 */
bool oc_storage_path(char *buffer, size_t buffer_size);

/**
 * @brief get size (in bytes) of the data written to store
 *
 * @param store the path to be read (cannot be NULL)
 * @return <0 on failure
 * @return >=0 size of the store
 */
long oc_storage_size(const char *store) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_STORAGE_INTERNAL_H */
