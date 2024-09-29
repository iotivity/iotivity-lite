/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
/**
  @file
*/
#ifndef OC_PORT_STORAGE_H
#define OC_PORT_STORAGE_H

#include "oc_export.h"
#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief open the storage
 *
 * @param store the storage path
 * @return 0 on success
 * @return <0 on failure
 */
OC_API
int oc_storage_config(const char *store);

/**
 * @brief read from the storage
 *
 * @param store the path to be read (cannot be NULL)
 * @param buf the buffer to store the contents (cannot be NULL)
 * @param size amount of bytes to read
 * @return long amount of bytes read
 */
OC_API
long oc_storage_read(const char *store, uint8_t *buf, size_t size) OC_NONNULL();

/**
 * @brief write to storage
 *
 * @param store the store (file path, cannot be NULL)
 * @param buf the buffer to write (cannot be NULL)
 * @param size the size of the buffer to write
 * @return long >= 0 amount of bytes written on success
 * @return long < 0 on failure
 */
OC_API
long oc_storage_write(const char *store, const uint8_t *buf, size_t size)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_STORAGE_H */
