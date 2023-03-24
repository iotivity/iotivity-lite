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

#ifndef OC_STORAGE_INTERNAL_H
#define OC_STORAGE_INTERNAL_H

#include "oc_config.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OC_DYNAMIC_ALLOCATION
#define OC_APP_DATA_STORAGE_BUFFER
#ifndef OC_APP_DATA_BUFFER_SIZE
#define OC_APP_DATA_BUFFER_SIZE OC_MAX_APP_DATA_SIZE
#endif /* OC_APP_DATA_BUFFER_SIZE */
#endif /* !OC_DYNAMIC_ALLOCATION */

#define OC_STORAGE_SVR_TAG_MAX (32)

typedef struct oc_storage_buffer_t
{
  uint8_t *buffer;
  size_t size;
} oc_storage_buffer_t;

/**
 * @brief Get buffer to store encoded data before saving them to storage.
 *
 * @param size size of the buffer (only used when compiled with
 * OC_DYNAMIC_ALLOCATION, otherwise a static buffer is returned)
 * @return new buffer
 */
oc_storage_buffer_t oc_storage_get_buffer(size_t size);

/**
 * @brief Deallocated a previously allocated buffer.
 *
 * @param sb buffer to deallocate
 */
void oc_storage_free_buffer(oc_storage_buffer_t sb);

/**
 * @brief Generate a name in the format "${name}_${device_index}".
 *
 * The maximal length of the name is OC_STORAGE_SVR_TAG_MAX (including the
 * NULL-terminator).
 * If the tag is longer than the output buffer or OC_STORAGE_SVR_TAG_MAX then
 * the function will attempt to truncate the tag. But the buffer must be large
 * enough to hold at least one char of the tag name, the '_' delimiter and the
 * encoded device index.
 *
 * @param name tag name (cannot be NULL)
 * @param device_index device index
 * @param[out] svr_tag output buffer (cannot be NULL)
 * @param svr_tag_size size of the output buffer
 * @return >= 0 number of written bytes
 * @return -1 on error
 */
int oc_storage_gen_svr_tag(const char *name, size_t device_index, char *svr_tag,
                           size_t svr_tag_size);

typedef int (*oc_decode_from_storage_fn_t)(const oc_rep_t *rep, size_t device,
                                           void *data);

/**
 * @brief Load data of resource from storage.
 *
 * @param name tag name used for given resource (cannot be NULL)
 * @param device device index
 * @param decode callback function invoked on successful load from storage,
 * used to decode data to a runtime structure representing the resource (cannot
 * be NULL)
 * @return >= 0 number of read bytes
 * @return -1 on error
 */
long oc_storage_load_resource(const char *name, size_t device,
                              oc_decode_from_storage_fn_t decode,
                              void *decode_data);

typedef int (*oc_encode_to_storage_fn_t)(size_t device, void *data);

/**
 * @brief Save data of resource to storage.
 *
 * @param name tag name used for given resource (cannot be NULL)
 * @param device device index
 * @param encode callback function invoked before saving the global encoder to
 * storage (cannot be NULL)
 * @return >= 0 number of written bytes
 * @return -1 on error
 */
long oc_storage_save_resource(const char *name, size_t device,
                              oc_encode_to_storage_fn_t encode,
                              void *encode_data);

#ifdef __cplusplus
}
#endif

#endif /* OC_STORAGE_INTERNAL_H */
