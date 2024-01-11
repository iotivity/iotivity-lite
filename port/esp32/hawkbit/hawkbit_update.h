/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#ifndef HAWKBIT_UPDATE_H
#define HAWKBIT_UPDATE_H

#include "api/oc_helpers_internal.h"
#include "oc_helpers.h"
#include "util/oc_compiler.h"

#include <esp_image_format.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Metadata about an update saved on an OTA partition
 */
typedef struct
{
  oc_string_t deployment_id;
  oc_string_t version;
  uint8_t
    sha256[ESP_IMAGE_HASH_LEN]; // sha256 hash of the file provided by hawkbit
  uint8_t partition_sha256[ESP_IMAGE_HASH_LEN]; // sha256 hash of the partition
                                                // with update obtained by
                                                // esp_partition_get_sha256
} hawkbit_async_update_t;

/** @brief Create instance with given data */
hawkbit_async_update_t hawkbit_update_create(
  oc_string_view_t deployment_id, oc_string_view_t version,
  const uint8_t *sha256, size_t sha256_size, const uint8_t *partition_sha256,
  size_t partition_sha256_size) OC_NONNULL();

/** @brief Deallocate instance data */
void hawkbit_update_free(hawkbit_async_update_t *update);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_UPDATE_H */
