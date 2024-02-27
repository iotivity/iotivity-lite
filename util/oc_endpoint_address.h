/******************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
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

#ifndef OC_ENDPOINT_ADDRESS_H
#define OC_ENDPOINT_ADDRESS_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST

#include "oc_export.h"
#include "oc_helpers.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum length of the endpoint address URI string. */
#ifdef OC_STORAGE
#define OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH STRING_ARRAY_ITEM_MAX_LEN
#else /* !OC_STORAGE */
#define OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH OC_MAX_STRING_LENGTH
#endif /* OC_STORAGE */

/// @brief Forward declaration of oc_endpoint_address_t, the structure contains
/// URI and metadata.
typedef struct oc_endpoint_address_t oc_endpoint_address_t;

/** @brief Get the address URI. */
OC_API
const oc_string_t *oc_endpoint_address_uri(const oc_endpoint_address_t *ea)
  OC_NONNULL();

/**
 * @brief Set the UUID in the address metadata.
 *
 * @note Currently the metadata is implemented as a union, so only one of the
 * `uuid` or `name` members is set at a time. The type of the metadata is
 * determined by the last setter called. The getter for invalid metadata type
 * will return NULL.
 */
OC_API
void oc_endpoint_address_set_uuid(oc_endpoint_address_t *ea, oc_uuid_t uuid)
  OC_NONNULL();

/** @brief Get the UUID from the address metadata. */
OC_API
const oc_uuid_t *oc_endpoint_address_uuid(const oc_endpoint_address_t *ea)
  OC_NONNULL();

/** @brief Set the name in the address metadata. */
OC_API
void oc_endpoint_address_set_name(oc_endpoint_address_t *ea, const char *name,
                                  size_t name_len) OC_NONNULL(1);

/** @brief Get the name from the address metadata. */
OC_API
const oc_string_t *oc_endpoint_address_name(const oc_endpoint_address_t *ea)
  OC_NONNULL();

/**
 * @brief Callback invoked for each iterated endpoint address.
 *
 * @param ea endpoint address with metadata to process
 * @param data custom user data provided to the iteration function
 * @return true to continue iteration
 * @return false to stop iteration
 */
typedef bool (*oc_endpoint_addresses_iterate_fn_t)(oc_endpoint_address_t *ea,
                                                   void *data) OC_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST */

#endif /* OC_ENDPOINT_ADDRESS_H */
