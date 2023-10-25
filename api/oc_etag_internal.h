/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 ***************************************************************************/

#ifndef OC_ETAG_INTERNAL_H
#define OC_ETAG_INTERNAL_H

#include "oc_config.h"
#include "oc_etag.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// ETag value that indicates that the ETag is not set.
#define OC_ETAG_UNINITIALIZED (0)

/** Get the global ETag value without modifying it. */
uint64_t oc_etag_global(void);

/** Set global ETag value */
uint64_t oc_etag_set_global(uint64_t etag);

/**  Get the next global ETag value. */
uint64_t oc_etag_get(void);

/** @brief Set ETag of given resource */
void oc_resource_set_etag(oc_resource_t *resource, uint64_t etag) OC_NONNULL();

/** @brief Get ETag of given resource */
uint64_t oc_resource_get_etag(const oc_resource_t *resource) OC_NONNULL();

#ifdef OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES

#define OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY "incChanges"

/** @brief Check if "incChanges" key is present in the query string */
bool oc_etag_has_incremental_updates_query(const char *query, size_t query_len);

/** @brief Callback invoked for each etag in the incremental updates query
 *
 * @param etag parsed etag value
 * @param user_data user data passed to
 * oc_etag_iterate_incremental_updates_query
 * @return true to continue iteration
 * @return false to stop iteration
 */
typedef bool (*oc_etag_iterate_incremental_updates_fn_t)(uint64_t etag,
                                                         void *user_data);

/**
 * @brief Iterate over etags in the incremental updates query
 *
 * @param query query string
 * @param query_len length of the query string
 * @param etag_fn callback invoked for each etag
 * @param etag_fn_data user data passed to etag_fn
 */
void oc_etag_iterate_incremental_updates_query(
  const char *query, size_t query_len,
  oc_etag_iterate_incremental_updates_fn_t etag_fn, void *etag_fn_data)
  OC_NONNULL(3);

#endif /* OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES */

#ifdef OC_STORAGE

/// per device storage of ETag data of all resources
#define OC_ETAG_STORE_NAME "etag"
/// single storage for ETag data of platform resources
#define OC_ETAG_PLATFORM_STORE_NAME "etag_platform"

/** Truncate all ETag stores. */
bool oc_etag_clear_storage(void);

/**
 * @brief Load the ETag values from persistent storage.
 *
 * The global ETag value and etags of all resources should be updated based on
 * the content of the persistent storage.
 *
 * - Global ETag value is updated to a value based on the maximum value of all
 * ETags from the persistent storage and the current time.
 * - Resources with ETag that are present in the persistent storage have their
 * ETag updated to the value from the persistent storage.
 * - Resources with ETag that are not present in the persistent storage are
 * updated by calling oc_etag_get().
 *
 * @note The function does not exit early in case of an error. For example, if
 * loading of the data from device 0 store fails, the function will attempt to
 * load other stores and the resources of device 0 will be updated by calling
 * oc_etag_get(). The function will return false in this case.
 *
 * @param from_storage_only if true, only the ETag values from persistent
 * storages are set and other resources' ETags are not changed
 *
 * @return true everything was succesfully loaded from persistent storage
 * @return false otherwise
 */
bool oc_etag_load_from_storage(bool from_storage_only);

/** Dump ETags of given device to persisent storage. */
bool oc_etag_dump_for_device(size_t device);

/** Do not dump resource with given URI to storage. */
bool oc_etag_dump_ignore_resource(const char *uri, size_t uri_len) OC_NONNULL();

typedef enum {
  OC_RESOURCE_CRC64_OK = 0, ///< resource has a payload and crc64 is calculated
  OC_RESOURCE_CRC64_NO_PAYLOAD = 1, ///< resource has no payload

  OC_RESOURCE_CRC64_ERROR = -1, ///< error occured
} oc_resource_crc64_status_t;

/** Calculate crc64 checksum for given resource */
oc_resource_crc64_status_t oc_resource_get_crc64(oc_resource_t *resource,
                                                 uint64_t *crc64) OC_NONNULL();

typedef enum {
  OC_RESOURCE_ENCODE_OK = 0,
  OC_RESOURCE_ENCODE_SKIPPED = 1,

  OC_RESOURCE_ENCODE_ERROR = -1,
} oc_resource_encode_status_t;

/** @brief Encode resource ETag
 *
 *  Format:
 *   "${resource-uri}": {
 *     "etag": ${resource->etag}
 *     "crc": ${crc64 checksum of the resource payload}
 *   }
 *
 * @param encoder encoder (cannot be NULL)
 * @param resource resource to encode (cannot be NULL)
 * @return OC_RESOURCE_ENCODE_OK if resource was encoded
 * @return OC_RESOURCE_ENCODE_SKIPPED if resource encoding was skipped
 * @return OC_RESOURCE_ENCODE_ERROR if error occured
 */
oc_resource_encode_status_t oc_etag_encode_resource_etag(
  CborEncoder *encoder, oc_resource_t *resource) OC_NONNULL();

/** Decode resource ETag */
bool oc_etag_decode_resource_etag(oc_resource_t *resource, const oc_rep_t *rep,
                                  uint64_t *etag) OC_NONNULL();

#endif /* OC_STORAGE */

#ifdef OC_SECURITY

/** @brief Reinitialize all ETags on device reset.
 *
 * This function is called when the device is reset. It should reset all ETags.
 *
 * @param device device being reset
 */
void oc_etag_on_reset(size_t device);

#endif /* OC_SECURITY */

#ifdef __cplusplus
}
#endif

#endif /* OC_ETAG_INTERNAL_H */
