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

#ifndef OC_ETAG_H
#define OC_ETAG_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ETAG

#include "oc_config.h"
#include "oc_export.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief update the ETag value for the resource based on the global ETag value
 *
 * @param resource resource to update (cannot be NULL)
 */
OC_API
void oc_resource_update_etag(oc_resource_t *resource) OC_NONNULL();

#ifdef OC_STORAGE

/**
 * @brief Save the ETag values to persistent storage.
 *
 * ETags are saved to per device persistent stores as URI-etag pairs:
 *
 * Example:
 * {
 *   "/oic/p": {
 *     "etag": 42,
 *   },
 *   "/oic/con": {
 *      "etag": 1337,
 *   }
 *   "/oic/d": {
 *     "etag": 1234567,
 *   },
 *   ...
 * }
 *
 * @return true all ETag values were saved to persistent storage
 * @return false otherwise
 */
OC_API
bool oc_etag_dump(void);

/**
 * @brief Load the ETag values from persistent storage and clear the storage.
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
 * @return true if loading of ETag and clearing ETag storage was successful
 * @return false otherwise
 */
OC_API
bool oc_etag_load_and_clear(void);

#endif /* OC_STORAGE */

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_ETAG */

#endif /* OC_ETAG_H */
