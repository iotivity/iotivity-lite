
/******************************************************************
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
 ******************************************************************/

#ifndef OC_COLLECTION_INTERNAL_H
#define OC_COLLECTION_INTERNAL_H

#include "oc_config.h"

#ifdef OC_COLLECTIONS

#include "oc_collection.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"
#include "util/oc_list.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_rt_t
{
  struct oc_rt_t *next;
  oc_string_t rt;
} oc_rt_t;

enum {
  OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX =
    1, ///< maximal number allowed of statically allocated resource types
};

struct oc_collection_s
{
  struct oc_resource_s res;
  OC_LIST_STRUCT(mandatory_rts);
  OC_LIST_STRUCT(supported_rts);
  OC_LIST_STRUCT(links); ///< list of links ordered by href length and value
};

/** @brief Allocate a new collection */
oc_collection_t *oc_collection_alloc(void);

/** @brief Deallocate a collection */
void oc_collection_free(oc_collection_t *collection);

/** @brief Add collection to global list
 *
 * Cannot add the same collection twice or cannot add the same URI twice to a
 * device.
 *
 * @return true if collection was added
 * @return false otherwise
 */
bool oc_collection_add(oc_collection_t *collection) OC_NONNULL();

/** @brief Get head of the global list of collections */
oc_collection_t *oc_collection_get_all(void);

/** @brief Free all collections from the global list */
void oc_collections_free_all(void);

/** @brief Iterate the global list of colletions and return the next collection
 * linked with the given resource */
oc_collection_t *oc_get_next_collection_with_link(const oc_resource_t *resource,
                                                  oc_collection_t *start)
  OC_NONNULL(1);

/** @brief Process CoAP request on a collection. */
OC_NO_DISCARD_RETURN
bool oc_handle_collection_request(oc_method_t method, oc_request_t *request,
                                  oc_interface_mask_t iface_mask,
                                  const oc_resource_t *notify_resource)
  OC_NONNULL(2);

/**
 * @brief Remove link from a collection and notify observers.
 *
 * @param collection the collection to remove the link from
 * @param link the link to remove
 * @param notify whether to notify observers
 * @param batchDispatch whether to schedule dispatch of batch notifications
 * @return true link was removed
 * @return false link was not removed
 */
bool oc_collection_remove_link_and_notify(oc_resource_t *collection,
                                          const oc_link_t *link, bool notify,
                                          bool batchDispatch);

#ifdef OC_COLLECTIONS_IF_CREATE

/** @brief Free all resource type factories and resources that have been created
 * by them. */
void oc_collections_free_rt_factories(void);

#endif /* OC_COLLECTIONS_IF_CREATE */

#ifdef OC_HAS_FEATURE_ETAG

/**
 * @brief Get batch etag for a collection.
 *
 * Batch etag is calculated as the maximum of the collection's etag and the
 * etags of all resources linked to the collection.
 *
 * @param collection collection to get batch etag for (cannot be NULL)
 * @return uint64_t batch etag
 */
uint64_t oc_collection_get_batch_etag(const oc_collection_t *collection)
  OC_NONNULL();

#endif /* OC_HAS_FEATURE_ETAG */

#ifdef __cplusplus
}
#endif

#endif /* OC_COLLECTIONS */

#endif /* OC_COLLECTION_INTERNAL_H */
