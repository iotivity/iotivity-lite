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

#ifndef OC_LINK_H
#define OC_LINK_H

#include "oc_export.h"
#include "oc_ri.h"
#include "util/oc_list.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_link_s oc_link_t;

/**
 * Creates a new link for collections with the specified resource.
 *
 * @param[in] resource Resource to set in the link. The resource is not copied.
 *                     Must not be NULL
 *
 * @return The created link or NULL if out of memory or resource is NULL.
 *
 * @see oc_delete_link
 * @see oc_collection_add_link
 * @see oc_new_resource
 */
OC_API
oc_link_t *oc_new_link(oc_resource_t *resource) OC_NONNULL();

/**
 * Deletes the link.
 *
 * @note The function neither removes the resource set on this link  nor does it
 *       remove it from any collection.
 *
 * @param[in,out] link The link to delete. The function does nothing, if the
 *                     parameter is NULL
 */
OC_API
void oc_delete_link(oc_link_t *link);

/**
 * Adds a relation to the link.
 *
 * @param[in,out] link Link to add the relation to. Must not be NULL
 * @param[in] rel Relation to add. Must not be NULL and cannot be longer than
 * STRING_ARRAY_ITEM_MAX_LEN
 *
 * @note maximal number of relations on a link is 3, adding of more relations
 * will fail.
 *
 * @return true if the relation was added, false otherwise
 */
OC_API
bool oc_link_add_rel(oc_link_t *link, const char *rel) OC_NONNULL();

/**
 * @brief Clears all relations from the link.
 *
 * @param[in,out] link Link on which to clear all relation to. Must not be NULL
 */
OC_API
void oc_link_clear_rels(oc_link_t *link) OC_NONNULL();

/**
 * Adds a link parameter with specified key and value.
 *
 * @param[in,out] link Link to which to add a link parameter. Must not be NULL
 * @param[in] key Key to identify the link parameter. Must not be NULL
 * @param[in] value Link parameter value. Must not be NULL
 *
 * @return true if the link parameter was added, false otherwise
 */
OC_API
bool oc_link_add_link_param(oc_link_t *link, const char *key, const char *value)
  OC_NONNULL();

/**
 * @brief Clears all link parameters from the link.
 *
 * @param[in,out] link Link on which to clear all link parameters. Must not be
 * NULL
 */
OC_API
void oc_link_clear_link_params(oc_link_t *link) OC_NONNULL();

/**
 * @brief Set link interface mask.
 *
 * @param link link on which to set interfaces (cannot be NULL)
 * @param new_interfaces interface mask
 */
OC_API
void oc_link_set_interfaces(oc_link_t *link, oc_interface_mask_t new_interfaces)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_LINK_H */
