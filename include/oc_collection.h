/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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
#ifndef OC_COLLECTION_H
#define OC_COLLECTION_H

#include "oc_link.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup doc_module_tag_collections Collection Support
 * Optional group of functions to support OCF compliant collections.
 * @{
 */

#ifdef OC_COLLECTIONS
/**
 * Creates a new empty collection.
 *
 * The collection is created with interfaces `OC_IF_BASELINE`,
 * `OC_IF_LL` (also default) and `OC_IF_B`. Initially it is neither discoverable
 * nor observable.
 *
 * The function only allocates the collection. Use oc_add_collection() after the
 * setup of the collection is complete.
 *
 * @param[in] name name of the collection
 * @param[in] uri Unique URI of this collection. Must not be NULL.
 * @param[in] num_resource_types Number of resources the caller will bind with
                      this resource (e.g. by invoking
                      `oc_resource_bind_resource_type(col, OIC_WK_COLLECTION)`).
                      Must be 1 or higher.
 * @param[in] device The internal device that should carry this collection.
 *                   This is typically 0.
 *
 * @return A pointer to the new collection (actually `oc_collection_t *`)
 *  or NULL if out of memory.
 *
 * @see oc_add_collection
 * @see oc_collection_add_link
 */
OC_API
oc_resource_t *oc_new_collection(const char *name, const char *uri,
                                 uint8_t num_resource_types, size_t device)
  OC_NONNULL(2);

/**
 * Deletes the specified collection.
 *
 * The function removes the collection from the internal list of collections
 * and releases all direct resources and links associated with this collection.
 *
 * @note The function does not delete the resources set in the links. The caller
 *       needs to do this on her/his own in case these are no longer required.
 *
 * @param[in,out] collection The pointer to the collection to delete. If this is
 *                           NULL, the function does nothing
 *
 * @see oc_collection_get_links
 * @see oc_delete_link
 */
OC_API
void oc_delete_collection(oc_resource_t *collection);

/**
 * Adds the link to the collection.
 *
 * @param[in,out] collection Collection to add the link to. Must not be NULL
 * @param[in] link Link to add to the collection. The link is not copied.
 *                 Must not be NULL. Must not be added again to this or a
 *                 different collection or a list corruption will occur. To
 *                 re-add it, remove the link first.
 *
 * @see oc_new_link
 * @see oc_collection_remove_link
 */
OC_API
void oc_collection_add_link(oc_resource_t *collection, oc_link_t *link)
  OC_NONNULL();

/**
 * Removes a link from the collection.
 *
 * @param[in,out] collection Collection to remove the link from. Does nothing
 *                           if this is NULL
 * @param[in] link The link to remove. Does nothing if this is NULL or not
 *                 part of the collection. The link and its resource are not
 *                 freed.
 */
OC_API
void oc_collection_remove_link(oc_resource_t *collection,
                               const oc_link_t *link);

/**
 * Returns the list of links belonging to this collection.
 *
 * @param[in] collection Collection to get the links from.
 *
 * @return All links of this collection. The links are not copied. Returns
 *         NULL if the collection is NULL or contains no links.
 *
 * @see oc_collection_add_link
 */
OC_API
oc_link_t *oc_collection_get_links(oc_resource_t *collection);

/**
 * Adds a collection to the list of collections.
 *
 * If the caller makes the collection discoverable, then it will be included in
 * the collection discovery once it has been added with this function.
 *
 * @param[in] collection Collection to add to the list of collections. Must not
 *                       be NULL. Must not be added twice or a list corruption
 *                       will occur. The collection is not copied.
 *
 * @see oc_resource_set_discoverable
 * @see oc_new_collection
 */
OC_API
void oc_add_collection(oc_resource_t *collection) OC_NONNULL();

/**
 * Gets all known collections.
 *
 * @return All collections that have been added via oc_add_collection(). The
 *         collections are not copied. Returns NULL if there are no collections.
 *         Collections created only via oc_new_collection() but not added will
 *         not be returned by this function.
 */
OC_API
oc_resource_t *oc_collection_get_collections(void);

/**
 * Add a supported Resource Type to a collection
 *
 * This will become the "rts" property of the collection. The "rts" property is
 * an array of Resource Types that are supported within an array of Links
 * exposed by the collection.
 *
 * @note adding a supported Resource Type multiple times will fail
 *
 * @param[in] collection the collection the the Resource Type will be added to
 * (cannot be NULL)
 * @param[in] rt the supported Resource Type being added to the collection
 * (cannot be NULL)
 *
 * @return true on success
 */
OC_API
bool oc_collection_add_supported_rt(oc_resource_t *collection, const char *rt)
  OC_NONNULL();

/**
 * Add a mandatory Resource Type to a collection
 *
 * This will be come the "rts-m" property of the collection. The "rts-m"
 * property is an array of Resource Types that are mandatory to be exposed with
 * in an array of Links exposed by the collection.
 *
 * @note adding a mandatory Resource Type multiple times will fail
 *
 * @param[in] collection the collection the the Resource Type will be added to
 * (cannot be NULL)
 * @param[in] rt the mandatory Resource Type being added to the collection
 * (cannot be NULL)
 *
 * @return true on success
 */
OC_API
bool oc_collection_add_mandatory_rt(oc_resource_t *collection, const char *rt)
  OC_NONNULL();

/**
 * @brief sets the callback properties for set properties and get properties
 *
 * @param resource the resource for the callback data
 * @param get_properties callback function for retrieving the properties
 * @param get_props_user_data the user data for the get_properties callback
 * function
 * @param set_properties callback function for setting the properties
 * @param set_props_user_data the user data for the set_properties callback
 * function
 */
OC_API
void oc_resource_set_properties_cbs(oc_resource_t *resource,
                                    oc_get_properties_cb_t get_properties,
                                    void *get_props_user_data,
                                    oc_set_properties_cb_t set_properties,
                                    void *set_props_user_data);

/** @brief Check if resource is a global collection */
OC_API
bool oc_check_if_collection(const oc_resource_t *resource);

/**
 * @brief Find a collection in the global collection by its URI.
 *
 * @param uri_path the URI path of the collection (with or without the leading
 * slash)
 * @param uri_path_len the length of the URI path
 * @param device device index
 *
 * @return the collection if found
 * @return NULL otherwise
 */
OC_API
oc_collection_t *oc_get_collection_by_uri(const char *uri_path,
                                          size_t uri_path_len, size_t device)
  OC_NONNULL();

/**
 * @brief Get a link from a collection by its URI.
 *
 * @param collection collection to search
 * @param uri_path the URI path of the link (with or without the leading slash)
 * @param uri_path_len the length of the URI path
 * @return oc_link_t* the link if found
 * @return NULL otherwise
 */
OC_API
oc_link_t *oc_get_link_by_uri(oc_collection_t *collection, const char *uri_path,
                              size_t uri_path_len);

#ifdef OC_COLLECTIONS_IF_CREATE
/**
 * Callback invoked to retrieve an resource
 */
typedef oc_resource_t *(*oc_resource_get_instance_t)(const char *,
                                                     const oc_string_array_t *,
                                                     oc_resource_properties_t,
                                                     oc_interface_mask_t,
                                                     size_t);

/**
 * Callback invoked to delete an resource
 *
 */
typedef void (*oc_resource_free_instance_t)(oc_resource_t *);

/**
 * @brief adds the resource type factory
 *
 * @param rt the resource type
 * @param get_instance creates the instance of the resource type
 * @param free_instance sets callback to free the created instance of the
 * resource tupe
 * @return true
 * @return false
 */
OC_API
bool oc_collections_add_rt_factory(const char *rt,
                                   oc_resource_get_instance_t get_instance,
                                   oc_resource_free_instance_t free_instance);

#endif    /* OC_COLLECTIONS_IF_CREATE */
#endif    /* OC_COLLECTIONS */
/** @} */ // end of doc_module_tag_collections

#ifdef __cplusplus
}
#endif

#endif /* OC_COLLECTION_H */
