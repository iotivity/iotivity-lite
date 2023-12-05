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

#ifndef OC_RESOURCE_INTERNAL_H
#define OC_RESOURCE_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check if given resource is initialized.
 *
 * @param resource resource to check (cannot be NULL)
 * @return true resource is initialized
 * @return false resource is uninitialized
 */
bool oc_resource_is_initialized(const oc_resource_t *resource) OC_NONNULL();

/**
 * @brief Check if given URI matches the cannonical URI of given resource.
 *
 * @param canonicalURI canonical URI (with leading '/') to match against
 * @param uri URI to match
 * @return true resource matches given URI
 * @return false resource does not match given URI
 */
bool oc_resource_match_uri(oc_string_view_t canonicalURI, oc_string_view_t uri);

/**
 * @brief Check if resource supports given interface.
 *
 * @param resource resource to check (cannot be NULL)
 * @param iface interface to check
 * @return true resource supports given interface
 * @return false resource does not support given interface
 */
bool oc_resource_supports_interface(const oc_resource_t *resource,
                                    oc_interface_mask_t iface) OC_NONNULL();

/**
 * @brief Get resource request handler for given method.
 *
 * @param resource resource to get request handler for (cannot be NULL)
 * @param method method to get
 * @param[out] handler request handler for given method (cannot be NULL)
 * @return true request handler found
 * @return false request handler not found
 */
bool oc_resource_get_method_handler(const oc_resource_t *resource,
                                    oc_method_t method,
                                    oc_request_handler_t *handler)
  OC_NONNULL(1);

/**
 * @brief Callback invoked for each resource iterated by oc_resources_iterate.
 *
 * @param resource resource to process
 * @param data custom user data provided to oc_resources_iterate
 * @return true to continue iteration
 * @return false to stop iteration
 */
typedef bool (*oc_resource_iterate_fn_t)(oc_resource_t *resource, void *data);

/**
 * @brief Iterate over all resources of given device and invoke given callback.
 *
 * @param device device to iterate
 * @param includePlatform true to include core platform resources
 * @param includeCore true to include core (non-platform) resources
 * @param includeDynamic true to include dynamic resources
 * @param includeCollections true to include collection resources
 * @param fn callback invoked for each resource (cannot be NULL)
 * @param data custom user data passed to \p fn
 *
 * @note if \p fn returns false then iteration is stopped immediately and the
 * remaining resources are not iterated
 */
void oc_resources_iterate(size_t device, bool includePlatform, bool includeCore,
                          bool includeDynamic, bool includeCollections,
                          oc_resource_iterate_fn_t fn, void *data)
  OC_NONNULL(6);

/** @brief Iterate over all platform resources and invoke given callback. */
void oc_resources_iterate_platform(oc_resource_iterate_fn_t fn, void *data)
  OC_NONNULL(1);

/** @brief Iterate over all core resources and invoke given callback. */
void oc_resources_iterate_core(size_t device, oc_resource_iterate_fn_t fn,
                               void *data) OC_NONNULL(2);

#ifdef OC_SERVER

/** @brief Iterate over all dynamic resources and invoke given callback. */
void oc_resources_iterate_dynamic(size_t device, oc_resource_iterate_fn_t fn,
                                  void *data) OC_NONNULL(2);

#ifdef OC_COLLECTIONS

/** @brief Iterate over all collection resources and invoke given callback. */
void oc_resources_iterate_collections(size_t device,
                                      oc_resource_iterate_fn_t fn, void *data)
  OC_NONNULL(2);

#endif /* OC_COLLECTIONS */

#endif /* OC_SERVER */

/** Check if the tag_pos_rel parts are empty */
bool oc_tag_pos_rel_is_empty(double pos1, double pos2, double pos3);

typedef bool (*oc_resource_properties_filter_fn_t)(
  oc_string_view_t property_name, void *data);

/**
 * @brief Encode baseline resource properties to encoder
 *
 * @param encoder encoder to encode properties to (cannot be NULL)
 * @param resource resource to encode (cannot be NULL)
 * @param filter property filtering function (if NULL then all properties are
 * accepted)
 * @param filter_data custom user data sent to the property filtering function
 */
void oc_resource_encode_baseline_properties(
  CborEncoder *encoder, const oc_resource_t *resource,
  oc_resource_properties_filter_fn_t filter, void *filter_data)
  OC_NONNULL(1, 2);

/** @brief Encode tag-pos-desc, tag-func-desc, tag-locn and tag-pos-rel resource
 * properties to encoder */
void oc_resource_encode_tag_properties(CborEncoder *object,
                                       const oc_resource_t *resource)
  OC_NONNULL();

/** @brief Retrieve a core, application or collection resource with given URI */
oc_resource_t *oc_resource_get_by_uri(const char *uri, size_t uri_len,
                                      size_t device) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_RESOURCE_INTERNAL_H */
