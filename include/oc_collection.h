/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_COLLECTION_H
#define OC_COLLECTION_H

/**
  @brief Collection handling API.
  @file
*/

#include "oc_ri.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
  @brief Link forming part of a collection.

  This struct can be used as \link oc_resource_s\endlink.
  @see oc_collection_s
*/
struct oc_link_s
{
  struct oc_link_s *next;
  oc_resource_t *resource;
  oc_string_t ins;
  oc_string_array_t rel;
};

typedef enum {
    OC_CT_COLLECTION = 0,
    OC_CT_SCENE_COLLECTION,
    OC_CT_SCENE_LIST
} oc_collection_type_t;

/**
  @brief Collection.

  If scene support is compiled in, then this also acts
  as scene list and scene collection.
*/
struct oc_collection_s
{
  struct oc_collection_s *next;
  size_t device;
  oc_string_t name;
  oc_string_t uri;
  oc_string_array_t types;
  oc_interface_mask_t interfaces;
  oc_interface_mask_t default_interface;
  oc_resource_properties_t properties;
  oc_request_handler_t get_handler;
  oc_request_handler_t put_handler;
  oc_request_handler_t post_handler;
  oc_request_handler_t delete_handler;
  OC_LIST_STRUCT(links);
#ifdef OC_SCENES
  oc_collection_type_t collection_type;
  oc_string_t last_scene;
  /* Note: OCF 1.0 specifies sceneValues actually as type string,
     but there is already a change request to change this to an array.
     Especially since a single string has size limitations disallowing
     more scenes. */
  oc_string_array_t scene_values;
#endif
};

bool oc_handle_collection_request(oc_method_t method, oc_request_t *request,
                                  oc_interface_mask_t interface);
oc_collection_t *oc_collection_alloc(void);
void oc_collection_free(oc_collection_t *collection);

/**
  @brief Gets the collection with the specified URI.
  @param uri_path URI to lookup. Must not be NULL.
  @param uri_path_len Lenght of the URI.
  @return The collection, scene list or scene collection with
   the specified URI or NULL if not found.
  @internal Internal API.
*/
oc_collection_t *oc_get_collection_by_uri(const char *uri_path,
                                          size_t uri_path_len, size_t device);

/**
  @brief Returns a list of collections.
  @return collections and scene list
  @see oc_collection_get_collections
  @internal Internal API. Use \c oc_collection_get_collections()
   instead.
*/
oc_collection_t *oc_collection_get_all(void);

/**
  @brief The function returns the link with the resource having the
   specified \c uri_path.

  The function starts looking from the head of the list and returns
  the first match.

  If the collection is a scene collection, then this function can
  also be used to find the correcponding scene member by URI.
  @param collection collection with the links to traverse (non-recursively)
  @param uri_path the href to compare to
  @param uri_path_len length of the path
  @return the link with the matching resource, NULL if there is no match or
   if any of the parameters is NULL or zero
  @see oc_get_scene_member_by_uri
  @internal Internal API.
*/
oc_link_t *oc_get_link_by_uri(oc_collection_t *collection, const char *uri_path, size_t uri_path_len);

oc_link_t *oc_get_link_by_resource(oc_collection_t *collection,
                                   oc_resource_t *resource);
void oc_collection_remove_resource(oc_collection_t *collection,
                                   oc_resource_t *resource);

/**
  @brief Checks if the given resource is a collection.
  @param resource Resource to evaluate. The comparison is done
   against the pointers, not against the URIs.
  @return true if the given resource is a collection, scene list
   or scene collection, false else
  @see oc_check_if_scene_collection
  @internal Internal API.
*/
bool oc_check_if_collection(oc_resource_t *resource);
void oc_collection_add(oc_collection_t *collection);

#ifdef __cplusplus
}
#endif

#endif /* OC_COLLECTION_H */
