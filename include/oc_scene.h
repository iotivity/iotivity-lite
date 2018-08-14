/*
// Copyright (c) 2017 Lynx Technology
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

#ifndef OC_SCENE_H
#define OC_SCENE_H

/**
    @brief Scene handling API.
    @file
*/
#include "oc_ri.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
  @brief URI of the scene list.
*/
#define OC_SCENELIST_URI "/OCSceneListURI"

/**
  @brief Scene mapping
  @see oc_scene_member_s
*/
struct oc_scene_mapping_s
{
  struct oc_scene_mapping_s *next;
  oc_string_t scene;
  oc_string_t property;
  oc_string_t value;
};

/**
  @brief Scene member.

  This struct can be used as \link oc_resource_s\endlink.
  @see oc_collection_s
*/
struct oc_scene_member_s
{
  struct oc_scene_member_s *next;
  size_t device;
  oc_string_t uri;
  oc_string_array_t types;
  oc_interface_mask_t interfaces;
  oc_interface_mask_t default_interface;
  oc_resource_properties_t properties;
  oc_request_handler_t get_handler;
  oc_request_handler_t put_handler;
  oc_request_handler_t post_handler;
  oc_request_handler_t delete_handler;
  oc_string_t name;
  oc_resource_t *resource;
  oc_collection_t *parent;
  OC_LIST_STRUCT(scene_mapping);
};

/**
  @brief Gets the scene list.

  If the scene list does not exist yet, then the function
  creates it first.
  @return the scene list or NULL if out of memory
*/
oc_collection_t *oc_scene_get_scenelist(void);

/**
  @brief Allocates a scene member.

  The function does no setup of the member.
  @return the scene member or NULL if out of memory.
  @internal Internal API. Apps shall use \c oc_new_scene_member() instead.
*/
oc_scene_member_t *oc_scene_member_alloc(void);

/**
  @brief Releases a scene member.

  The function frees the resource properties and scene mappings.
  The scene member is not removed from the scene collection.
  @param member Scene member to release. The function does nothing,
   if this is NULL.
  @internal Internal API. Apps shall use \c oc_delete_scene_member() instead.
*/
void oc_scene_member_free(oc_scene_member_t *member);

/**
  @brief Checks whether the scene collection contains a specific scene.

  The function checks, if the specified scene is in \c scene_values
  array of the scene collection.
  @param scene_collection Scene collection to search for.
   The function does nothing, if this is NULL.
  @param scene Scene to search for. The scene name is case-sensitive.
   The function does nothing, if this is NULL or empty.
  @return true if the scene part of the scene collection, false if
   not or if the parameters are invalid.
  @see oc_scene_collection_add_scene
  @internal Internal API.
*/
bool oc_scene_collection_has_scene(oc_collection_t *scene_collection,
                                   const char *scene);

/**
  @brief Adds the scene to the scene collection.

  The function adds the scene to the \c scene_values array of the
  scene collection, if it is not already in the array. If it is
  already in the array, then the function does nothing.
  @param scene_collection Scene collection to add the scene to.
   The function does nothing, if this is NULL.
  @param scene Scene to add to the scene collection. The name
   is case-sensitive. The function does nothing, if this is
   NULL or empty.
  @internal Internal API.
*/
void oc_scene_collection_add_scene(oc_collection_t *scene_collection,
                                   const char *scene);

/**
  @brief Looks up the scene collection with the specified URI.
  @param uri_path URI to lookup with any leading slashes stripped.
   Must not be NULL.
  @param uri_path_len length of the specified URI
  @return the matching scene collection or NULL if not found
  @internal Internal API.
*/
oc_collection_t *oc_get_scene_collection_by_uri(const char *uri_path,
                                                size_t uri_path_len);

/**
  @brief Looks up the scene collection with the specified URI.
  @param uri_path URI to lookup with any leading slashes stripped.
   Must not be NULL.
  @param uri_path_len length of the specified URI
  @return the matching scene collection or NULL if not found
  @internal Internal API.
*/
oc_resource_t *oc_get_scene_member_by_uri(const char *uri_path,
                                          size_t uri_path_len);

/**
  @brief Checks whether the given resource is a scene collection.

  The function compares the resources linked in the scene list
  with the specified resource.
  @param resource Resource to evaluate. The comparison is done
   against the pointers, not against the URIs.
  @return true if the resource is a scene collection, false if
   not or if the resource is NULL.
  @see oc_check_if_collection
  @internal Internal API.
*/
bool oc_check_if_scene_collection(oc_resource_t *resource);

/**
  @brief Checks whether the given resource is a scene member.

  The function compares the resources linked in all scene
  collections with the specified resource.
  @param resource Resource to evaluate. The comparison is done
   against the pointers, not against the URIs.
  @return true if the resource is a scene member, false if
   not or if the resource is NULL.
  @internal Internal API.
*/
bool oc_check_if_scene_member(oc_resource_t *resource);

bool oc_handle_scene_member_request(oc_method_t method,
                                    oc_request_t *request,
                                    oc_interface_mask_t interface);

#ifdef __cplusplus
}
#endif

#endif /* OC_SCENE_H */
