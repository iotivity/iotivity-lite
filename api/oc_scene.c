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

#include "oc_scene.h"

#if defined(OC_SCENES) && defined(OC_SERVER)
#ifndef OC_COLLECTIONS
#error "Cannot use scenes without defining OC_COLLECTIONS"
#endif /* OC_COLLECTIONS */
#include "oc_api.h"
#include "oc_core_res.h"
#include "util/oc_memb.h"
#include "oc_collection.h"

#define OC_SCENELIST_URI "/OCSceneListURI"
#define OC_SCENELIST_URI_LEN 15

OC_MEMB(oc_scenemembers_s, oc_scene_member_t, OC_MAX_APP_RESOURCES);
OC_MEMB(oc_scenemappings_s, oc_scene_mapping_t, OC_MAX_APP_RESOURCES);

oc_collection_t *
oc_scene_get_scenelist(void)
{
  oc_resource_t *scene_list = 
    (oc_resource_t*)oc_get_collection_by_uri(OC_SCENELIST_URI,
                                             OC_SCENELIST_URI_LEN, 0);
  if (scene_list == NULL) {
    /* TBD: does it make sense to allow multiple scene lists /
       one per device? Default now to zero. */
    scene_list = oc_new_scene_collection(OC_SCENELIST_URI, 0);
    if (scene_list)
    {
      oc_resource_set_discoverable(scene_list, true);
      oc_add_collection(scene_list);
    }
  }
  return (oc_collection_t*)scene_list;
}

bool
oc_add_scene_mapping(oc_resource_t *scene_member,
                     const char *scene,
                     const char *property,
                     const char *value)
{
  if (scene_member &&
      scene && *scene &&
      property && *property &&
      value && *value) {
    oc_scene_mapping_t *mapping = oc_memb_alloc(&oc_scenemappings_s);
    if (mapping) {
      oc_new_string(&mapping->scene, scene, strlen(scene));
      oc_new_string(&mapping->property, property, strlen(property));
      oc_new_string(&mapping->value, value, strlen(value));
      oc_list_add(((oc_scene_member_t*)scene_member)->scene_mapping, mapping);
      /* This will work only, when the scene member was already added
         to the scene collection (see oc_server_api::oc_add_scene_member()). */
      oc_scene_collection_add_scene(((oc_scene_member_t*)scene_member)->parent, scene);
      return true;
    }
    else {
      OC_WRN("insufficient memory to create new scene mapping");
    }
  }
  return false;
}

oc_scene_member_t *
oc_scene_member_alloc(void)
{
  oc_scene_member_t *member = oc_memb_alloc(&oc_scenemembers_s);
  if (member) {
    OC_LIST_STRUCT_INIT(member, scene_mapping);
    return member;
  }
  OC_WRN("insufficient memory to create new scene member");
  return NULL;
}

void
oc_scene_member_free(oc_scene_member_t *member)
{
  if (member != NULL) {
    oc_scene_mapping_t *mapping;
    while ((mapping = (oc_scene_mapping_t*)oc_list_pop(member->scene_mapping)) != NULL) {
      if (oc_string_len(mapping->scene) > 0) {
        oc_free_string(&mapping->scene);
      }
      if (oc_string_len(mapping->property) > 0) {
        oc_free_string(&mapping->property);
      }
      if (oc_string_len(mapping->value) > 0) {
        oc_free_string(&mapping->value);
      }
      oc_memb_free(&oc_scenemappings_s, mapping);
    }

    oc_ri_free_resource_properties((oc_resource_t*)member);
    oc_memb_free(&oc_scenemembers_s, member);
  }
}

bool
oc_scene_collection_has_scene(oc_collection_t *scene_collection, const char *scene)
{
  if (scene_collection && scene && *scene) {
    size_t scene_len = strlen(scene);
    unsigned int i;
    for (i = 0; i < oc_string_array_get_allocated_size(scene_collection->scene_values); ++i) {
      size_t value_len = oc_string_array_get_item_size(scene_collection->scene_values, i);
      if (value_len == scene_len &&
          strncmp(scene,
                  (const char *)oc_string_array_get_item(scene_collection->scene_values, i),
                  scene_len) == 0) {
        return true;
      }
    }
  }
  return false;
}

void
oc_scene_collection_add_scene(oc_collection_t *scene_collection, const char *scene)
{
  if (scene_collection && scene && *scene) {
    if (!oc_scene_collection_has_scene(scene_collection, scene)) {
      oc_string_array_add_item(scene_collection->scene_values, scene);
    }
  }
}

oc_collection_t *
oc_get_scene_collection_by_uri(const char *uri_path, size_t uri_path_len)
{
  const char *scene_list_uri = OC_SCENELIST_URI;
  ++scene_list_uri; /* skip leading /, the caller has skipped
                       it already in uri_path */
  size_t scene_list_uri_len = strlen(scene_list_uri);
  /* The function is called by oc_get_collection_by_uri() and we call
     that ourselves again to get the scene list collection. Add
     a check here that we do not enter an endless loop in case
     the scene list does not exist for some reason. */
  if (scene_list_uri_len != uri_path_len ||
      strncmp(scene_list_uri, uri_path, uri_path_len) != 0) {
    /* this function checks the URI of linked resource which is a
       scene collection within the scene list */
    oc_link_t *link = oc_get_link_by_uri(oc_scene_get_scenelist(),
                                         uri_path, uri_path_len);
    if (link) {
      return (oc_collection_t*)link->resource;
    }
  }
  return NULL;
}

bool
oc_check_if_scene_collection(oc_resource_t *resource)
{
  return oc_get_link_by_resource(oc_scene_get_scenelist(),
                                 resource) != NULL ? true : false;
}

bool
oc_check_if_scene_member(oc_resource_t *resource)
{
  oc_collection_t *scene_list = oc_scene_get_scenelist();
  if (scene_list) {
    oc_link_t *link = oc_list_head(scene_list->links);
    while (link != NULL) {
      oc_collection_t *scene_collection = (oc_collection_t*)link->resource;
      oc_link_t *member = oc_get_link_by_resource(scene_collection, resource);
      if (member != NULL) {
        return true;
      }
    }
  }
  return false;
}

oc_resource_t *
oc_get_scene_member_by_uri(const char *uri_path, size_t uri_path_len)
{
  oc_collection_t *scene_list = oc_scene_get_scenelist();
  if (scene_list) {
    oc_link_t *link = oc_list_head(scene_list->links);
    while (link != NULL) {
      oc_collection_t *scene_collection = (oc_collection_t*)link->resource;
      oc_link_t *member = oc_get_link_by_uri(scene_collection,
                                             uri_path, uri_path_len);
      if (member != NULL) {
        return member->resource;
      }
    }
  }
  return NULL;
}

bool
oc_handle_scene_member_request(oc_method_t method,
                               oc_request_t *request,
                               oc_interface_mask_t interface)
{
  bool process_baseline = true;
  int code = 69; /* status ok */
  oc_scene_member_t *member = (oc_scene_member_t *)request->resource;

reprocess:
  switch (interface) {
    case OC_IF_BASELINE: {
      oc_rep_start_root_object();
      if (process_baseline)
        oc_process_baseline_interface(request->resource);
      /* no filtering here as link is mandatory for scene member */
      oc_rep_set_object(root, link);
      oc_rep_set_text_string(link, href, oc_string(member->resource->uri));
      oc_rep_set_string_array(link, rt, member->resource->types);
      oc_core_encode_interfaces_mask(oc_rep_object(link),
                                     member->resource->interfaces);
      oc_rep_set_object(link, p);
      oc_rep_set_uint(p, bm, (uint8_t)(member->resource->properties &
                                       ~(OC_PERIODIC | OC_SECURE)));
      oc_rep_close_object(link, p);

      // eps
      oc_rep_set_array(link, eps);
      oc_endpoint_t *eps =
        oc_connectivity_get_endpoints(member->resource->device);
      while (eps != NULL) {
        oc_rep_object_array_start_item(eps);
        oc_string_t ep;
        if (oc_endpoint_to_string(eps, &ep) == 0) {
          oc_rep_set_text_string(eps, ep, oc_string(ep));
          oc_free_string(&ep);
        }
        oc_rep_object_array_end_item(eps);
        eps = eps->next;
      }
      oc_rep_close_array(link, eps);

      oc_rep_close_object(root, link);
      oc_rep_set_array(root, sceneMappings);
      oc_scene_mapping_t *mapping = (oc_scene_mapping_t*)oc_list_head(member->scene_mapping);
      while (mapping != NULL) {
        oc_rep_object_array_start_item(sceneMappings);
        oc_rep_set_text_string(sceneMappings, scene, oc_string(mapping->scene));
        oc_rep_set_text_string(sceneMappings, memberProperty, oc_string(mapping->property));
        oc_rep_set_text_string(sceneMappings, memberValue, oc_string(mapping->value));
        oc_rep_object_array_end_item(sceneMappings);
        mapping = mapping->next;
      }
      oc_rep_close_array(root, sceneMappings);
      oc_rep_end_root_object();
    } break;
    case OC_IF_LL: {
      oc_rep_set_array(root, links);
      if (oc_filter_resource_by_rt(member->resource, request)) {
        oc_rep_object_array_start_item(links);
        oc_rep_set_text_string(links, href, oc_string(member->resource->uri));
        oc_rep_set_string_array(links, rt, member->resource->types);
        oc_core_encode_interfaces_mask(oc_rep_object(links),
                                       member->resource->interfaces);
        oc_rep_set_object(links, p);
        oc_rep_set_uint(p, bm, (uint8_t)(member->resource->properties &
                                         ~(OC_PERIODIC | OC_SECURE)));
        oc_rep_close_object(links, p);

        // eps
        oc_rep_set_array(links, eps);
        oc_endpoint_t *eps =
          oc_connectivity_get_endpoints(member->resource->device);
        while (eps != NULL) {
          oc_rep_object_array_start_item(eps);
          oc_string_t ep;
          if (oc_endpoint_to_string(eps, &ep) == 0) {
            oc_rep_set_text_string(eps, ep, oc_string(ep));
            oc_free_string(&ep);
          }
          oc_rep_object_array_end_item(eps);
          eps = eps->next;
        }
        oc_rep_close_array(links, eps);

        oc_rep_object_array_end_item(links);
      }
      oc_rep_close_array(root, links);
      oc_rep_end_root_object();
      } break;
    case OC_IF_A: {
      if (method == OC_GET) {
        interface = OC_IF_BASELINE;
        process_baseline = false;
        goto reprocess;
      }
      code = oc_status_code(OC_STATUS_NOT_IMPLEMENTED);
    } break;
    default:
      break;
  }

  int size = oc_rep_finalize();
  size = (size <= 2) ? 0 : size;

  request->response->response_buffer->response_length = size;
  request->response->response_buffer->code = code;

  return true;
}

#endif /* OC_SCENES && OC_SERVER */
