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

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif /* OC_CLIENT */

#include "messaging/coap/oc_coap.h"
#include "oc_api.h"

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "oc_collection.h"
#if defined(OC_SCENES)
#include "oc_scene.h"
#endif /* OC_SCENES */
#endif /* OC_COLLECTIONS && OC_SERVER */

#include "oc_core_res.h"

static bool
filter_resource(oc_resource_t *resource, const char *rt, int rt_len,
                CborEncoder *links)
{

  if (!oc_ri_filter_rt(resource, rt, rt_len)) {
    return false;
  }

  oc_rep_start_object(*links, res);

  // uri
  oc_rep_set_text_string(res, href, oc_string(resource->uri));

  // rt
  oc_rep_set_array(res, rt);
  int i;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(resource->types);
       i++) {
    int size = oc_string_array_get_item_size(resource->types, i);
    const char *t = (const char *)oc_string_array_get_item(resource->types, i);
    if (size > 0)
      oc_rep_add_text_string(rt, t);
  }
  oc_rep_close_array(res, rt);

  // if
  oc_core_encode_interfaces_mask(oc_rep_object(res), resource->interfaces);

  // p
  oc_rep_set_object(res, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & ~(OC_PERIODIC | OC_SECURE)));
#ifdef OC_SECURITY
  if (resource->properties & OC_SECURE) {
    oc_rep_set_boolean(p, sec, true);
    oc_rep_set_uint(p, port, oc_connectivity_get_dtls_port());
  }
#endif /* OC_SECURITY */

  oc_rep_close_object(res, p);

  oc_rep_end_object(*links, res);
  return true;
}

static int
process_device_object(CborEncoder *device, const char *rt, int rt_len,
                      int device_num, bool baseline)
{
  int matches = 0;
  char uuid[37];
  oc_uuid_to_str(oc_core_get_device_id(device_num), uuid, 37);

  oc_rep_start_object(*device, links);
  oc_rep_set_text_string(links, di, uuid);

  if (baseline) {
    oc_resource_t *ocf_res = oc_core_get_resource_by_index(OCF_RES);
    oc_rep_set_string_array(links, rt, ocf_res->types);
    oc_core_encode_interfaces_mask(oc_rep_object(links), ocf_res->interfaces);
  }

  oc_rep_set_array(links, links);

  if (filter_resource(oc_core_get_resource_by_index(OCF_P), rt, rt_len,
                      oc_rep_array(links)))
    matches++;

  if (filter_resource(
        oc_core_get_resource_by_index(NUM_OC_CORE_RESOURCES - 1 + device_num),
        rt, rt_len, oc_rep_array(links)))
    matches++;

  /* oic.wk.con */
  if (device_num == 0 &&
      filter_resource(oc_core_get_resource_by_index(OCF_CON),
                      rt, rt_len, oc_rep_array(links)))
    matches++;

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {

    if (resource->device != device_num ||
        !(resource->properties & OC_DISCOVERABLE))
      continue;

    if (filter_resource(resource, rt, rt_len, oc_rep_array(links)))
      matches++;
  }

#if defined(OC_COLLECTIONS)
  oc_collection_t *collection = oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_num ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (filter_resource((oc_resource_t *)collection, rt, rt_len,
                        oc_rep_array(links)))
      matches++;
  }

#if defined(OC_SCENES)
  collection = oc_scene_get_scenelist();
  if (collection) {
    oc_link_t *link = oc_list_head(collection->links);
    for (; link; link = link->next) {
      oc_collection_t *scene_collection = (oc_collection_t*)link->resource;
      if (scene_collection != NULL &&
          scene_collection->device == device_num) {
        if (collection->properties & OC_DISCOVERABLE &&
            filter_resource((oc_resource_t *)scene_collection, rt, rt_len,
                            oc_rep_array(links))) {
          matches++;
        }
        oc_link_t *member = oc_list_head(scene_collection->links);
        for (; member; member = member->next) {
          oc_resource_t *scene_member = member->resource;
          if (scene_member != NULL &&
              scene_member->properties & OC_DISCOVERABLE &&
              filter_resource(scene_member, rt, rt_len, oc_rep_array(links))) {
            matches++;
          }
        }
      }
    }
  }
#endif /* OC_SCENES */
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

#ifdef OC_SECURITY
  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_DOXM), rt, rt_len,
                      oc_rep_array(links)))
    matches++;
  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_PSTAT), rt, rt_len,
                      oc_rep_array(links)))
    matches++;
#endif

  oc_rep_close_array(links, links);
  oc_rep_end_object(*device, links);

  return matches;
}

static void
oc_core_discovery_handler(oc_request_t *request, oc_interface_mask_t interface,
                          void *data)
{
  (void)data;
  char *rt = NULL, *di = NULL;
  oc_uuid_t dev_id;
  int rt_len = 0, matches = 0, di_len = 0, device;
  if (request->query_len) {
    rt_len =
      oc_ri_get_query_value(request->query, request->query_len, "rt", &rt);
    di_len =
      oc_ri_get_query_value(request->query, request->query_len, "di", &di);
    if (di_len == 36) {
      oc_str_to_uuid(di, &dev_id);
    }
  }

  switch (interface) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    for (device = 0; device < oc_core_get_num_devices(); device++) {
      if (di_len > 0 &&
          memcmp(oc_core_get_device_id(device), &dev_id, sizeof(oc_uuid_t)) !=
            0)
        continue;
      matches +=
        process_device_object(oc_rep_array(links), rt, rt_len, device, false);
    }
    oc_rep_end_links_array();
  } break;
  case OC_IF_BASELINE: {
    oc_rep_start_links_array();
    for (device = 0; device < oc_core_get_num_devices(); device++) {
      if (di_len > 0 &&
          memcmp(oc_core_get_device_id(device), &dev_id, sizeof(oc_uuid_t)) !=
            0)
        continue;
      matches +=
        process_device_object(oc_rep_array(links), rt, rt_len, device, true);
    }
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }

  int response_length = oc_rep_finalize();

  if (matches && response_length) {
    request->response->response_buffer->response_length = response_length;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else {
    /* There were rt/if selections and there were no matches, so ignore */

    request->response->response_buffer->code = OC_IGNORE;
  }
}

void
oc_create_discovery_resource(void)
{
  oc_core_populate_resource(OCF_RES, 0, "oic/res", OC_IF_LL | OC_IF_BASELINE,
                            OC_IF_LL, 0, oc_core_discovery_handler, 0, 0, 0, 1,
                            "oic.wk.res");
}

#ifdef OC_CLIENT
oc_discovery_flags_t
oc_ri_process_discovery_payload(uint8_t *payload, int len,
                                oc_discovery_handler_t handler,
                                oc_endpoint_t *endpoint, void *user_data)
{
  oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;
  oc_string_t uri;
  uri.ptr = 0;
  oc_string_t di;
  di.ptr = 0;
  bool secure = false;
  uint16_t dtls_port = 0, default_port = endpoint->addr.ipv6.port;
  oc_string_array_t types = { 0 };
  oc_interface_mask_t interfaces = 0;
  oc_server_handle_t handle;
  memcpy(&handle.endpoint, endpoint, sizeof(oc_endpoint_t));

  oc_rep_t *array = 0, *rep;

#ifndef OC_DYNAMIC_ALLOCATION
  char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
  memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                 rep_objects_alloc, (void *)rep_objects_pool };
#else  /* !OC_DYNAMIC_ALLOCATION */
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_set_pool(&rep_objects);

  int s = oc_parse_rep(payload, len, &rep);
  if (s == 0)
    array = rep;
  else if (s == CborErrorOutOfMemory) {
      OC_ERR("rep objects exhausted\n");
  }
  else {
      OC_WRN("error parsing discovery response\n");
  }
  while (array != NULL) {
    oc_rep_t *device_map = array->value.object;
    while (device_map != NULL) {
      switch (device_map->type) {
      case STRING:
        if (oc_string_len(device_map->name) == 2 &&
            strncmp(oc_string(device_map->name), "di", 2) == 0)
          di = device_map->value.string;
        break;
      default:
        break;
      }
      device_map = device_map->next;
    }
    device_map = array->value.object;
    while (device_map != NULL) {
      switch (device_map->type) {
      case OBJECT_ARRAY: {
        oc_rep_t *links = device_map->value.object_array;
        while (links != NULL) {
          switch (links->type) {
          case OBJECT: {
            oc_rep_t *resource_info = links->value.object;
            while (resource_info != NULL) {
              switch (resource_info->type) {
              case STRING:
                uri = resource_info->value.string;
                break;
              case STRING_ARRAY:
                if (oc_string_len(resource_info->name) == 2 &&
                    strncmp(oc_string(resource_info->name), "rt", 2) == 0)
                  types = resource_info->value.array;
                else {
                  interfaces = 0;
                  int i;
                  for (i = 0; i < (int)oc_string_array_get_allocated_size(
                                    resource_info->value.array);
                       i++) {
                    interfaces |= oc_ri_get_interface_mask(
                      oc_string_array_get_item(resource_info->value.array, i),
                      oc_string_array_get_item_size(resource_info->value.array,
                                                    i));
                  }
                }
                break;
              case OBJECT: {
                oc_rep_t *policy_info = resource_info->value.object;
                while (policy_info != NULL) {
                  if (policy_info->type == INT &&
                      oc_string_len(policy_info->name) == 4 &&
                      strncmp(oc_string(policy_info->name), "port", 4) == 0) {
                    dtls_port = policy_info->value.integer;
                  }
                  if (policy_info->type == BOOL &&
                      oc_string_len(policy_info->name) == 3 &&
                      strncmp(oc_string(policy_info->name), "sec", 3) == 0 &&
                      policy_info->value.boolean == true) {
                    secure = true;
                  }
                  policy_info = policy_info->next;
                }
              } break;
              default:
                break;
              }
              resource_info = resource_info->next;
            }
            if (secure) {
              handle.endpoint.addr.ipv6.port = dtls_port;
              handle.endpoint.flags |= SECURED;
            } else {
              handle.endpoint.addr.ipv6.port = default_port;
              handle.endpoint.flags &= ~SECURED;
            }

            if (handler(oc_string(di), oc_string(uri), types, interfaces,
                        &handle, user_data) == OC_STOP_DISCOVERY) {
              ret = OC_STOP_DISCOVERY;
              goto done;
            }
            dtls_port = 0;
            secure = false;
          } break;
          default:
            break;
          }
          links = links->next;
        }
      } break;
      default:
        break;
      }
      device_map = device_map->next;
    }
    array = array->next;
  }
done:
  oc_free_rep(rep);
  return ret;
}
#endif /* OC_CLIENT */
