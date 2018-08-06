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
#include "oc_endpoint.h"

/* TBD: Make this configurable and add dynamic support */
#define OC_ENDPOINT_CACHE_MAX_ITEMS 200
typedef struct {
  oc_endpoint_t ep;
  uint8_t device;
} endpoint_cache_item_t;
static uint8_t last_device; // zero means none
static int next_free_item;
static endpoint_cache_item_t endpoint_cache[OC_ENDPOINT_CACHE_MAX_ITEMS];

static int
get_cache_entry_for_endpoint(oc_endpoint_t *endpoint)
{
  if (endpoint) {
    int loop;
    for (loop = 0; loop < next_free_item; ++loop) {
      if (oc_endpoint_compare(endpoint, &endpoint_cache[loop].ep) == 0) {
        return loop;
      }
    }
  }
  return -1;
}

static bool
add_cache_entry(oc_endpoint_t *endpoint, uint8_t device)
{
  if (endpoint && device > 0 && next_free_item < OC_ENDPOINT_CACHE_MAX_ITEMS) {
    endpoint_cache[next_free_item].device = device;
    memcpy(&endpoint_cache[next_free_item].ep, endpoint, sizeof(oc_endpoint_t));
    endpoint_cache[next_free_item].ep.next = NULL;
#ifdef OC_DEBUG
    PRINT("eps cache: added ");
    PRINTipaddr(*endpoint);
    PRINT(" %d/%d as device %u at index %d\n",
          (endpoint->flags & SECURED), (endpoint->flags & MULTICAST),
          device, next_free_item);
#endif
    ++next_free_item;
    return true;
  }
  return false;
}

void
oc_discovery_add_eps_to_cache(oc_endpoint_t *source, oc_endpoint_t *eps)
{
  uint8_t device = 0;
  int source_entry = get_cache_entry_for_endpoint(source);
  oc_endpoint_t *loop;
  for (loop = eps; loop != NULL && device == 0; loop = loop->next) {
    int entry = get_cache_entry_for_endpoint(loop);
    if (entry >= 0) {
      device = endpoint_cache[entry].device;
    }
  }

  if (device == 0) {
    if (source_entry >= 0) {
      device = endpoint_cache[source_entry].device;
    }
    else {
      device = ++last_device;
    }
  }

  bool added = true;
  if (source_entry < 0) {
    added = add_cache_entry(source, device);
  }
  else {
    // align all endpoints
    endpoint_cache[source_entry].device = device;
  }

  for (loop = eps; loop != NULL && added; loop = loop->next) {
    int entry = get_cache_entry_for_endpoint(loop);
    if (entry < 0) {
      added = add_cache_entry(loop, device);
    }
    else {
      // align all endpoints
      endpoint_cache[entry].device = device;
    }
  }
}

uint8_t
oc_discovery_get_device(oc_endpoint_t *endpoint)
{
  int entry = get_cache_entry_for_endpoint(endpoint);
  if (entry >= 0) {
#ifdef OC_DEBUG
    PRINT("Found match ");
    PRINTipaddr(endpoint_cache[entry].ep);
    PRINT(" with device %u\n", endpoint_cache[entry].device);
#endif
    return endpoint_cache[entry].device;
  }
  return 0;
}

static bool
filter_resource(oc_resource_t *resource, oc_request_t *request,
                const char *anchor, CborEncoder *links)
{
  if (!oc_filter_resource_by_rt(resource, request)) {
    return false;
  }

  if (!(resource->properties & OC_DISCOVERABLE)) {
    return false;
  }

  oc_rep_start_object(*links, link);

  // anchor
  oc_rep_set_text_string(link, anchor, anchor);

  // uri
  oc_rep_set_text_string(link, href, oc_string(resource->uri));

  // rt
  oc_rep_set_array(link, rt);
  int i;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(resource->types);
       i++) {
    size_t size = oc_string_array_get_item_size(resource->types, i);
    const char *t = (const char *)oc_string_array_get_item(resource->types, i);
    if (size > 0)
      oc_rep_add_text_string(rt, t);
  }
  oc_rep_close_array(link, rt);

  // if
  oc_core_encode_interfaces_mask(oc_rep_object(link), resource->interfaces);

  // p
  oc_rep_set_object(link, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & ~(OC_PERIODIC | OC_SECURE)));
  oc_rep_close_object(link, p);

  // eps
  oc_rep_set_array(link, eps);
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(resource->device);
  while (eps != NULL) {
    /*  If this resource has been explicitly tagged as SECURE on the
     *  application layer, skip all coap:// endpoints, and only include
     *  coaps:// endpoints.
     *  Also, exclude all endpoints that are not associated with the interface
     *  through which this request arrived. This is achieved by checking if the
     *  interface index matches.
     */
    if ((resource->properties & OC_SECURE && !(eps->flags & SECURED)) ||
        (request->origin && request->origin->interface_index != -1 &&
         request->origin->interface_index != eps->interface_index)) {
      goto next_eps;
    }
    oc_rep_object_array_start_item(eps);
    oc_string_t ep;
    if (oc_endpoint_to_string(eps, &ep) == 0) {
      oc_rep_set_text_string(eps, ep, oc_string(ep));
      oc_free_string(&ep);
    }
    oc_rep_object_array_end_item(eps);
  next_eps:
    eps = eps->next;
  }
  oc_rep_close_array(link, eps);

  oc_rep_end_object(*links, link);

  return true;
}

static int
process_device_resources(CborEncoder *links, oc_request_t *request,
                         int device_index)
{
  int matches = 0;
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, OC_UUID_LEN);
  oc_string_t anchor;
  oc_concat_strings(&anchor, "ocf://", uuid);

  if (filter_resource(oc_core_get_resource_by_index(OCF_P, 0), request,
                      oc_string(anchor), links))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_D, device_index),
                      request, oc_string(anchor), links))
    matches++;

  if (filter_resource(
        oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_index),
        request, oc_string(anchor), links))
    matches++;

  if (oc_get_con_res_announced() &&
      filter_resource(oc_core_get_resource_by_index(OCF_CON, device_index),
                      request, oc_string(anchor), links))
    matches++;

#ifdef OC_SECURITY
  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_DOXM, device_index),
                      request, oc_string(anchor), links))
    matches++;

  if (filter_resource(
        oc_core_get_resource_by_index(OCF_SEC_PSTAT, device_index), request,
        oc_string(anchor), links))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_ACL, device_index),
                      request, oc_string(anchor), links))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_CRED, device_index),
                      request, oc_string(anchor), links))
    matches++;
#endif /* OC_SECURITY */

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {
    if (resource->device != device_index ||
        !(resource->properties & OC_DISCOVERABLE))
      continue;

    if (filter_resource(resource, request, oc_string(anchor), links))
      matches++;
  }

#if defined(OC_COLLECTIONS)
  oc_collection_t *collection = oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_index ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (filter_resource((oc_resource_t *)collection, request, oc_string(anchor),
                        links))
      matches++;
  }

#if defined(OC_SCENES)
  collection = oc_scene_get_scenelist();
  if (collection) {
    oc_link_t *link = oc_list_head(collection->links);
    for (; link; link = link->next) {
      oc_collection_t *scene_collection = (oc_collection_t*)link->resource;
      if (scene_collection != NULL &&
          scene_collection->device == device_index) {
        if (collection->properties & OC_DISCOVERABLE &&
            filter_resource((oc_resource_t *)scene_collection, request,
                            oc_string(anchor), links)) {
          matches++;
        }
        oc_link_t *member = oc_list_head(scene_collection->links);
        for (; member; member = member->next) {
          oc_resource_t *scene_member = member->resource;
          if (scene_member != NULL &&
              scene_member->properties & OC_DISCOVERABLE &&
              filter_resource(scene_member, request,
                              oc_string(anchor), links)) {
            matches++;
          }
        }
      }
    }
  }
#endif /* OC_SCENES */
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

  oc_free_string(&anchor);

  return matches;
}

static bool
filter_oic_1_1_resource(oc_resource_t *resource, oc_request_t *request,
                        CborEncoder *links)
{
  if (!oc_filter_resource_by_rt(resource, request)) {
    return false;
  }

  if (!(resource->properties & OC_DISCOVERABLE)) {
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
    size_t size = oc_string_array_get_item_size(resource->types, i);
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
  /** Tag all resources with sec=true for OIC 1.1 to pass the CTT script. */
  oc_rep_set_boolean(p, sec, true);
#endif /* OC_SECURITY */

  // port, x.org.iotivity.tcp and x.org.iotivity.tls
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(resource->device);
  while (eps != NULL) {
    if (resource->properties & OC_SECURE && !(eps->flags & SECURED)) {
      goto next_eps;
    }

#ifdef OC_TCP
    if (eps->flags & TCP) {
      if (eps->flags & SECURED) {
        if (request->origin->flags & IPV6 && eps->flags & IPV6) {
          oc_rep_set_uint(p, x.org.iotivity.tls, eps->addr.ipv6.port);
        }
#ifdef OC_IPV4
        else if (request->origin->flags & IPV4 && eps->flags & IPV4) {
          oc_rep_set_uint(p, x.org.iotivity.tls, eps->addr.ipv4.port);
        }
#endif /* OC_IPV4 */
      }
      else {
        if (request->origin->flags & IPV6 && eps->flags & IPV6) {
          oc_rep_set_uint(p, x.org.iotivity.tcp, eps->addr.ipv6.port);
        }
#ifdef OC_IPV4
        else if (request->origin->flags & IPV4 && eps->flags & IPV4) {
          oc_rep_set_uint(p, x.org.iotivity.tcp, eps->addr.ipv4.port);
        }
#endif /* OC_IPV4 */
      }
    }
    else
#endif /* OC_TCP */
    if (eps->flags & SECURED) {
      if (request->origin->flags & IPV6 && eps->flags & IPV6) {
        oc_rep_set_uint(p, port, eps->addr.ipv6.port);
      }
#ifdef OC_IPV4
      else if (request->origin->flags & IPV4 && eps->flags & IPV4) {
        oc_rep_set_uint(p, port, eps->addr.ipv4.port);
      }
#endif /* OC_IPV4 */
    }
    next_eps:
    eps = eps->next;
  }

  oc_rep_close_object(res, p);

  oc_rep_end_object(*links, res);
  return true;
}

static int
process_oic_1_1_device_object(CborEncoder *device, oc_request_t *request,
                              int device_num, bool baseline)
{
  int matches = 0;
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(device_num), uuid, OC_UUID_LEN);

  oc_rep_start_object(*device, links);
  oc_rep_set_text_string(links, di, uuid);

  if (baseline) {
    oc_resource_t *ocf_res = oc_core_get_resource_by_index(OCF_RES, device_num);
    oc_rep_set_string_array(links, rt, ocf_res->types);
    oc_core_encode_interfaces_mask(oc_rep_object(links), ocf_res->interfaces);
  }

  oc_rep_set_array(links, links);

  if (filter_oic_1_1_resource(oc_core_get_resource_by_index(OCF_P, device_num),
                              request, oc_rep_array(links)))
    matches++;

  if (filter_oic_1_1_resource(oc_core_get_resource_by_index(OCF_D, device_num),
                              request, oc_rep_array(links)))
    matches++;

  /* oic.wk.con */
  if (oc_get_con_res_announced() &&
      filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_CON, device_num), request,
        oc_rep_array(links)))
    matches++;

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {

    if (resource->device != device_num ||
        !(resource->properties & OC_DISCOVERABLE))
      continue;

    if (filter_oic_1_1_resource(resource, request, oc_rep_array(links)))
      matches++;
  }

#if defined(OC_COLLECTIONS)
  oc_collection_t *collection = oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_num ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (filter_oic_1_1_resource((oc_resource_t *)collection, request,
                                oc_rep_array(links)))
      matches++;
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

#ifdef OC_SECURITY
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_DOXM, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_PSTAT, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_CRED, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_ACL, device_num), request,
        oc_rep_array(links)))
    matches++;
#endif

  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_num),
        request, oc_rep_array(links)))
    matches++;

  oc_rep_close_array(links, links);
  oc_rep_end_object(*device, links);

  return matches;
}

static void
oc_core_1_1_discovery_handler(oc_request_t *request,
                              oc_interface_mask_t interface, void *data)
{
  (void)data;
  int matches = 0, device;

  switch (interface) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    for (device = 0; device < oc_core_get_num_devices(); device++) {
      matches += process_oic_1_1_device_object(oc_rep_array(links), request,
                                               device, false);
    }
    oc_rep_end_links_array();
  } break;
  case OC_IF_BASELINE: {
    oc_rep_start_links_array();
    for (device = 0; device < oc_core_get_num_devices(); device++) {
      matches += process_oic_1_1_device_object(oc_rep_array(links), request,
                                               device, true);
    }
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }

  int response_length = oc_rep_finalize();

  if (matches && response_length) {
    request->response->response_buffer->response_length =
      (uint16_t)response_length;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else if (request->origin && (request->origin->flags & MULTICAST) == 0) {
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_BAD_REQUEST);
  } else {
    request->response->response_buffer->code = OC_IGNORE;
  }
}

static void
oc_core_discovery_handler(oc_request_t *request, oc_interface_mask_t interface,
                          void *data)
{
  (void)data;

  if (request->origin && request->origin->version == OIC_VER_1_1_0) {
    oc_core_1_1_discovery_handler(request, interface, data);
    return;
  }

  int matches = 0, device = request->resource->device;

  switch (interface) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    matches += process_device_resources(oc_rep_array(links), request, device);
    oc_rep_end_links_array();
  } break;
  case OC_IF_BASELINE: {
    oc_rep_start_links_array();
    oc_rep_start_object(*oc_rep_array(links), props);
    memcpy(&root_map, &props_map, sizeof(CborEncoder));
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_RES, device));
    oc_rep_set_array(root, links);
    matches += process_device_resources(oc_rep_array(links), request, device);
    oc_rep_close_array(root, links);
    memcpy(&props_map, &root_map, sizeof(CborEncoder));
    oc_rep_end_object(*oc_rep_array(links), props);
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }
  int response_length = oc_rep_finalize();
  if (matches && response_length > 0) {
    request->response->response_buffer->response_length =
      (uint16_t)response_length;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else if (request->origin && (request->origin->flags & MULTICAST) == 0) {
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_BAD_REQUEST);
  } else {
    /* There were rt/if selections and there were no matches, so ignore */
    request->response->response_buffer->code = OC_IGNORE;
  }
}

void
oc_create_discovery_resource(int resource_idx, int device)
{
  oc_core_populate_resource(
    resource_idx, device, "oic/res", OC_IF_LL | OC_IF_BASELINE, OC_IF_LL, 0,
    oc_core_discovery_handler, 0, 0, 0, 1, "oic.wk.res");
}

#ifdef OC_CLIENT
oc_discovery_flags_t
oc_ri_process_discovery_payload(uint8_t *payload, int len,
                                oc_discovery_handler_t handler,
                                oc_endpoint_t *endpoint, void *user_data)
{
  oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;
  oc_string_t *uri = NULL;
  oc_string_t *anchor = NULL;
  oc_string_array_t *types = NULL;
  oc_interface_mask_t interfaces = 0;

#ifndef OC_DYNAMIC_ALLOCATION
  char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
  memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                 rep_objects_alloc, (void *)rep_objects_pool,
                                 0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_set_pool(&rep_objects);

  oc_rep_t *links = 0, *rep, *p;
  int s = oc_parse_rep(payload, len, &p);
  if (s != 0) {
    OC_WRN("error parsing discovery response");
  }
  links = rep = p;
  /*  While the oic.wk.res schema over the baseline interface provides for an
   *  array of objects, only one object is present and used in practice.
   *
   *  If rep->value.object != NULL, it means the response was from the baseline
   *  interface, and in that case make rep point to the properties of its first
   *  object. It is traversed in the following loop to obtain a handle to its
   *  array of links.
   */
  if (rep->value.object) {
    rep = rep->value.object;
  }

  while (rep != NULL) {
    switch (rep->type) {
    /*  Ignore other oic.wk.res properties over here as they're known
     *  and fixed. Only process the "links" property.
     */
    case OC_REP_OBJECT_ARRAY: {
      if (oc_string_len(rep->name) == 5 &&
          memcmp(oc_string(rep->name), "links", 5) == 0) {
        links = rep->value.object_array;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  while (links != NULL) {
    /* Reset bm in every round as this can be omitted if 0. */
    oc_resource_properties_t bm = 0;
    oc_endpoint_t *eps_list = NULL;
    oc_endpoint_t *unmatched_eps_list = NULL;
    oc_rep_t *link = links->value.object;
    while (link != NULL) {
      switch (link->type) {
      case OC_REP_STRING: {
        if (oc_string_len(link->name) == 6 &&
            memcmp(oc_string(link->name), "anchor", 6) == 0) {
          anchor = &link->value.string;
        } else if (oc_string_len(link->name) == 4 &&
                   memcmp(oc_string(link->name), "href", 4) == 0) {
          uri = &link->value.string;
        }
      } break;
      case OC_REP_STRING_ARRAY: {
        size_t i;
        if (oc_string_len(link->name) == 2 &&
            strncmp(oc_string(link->name), "rt", 2) == 0) {
          types = &link->value.array;
        } else {
          interfaces = 0;
          for (i = 0;
               i < oc_string_array_get_allocated_size(link->value.array);
               i++) {
            interfaces |= oc_ri_get_interface_mask(
              oc_string_array_get_item(link->value.array, i),
              oc_string_array_get_item_size(link->value.array, i));
          }
        }
      } break;
      case OC_REP_OBJECT_ARRAY: {
        oc_rep_t *eps = link->value.object_array;
        oc_endpoint_t *eps_cur = NULL;
        oc_endpoint_t *unmatched_cur = NULL;
        while (eps != NULL) {
          oc_rep_t *ep = eps->value.object;
          while (ep != NULL) {
            switch (ep->type) {
            case OC_REP_STRING: {
              if (oc_string_len(ep->name) == 2 &&
                  memcmp(oc_string(ep->name), "ep", 2) == 0) {
                oc_endpoint_t temp_ep;
                memset(&temp_ep, 0, sizeof(oc_endpoint_t));
                if (oc_string_to_endpoint(&ep->value.string, &temp_ep, NULL) ==
                    0) {
                  oc_endpoint_t **work_ep = &eps_cur;
                  oc_endpoint_t **work_list_ep = &eps_list;
                  /* Return all endpoints whose address matches with the source
                   * address of this response.
                   *
                   * In case the eps does not contain any address that matches
                   * the actual source address, pass through the eps instead.
                   *
                   * Note: Do not use the source address as a replacement
                   *       in case there is no match, since IoTivity refuses
                   *       secure connections to addresses not listed
                   *       in its eps.
                   */
                  if (oc_endpoint_compare_address(&temp_ep, endpoint) != 0) {
                    work_ep = &unmatched_cur;
                    work_list_ep = &unmatched_eps_list;
                  }

                  if (*work_ep) {
                    (*work_ep)->next = oc_new_endpoint();
                    (*work_ep) = (*work_ep)->next;
                  } else {
                    *work_ep = *work_list_ep = oc_new_endpoint();
                  }

                  if (*work_ep) {
                    memcpy(*work_ep, &temp_ep, sizeof(oc_endpoint_t));
                    (*work_ep)->interface_index = endpoint->interface_index;
                    if (oc_ipv6_endpoint_is_link_local(*work_ep) == 0 &&
                        oc_ipv6_endpoint_is_link_local(endpoint) == 0) {
                      (*work_ep)->addr.ipv6.scope = endpoint->addr.ipv6.scope;
                    }
                  }
                }
              }
            } break;
            default:
              break;
            }
            ep = ep->next;
          }
          eps = eps->next;
        }
      } break;
      case OC_REP_OBJECT: {
        oc_rep_t *policy = link->value.object;
        if (policy != NULL && oc_string_len(link->name) == 1 &&
            *(oc_string(link->name)) == 'p' && policy->type == OC_REP_INT &&
            oc_string_len(policy->name) == 2 &&
            memcmp(oc_string(policy->name), "bm", 2) == 0) {
          bm = policy->value.integer;
        }
      } break;
      default:
        break;
      }
      link = link->next;
    }

    /*
      OCF devices use same socket for sending and receiving and hence
      the ports match the endpoints.
      For bridged devices or multiple virtual devices on a physical
      device the IP addresses are identical but the ports are different.
      Hence, endpoints (including ports) are different per virtual device.
      Exception: /oic/p has same endpoints as there is one platform for all
      virtual devices. But /oic/p is returned per virtual device.
      Ie., /oic/p is returned for each virtual device on the origin endpoint
      matching that device, but the eps listed in /oic/p is identical.
      As we include the source address in the endpoint cache, we need to
      exclude /oic/p, as otherwise all virtual devices would be collected
      into a single pseudo device (see device in endpoint_cache_item_t).
    */
    bool is_oic_p = (oc_string_len(*uri) == 6 &&
                     memcmp(oc_string(*uri), "/oic/p", 6) == 0);
    if (eps_list && !is_oic_p) {
      oc_discovery_add_eps_to_cache(endpoint, eps_list);
    }
    if (unmatched_eps_list) {
      if (!is_oic_p) {
        oc_discovery_add_eps_to_cache(endpoint, unmatched_eps_list);
      }
      if (!eps_list) {
        eps_list = unmatched_eps_list;
      }
      else {
        oc_free_server_endpoints(unmatched_eps_list);
      }
    }
    if (eps_list &&
        handler(oc_string(*anchor), oc_string(*uri), *types, interfaces,
                eps_list, bm, user_data) == OC_STOP_DISCOVERY) {
      ret = OC_STOP_DISCOVERY;
      goto done;
    }
    links = links->next;
  }

done:
  oc_free_rep(p);
  return ret;
}
#endif /* OC_CLIENT */
