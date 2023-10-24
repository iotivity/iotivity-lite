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

#include "oc_collection.h"

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "api/oc_collection_internal.h"
#include "api/oc_endpoint_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_link_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/observe_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_core_res_internal.h"
#include "oc_discovery_internal.h"
#include "oc_server_api_internal.h"
#include "util/oc_memb.h"
#include "util/oc_secure_string_internal.h"

#ifdef OC_COLLECTIONS_IF_CREATE
#include "api/oc_resource_factory_internal.h"
#endif /* OC_COLLECTIONS_IF_CREATE */

#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_etag_internal.h"
#endif /* OC_HAS_FEATURE_ETAG */

#include <assert.h>

OC_MEMB(g_collections_s, oc_collection_t, OC_MAX_NUM_COLLECTIONS);
OC_LIST(g_collections);
/* Allocator for oc_rtt_t */
OC_MEMB(g_rtt_s, oc_rt_t, OC_COLLECTION_SUPPORTED_RTS_COUNT_MAX);

#ifdef OC_COLLECTIONS_IF_CREATE
/* Allocator for resource factories */
OC_MEMB(g_rts_s, oc_rt_factory_t, 1);
OC_LIST(g_rt_factories);
OC_LIST(g_params_list);
#endif /* OC_COLLECTIONS_IF_CREATE */

oc_collection_t *
oc_collection_alloc(void)
{
  oc_collection_t *collection =
    (oc_collection_t *)oc_memb_alloc(&g_collections_s);
  if (collection == NULL) {
    OC_ERR("insufficient memory to create new collection");
    return NULL;
  }
  OC_LIST_STRUCT_INIT(collection, supported_rts);
  OC_LIST_STRUCT_INIT(collection, mandatory_rts);
  OC_LIST_STRUCT_INIT(collection, links);
  return collection;
}

static oc_event_callback_retval_t
collection_notify_batch_async(void *data)
{
  if (coap_notify_collection_batch((oc_collection_t *)data) != 0) {
    OC_WRN("failed to send batch notification to collection observers");
  }
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
collection_notify_baseline_async(void *data)
{
  if (coap_notify_collection_baseline((oc_collection_t *)data) != 0) {
    OC_WRN("failed to send baseline notification to collection observers");
  }
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
collection_notify_links_list_async(void *data)
{
  if (coap_notify_collection_links_list(data) != 0) {
    OC_WRN("failed to send linked list notification to collection observers");
  }
  oc_reset_delayed_callback(data, collection_notify_baseline_async, 0);
  return OC_EVENT_DONE;
}

static void
collection_free_resource_types(oc_list_t list)
{
  oc_rt_t *rtt = (oc_rt_t *)oc_list_pop(list);
  while (rtt != NULL) {
    oc_free_string(&rtt->rt);
    oc_memb_free(&g_rtt_s, rtt);
    rtt = (oc_rt_t *)oc_list_pop(list);
  }
}

static void
collection_free(oc_collection_t *collection, bool notify)
{
  bool removed = oc_list_remove2(g_collections, collection) != NULL;

  oc_link_t *link;
  while ((link = (oc_link_t *)oc_list_pop(collection->links)) != NULL) {
    oc_delete_link(link);
  }

  if (notify && removed) {
    oc_notify_resource_removed(&collection->res);
  }

  oc_remove_delayed_callback(collection, collection_notify_batch_async);
  oc_remove_delayed_callback(collection, collection_notify_baseline_async);
  oc_remove_delayed_callback(collection, collection_notify_links_list_async);

  oc_ri_free_resource_properties(&collection->res);
  collection_free_resource_types(collection->supported_rts);
  collection_free_resource_types(collection->mandatory_rts);

  oc_memb_free(&g_collections_s, collection);
}

void
oc_collection_free(oc_collection_t *collection)
{
  if (collection == NULL) {
    return;
  }
  collection_free(collection, true);
}

void
oc_collections_free_all(void)
{
  oc_collection_t *collection = (oc_collection_t *)oc_list_pop(g_collections);
  while (collection != NULL) {
    collection_free(collection, false);
    collection = (oc_collection_t *)oc_list_pop(g_collections);
  }
}

static void
collection_notify_resource_changed(oc_collection_t *collection,
                                   bool batchDispatch)
{
#ifdef OC_HAS_FEATURE_ETAG
  oc_resource_update_etag(&collection->res);
#endif /* OC_HAS_FEATURE_ETAG */
  oc_reset_delayed_callback(collection, collection_notify_links_list_async, 0);
#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
  coap_add_discovery_batch_observer(&collection->res, /*removed*/ false,
                                    batchDispatch);
#else  /* !OC_RES_BATCH_SUPPORT || !OC_DISCOVERY_RESOURCE_OBSERVABLE */
  (void)batchDispatch;
#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */
}

void
oc_collection_add_link(oc_resource_t *collection, oc_link_t *link)
{
  assert(collection != NULL);
  assert(link != NULL);

  if (link->resource == NULL || link->resource->uri.size <= 1) {
    OC_ERR("cannot add link to collection, invalid link");
    return;
  }
  oc_string_view_t link_uri = oc_string_view2(&link->resource->uri);
  oc_collection_t *col = (oc_collection_t *)collection;

  // Find position to insert to keep the list sorted by primarily by href
  // length and secondarily by href value.
  // Keeping the links ordered like this enables use to use O(n) algorithm
  // to find a unique index for a new link.
  // Example of list sorted in this order:
  // ["/lights", "/switch", "/lights/1", "/lights/2", "/lights/10"]
  oc_link_t *next = oc_list_head(col->links);
  oc_link_t *prev = NULL;
  while (next != NULL) {
    if ((next->resource != NULL) && (oc_string_len(next->resource->uri) > 0)) {
      // primary order by length
      if (link_uri.length < oc_string_len(next->resource->uri)) {
        break;
      }
      // secondary order by value
      if (link_uri.length == oc_string_len(next->resource->uri) &&
          strcmp(link_uri.data, oc_string(next->resource->uri)) < 0) {
        break;
      }
    }
    prev = next;
    next = next->next;
  }
  oc_list_insert(col->links, prev, link);
  if (link->resource == collection) {
    oc_string_array_add_item(link->rel, "self");
  }
  collection_notify_resource_changed(col, true);
}

bool
oc_collection_remove_link_and_notify(oc_resource_t *collection,
                                     const oc_link_t *link, bool notify,
                                     bool batchDispatch)
{
  if (collection == NULL || link == NULL) {
    return false;
  }
  oc_collection_t *col = (oc_collection_t *)collection;
  if (oc_list_remove2(col->links, link) == NULL) {
    return false;
  }
  if (notify) {
    collection_notify_resource_changed(col, batchDispatch);
  }
  return true;
}

void
oc_collection_remove_link(oc_resource_t *collection, const oc_link_t *link)
{
  oc_collection_remove_link_and_notify(collection, link, /*notify*/ true,
                                       /*batchDispatch*/ true);
}

oc_link_t *
oc_collection_get_links(oc_resource_t *collection)
{
  if (collection != NULL) {
    return (oc_link_t *)oc_list_head(((oc_collection_t *)collection)->links);
  }
  return NULL;
}

oc_collection_t *
oc_get_collection_by_uri(const char *uri_path, size_t uri_path_len,
                         size_t device)
{
  assert(uri_path != NULL);
  while (uri_path[0] == '/') {
    uri_path++;
    uri_path_len--;
  }
  oc_resource_t *collection = (oc_resource_t *)oc_list_head(g_collections);
  while (collection != NULL) {
    if (collection->device == device &&
        oc_string_len(collection->uri) == (uri_path_len + 1) &&
        strncmp(oc_string(collection->uri) + 1, uri_path, uri_path_len) == 0) {
      break;
    }
    collection = collection->next;
  }
  return (oc_collection_t *)collection;
}

oc_link_t *
oc_get_link_by_uri(oc_collection_t *collection, const char *uri_path,
                   size_t uri_path_len)
{
  if (collection == NULL || uri_path == NULL || uri_path_len == 0) {
    return NULL;
  }

  while (uri_path[0] == '/') {
    uri_path++;
    uri_path_len--;
  }

  oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
  for (; link != NULL; link = link->next) {
    if (link->resource == NULL) {
      continue;
    }
    const char *resource_uri = oc_string(link->resource->uri);
    size_t resource_uri_len = oc_string_len(link->resource->uri);
    while (resource_uri[0] == '/') {
      resource_uri++;
      resource_uri_len--;
    }
    if (resource_uri_len == uri_path_len &&
        strncmp(resource_uri, uri_path, uri_path_len) == 0) {
      return link;
    }
  }
  return NULL;
}

bool
oc_check_if_collection(const oc_resource_t *resource)
{
  oc_resource_t *collection = (oc_resource_t *)oc_list_head(g_collections);
  while (collection != NULL) {
    if (resource == collection) {
      return true;
    }
    collection = collection->next;
  }
  return false;
}

bool
oc_collection_add(oc_collection_t *collection)
{
  // check if collection already exists
  if (oc_check_if_collection((oc_resource_t *)collection)) {
    return false;
  }
  // check if URI is already in use
  if (oc_ri_URI_is_in_use(collection->res.device,
                          oc_string(collection->res.uri),
                          oc_string_len(collection->res.uri))) {
    return false;
  }
  oc_list_add(g_collections, collection);
  return true;
}

static bool
collection_is_known_rt(oc_list_t list, oc_string_view_t rtv)
{
  const oc_rt_t *rtt = (oc_rt_t *)oc_list_head(list);
  while (rtt != NULL) {
    if (oc_string_view_is_equal(rtv, oc_string_view2(&rtt->rt))) {
      return true;
    }
    rtt = rtt->next;
  }
  return false;
}

#ifdef OC_COLLECTIONS_IF_CREATE

static oc_rt_factory_t *
collection_get_rtfactory(oc_string_view_t rtv)
{
  oc_rt_factory_t *rf = (oc_rt_factory_t *)oc_list_head(g_rt_factories);
  while (rf != NULL) {
    if (oc_string_view_is_equal(rtv, oc_string_view2(&rf->rt))) {
      return rf;
    }
    rf = rf->next;
  }

  return NULL;
}

void
oc_collections_free_rt_factories(void)
{
  oc_fi_factory_free_all_created_resources();
  oc_rt_factory_t *rf = (oc_rt_factory_t *)oc_list_pop(g_rt_factories);
  while (rf != NULL) {
    oc_free_string(&rf->rt);
    oc_memb_free(&g_rts_s, rf);
    rf = (oc_rt_factory_t *)oc_list_pop(g_rt_factories);
  }
}

bool
oc_collections_add_rt_factory(const char *rt,
                              oc_resource_get_instance_t get_instance,
                              oc_resource_free_instance_t free_instance)
{
  oc_string_view_t rtv = oc_string_view(rt, strlen(rt));
  if (collection_get_rtfactory(rtv) != NULL) {
    return true;
  }

  oc_rt_factory_t *rf = (oc_rt_factory_t *)oc_memb_alloc(&g_rts_s);
  if (!rf) {
    return false;
  }

  oc_new_string(&rf->rt, rtv.data, rtv.length);
  rf->get_instance = get_instance;
  rf->free_instance = free_instance;
  oc_list_add(g_rt_factories, rf);

  return true;
}

static void
link_param_add(oc_string_view_t key, oc_string_view_t value)
{
  oc_link_params_t *p = oc_link_param_allocate(key, value);
  if (p == NULL) {
    return;
  }
  oc_list_add(g_params_list, p);
}

static void
link_params_free(void)
{
  oc_link_params_t *p = (oc_link_params_t *)oc_list_pop(g_params_list);
  while (p != NULL) {
    oc_link_param_free(p);
    p = (oc_link_params_t *)oc_list_pop(g_params_list);
  }
}

static bool
oc_handle_collection_create_request(oc_method_t method, oc_request_t *request)
{
  oc_collection_t *collection = (oc_collection_t *)request->resource;

  if (method == OC_GET) {
    oc_rep_start_root_object();
    oc_rep_end_root_object();
    return true;
  }

  if (method == OC_PUT || method == OC_POST) {
    const oc_rep_t *rep = request->request_payload;
    const oc_string_array_t *rt = NULL;
    oc_interface_mask_t interfaces = 0;
    oc_resource_properties_t bm = 0;
    const oc_rep_t *payload = NULL;
    while (rep) {
      switch (rep->type) {
      case OC_REP_STRING_ARRAY: {
        if (oc_string_len(rep->name) == 2 &&
            strncmp(oc_string(rep->name), "rt", 2) == 0) {
          rt = &rep->value.array;
        } else {
          for (size_t i = 0;
               i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
            interfaces |= oc_ri_get_interface_mask(
              oc_string_array_get_item(rep->value.array, i),
              oc_string_array_get_item_size(rep->value.array, i));
          }
        }
      } break;
      case OC_REP_OBJECT: {
        const oc_rep_t *obj = rep->value.object;
        if (obj && oc_string_len(rep->name) == 1 &&
            *(oc_string(rep->name)) == 'p' && obj->type == OC_REP_INT &&
            oc_string_len(obj->name) == 2 &&
            memcmp(oc_string(obj->name), "bm", 2) == 0) {
          bm = (oc_resource_properties_t)obj->value.integer;
        } else if (oc_string_len(rep->name) == 3 &&
                   memcmp(oc_string(rep->name), "rep", 3) == 0) {
          payload = obj;
        }
      } break;
      case OC_REP_STRING:
        /* Other arbitrary link parameters to be stored in the link to the
         * created resource.
         */
        link_param_add(oc_string_view2(&rep->name),
                       oc_string_view2(&rep->value.string));
        break;
      default:
        break;
      }
      rep = rep->next;
    }

    if (!rt || (interfaces == 0)) {
      goto error;
    }
#ifdef OC_SECURITY
    bm |= OC_SECURE;
#endif /* OC_SECURITY */
    const char *type_str = oc_string_array_get_item(*rt, 0);
    size_t type_str_len = oc_strnlen(type_str, STRING_ARRAY_ITEM_MAX_LEN);
    oc_string_view_t type = oc_string_view(type_str, type_str_len);
    bool is_rt_found =
      (oc_list_length(collection->supported_rts) > 0 &&
       collection_is_known_rt(collection->supported_rts, type)) ||
      (oc_list_length(collection->mandatory_rts) > 0 &&
       collection_is_known_rt(collection->mandatory_rts, type));
    if (!is_rt_found) {
      goto error;
    }
    oc_rt_factory_t *rf = collection_get_rtfactory(type);
    if (!rf) {
      goto error;
    }

    oc_rt_created_t *new_res = oc_rt_factory_create_resource(
      collection, rt, bm, interfaces, rf, request->resource->device);
    if (!new_res) {
      goto error;
    }
    if (!payload || !new_res->resource->set_properties.cb.set_props(
                      new_res->resource, payload,
                      new_res->resource->set_properties.user_data)) {
      oc_rt_factory_free_created_resource(new_res, rf);
      goto error;
    }

    CborEncoder encoder;
    oc_link_t *link = oc_new_link(new_res->resource);
    oc_collection_add_link((oc_resource_t *)collection, link);

    oc_rep_start_root_object();
    memcpy(&encoder, oc_rep_get_encoder(), sizeof(CborEncoder));
    oc_rep_set_text_string_v1(root, href, oc_string(new_res->resource->uri),
                              oc_string_len(new_res->resource->uri));
    oc_rep_set_string_array(root, rt, new_res->resource->types);
    oc_core_encode_interfaces_mask(oc_rep_object(root),
                                   new_res->resource->interfaces, false);
    oc_rep_set_object(root, p);
    oc_rep_set_uint(p, bm, (uint8_t)(bm & ~(OC_PERIODIC | OC_SECURE)));
    oc_rep_close_object(root, p);
    oc_rep_set_int(root, ins, link->ins);
    oc_rep_set_key(oc_rep_object(root), "rep");
    memcpy(oc_rep_get_encoder(), &root_map, sizeof(CborEncoder));
    oc_rep_start_root_object();
    new_res->resource->get_properties.cb.get_props(
      new_res->resource, OC_IF_BASELINE,
      new_res->resource->get_properties.user_data);
    oc_rep_end_root_object();
    memcpy(&root_map, oc_rep_get_encoder(), sizeof(CborEncoder));
    memcpy(oc_rep_get_encoder(), &encoder, sizeof(CborEncoder));

    oc_link_params_t *p = (oc_link_params_t *)oc_list_pop(g_params_list);
    while (p) {
      oc_rep_set_key_v1(oc_rep_object(root), oc_string(p->key),
                        oc_string_len(p->key));
      oc_rep_set_value_text_string_v1(root, oc_string(p->value),
                                      oc_string_len(p->value));
      oc_list_add(link->params, p);
      p = (oc_link_params_t *)oc_list_pop(g_params_list);
    }

    oc_rep_end_root_object();
#ifdef OC_SECURITY
    oc_sec_acl_add_created_resource_ace(
      oc_string(new_res->resource->uri), request->origin,
      request->resource->device,
      false); /* TODO: handle creation of Collections */
#endif        /* OC_SECURITY */

    return true;
  }

error:
  link_params_free();
  return false;
}
#endif /* OC_COLLECTIONS_IF_CREATE */

bool
oc_collection_add_supported_rt(oc_resource_t *collection, const char *rt)
{
  oc_collection_t *col = (oc_collection_t *)collection;
  oc_string_view_t rtv = oc_string_view(rt, strlen(rt));
  if (!collection_is_known_rt(col->supported_rts, rtv)) {
    oc_rt_t *rtt = (oc_rt_t *)oc_memb_alloc(&g_rtt_s);
    if (rtt == NULL) {
      OC_ERR("insufficient memory to add supported rt");
      return false;
    }
    oc_new_string(&rtt->rt, rtv.data, rtv.length);
    oc_list_add(col->supported_rts, rtt);
    return true;
  }
  return false;
}

bool
oc_collection_add_mandatory_rt(oc_resource_t *collection, const char *rt)
{
  oc_collection_t *col = (oc_collection_t *)collection;
  oc_string_view_t rtv = oc_string_view(rt, strlen(rt));
  if (!collection_is_known_rt(col->mandatory_rts, rtv)) {
    oc_rt_t *rtt = (oc_rt_t *)oc_memb_alloc(&g_rtt_s);
    if (rtt == NULL) {
      OC_ERR("insufficient memory to add mandatory rt");
      return false;
    }
    oc_new_string(&rtt->rt, rtv.data, rtv.length);
    oc_list_add(col->mandatory_rts, rtt);
    return true;
  }
  return false;
}

oc_collection_t *
oc_get_next_collection_with_link(const oc_resource_t *resource,
                                 oc_collection_t *start)
{
  oc_collection_t *collection = start;

  if (!collection) {
    collection = oc_collection_get_all();
  } else {
    collection = (oc_collection_t *)collection->res.next;
  }

  while (collection != NULL && collection->res.device == resource->device) {
    const oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
    while (link != NULL) {
      if (link->resource == resource) {
        return collection;
      }
      link = link->next;
    }
    collection = (oc_collection_t *)collection->res.next;
  }

  return collection;
}

typedef struct oc_handle_collection_request_result_t
{
  bool ok;
  coap_status_t ecode;
  coap_status_t pcode;
} oc_handle_collection_request_result_t;

static bool
collection_encode_supported_rts(const oc_collection_t *collection)
{
  if (oc_list_length(collection->supported_rts) == 0) {
    return true;
  }
  oc_rep_open_array(root, rts);
  const oc_rt_t *rtt = (oc_rt_t *)oc_list_head(collection->supported_rts);
  while (rtt != NULL) {
    oc_rep_add_text_string_v1(rts, oc_string(rtt->rt), oc_string_len(rtt->rt));
    rtt = rtt->next;
  }
  oc_rep_close_array(root, rts);
  return g_err == CborNoError;
}

static bool
collection_encode_mandatory_rts(const oc_collection_t *collection)
{
  if (oc_list_length(collection->mandatory_rts) == 0) {
    return true;
  }
  oc_rep_set_key(oc_rep_object(root), "rts-m");
  oc_rep_start_array(oc_rep_object(root), rtsm);
  const oc_rt_t *rtt = (oc_rt_t *)oc_list_head(collection->mandatory_rts);
  while (rtt != NULL) {
    oc_rep_add_text_string_v1(rtsm, oc_string(rtt->rt), oc_string_len(rtt->rt));
    rtt = rtt->next;
  }
  oc_rep_end_array(oc_rep_object(root), rtsm);
  return g_err == CborNoError;
}

static bool
collection_encode_links(const oc_collection_t *collection,
                        const oc_request_t *request)
{
  oc_rep_set_array(root, links);
  for (const oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
       link != NULL; link = link->next) {
    if (!oc_filter_resource_by_rt(link->resource, request)) {
      continue;
    }
    oc_rep_object_array_start_item(links);
    oc_rep_set_text_string_v1(links, href, oc_string(link->resource->uri),
                              oc_string_len(link->resource->uri));
    oc_rep_set_string_array(links, rt, link->resource->types);
    oc_core_encode_interfaces_mask(oc_rep_object(links), link->interfaces,
                                   false);
    oc_rep_set_string_array(links, rel, link->rel);
    oc_rep_set_int(links, ins, link->ins);
    oc_link_params_t *p = (oc_link_params_t *)oc_list_head(link->params);
    while (p) {
      oc_rep_set_key_v1(oc_rep_object(links), oc_string(p->key),
                        oc_string_len(p->key));
      oc_rep_set_value_text_string_v1(links, oc_string(p->value),
                                      oc_string_len(p->value));
      p = p->next;
    }
    oc_rep_set_object(links, p);
    oc_rep_set_uint(
      p, bm,
      (uint8_t)(link->resource->properties & ~(OC_PERIODIC | OC_SECURE)));
    oc_rep_close_object(links, p);

    // tag-pos-desc
    if (link->resource->tag_pos_desc > 0) {
      const char *desc = oc_enum_pos_desc_to_str(link->resource->tag_pos_desc);
      if (desc) {
        // clang-format off
        oc_rep_set_text_string(links, tag-pos-desc, desc);
        // clang-format on
      }
    }

    // tag-func-desc
    if (link->resource->tag_func_desc > 0) {
      const char *func = oc_enum_to_str(link->resource->tag_func_desc);
      if (func) {
        // clang-format off
        oc_rep_set_text_string(links, tag-func-desc, func);
        // clang-format on
      }
    }

    // tag-pos-rel
    const double *pos = link->resource->tag_pos_rel;
    if (pos[0] != 0 || pos[1] != 0 || pos[2] != 0) {
      oc_rep_set_key(oc_rep_object(links), "tag-pos-rel");
      oc_rep_start_array(oc_rep_object(links), tag_pos_rel);
      oc_rep_add_double(tag_pos_rel, pos[0]);
      oc_rep_add_double(tag_pos_rel, pos[1]);
      oc_rep_add_double(tag_pos_rel, pos[2]);
      oc_rep_end_array(oc_rep_object(links), tag_pos_rel);
    }

    // eps
    oc_rep_set_array(links, eps);
    oc_endpoint_t *eps = oc_connectivity_get_endpoints(link->resource->device);
    for (; eps != NULL; eps = eps->next) {
      if (oc_filter_out_ep_for_resource(eps, link->resource, request->origin,
                                        link->resource->device, false)) {
        continue;
      }
      oc_rep_object_array_start_item(eps);
      oc_string64_t ep;
      if (oc_endpoint_to_string64(eps, &ep)) {
        oc_rep_set_text_string_v1(eps, ep, oc_string(ep), oc_string_len(ep));
      }
      oc_rep_object_array_end_item(eps);
    }
    oc_rep_close_array(links, eps);

    oc_rep_object_array_end_item(links);
  }
  oc_rep_close_array(root, links);
  return g_err == CborNoError;
}

OC_NO_DISCARD_RETURN
static oc_handle_collection_request_result_t
oc_handle_collection_baseline_request(oc_method_t method, oc_request_t *request)
{
  oc_collection_t *collection = (oc_collection_t *)request->resource;
  coap_status_t ecode = oc_status_code_unsafe(OC_STATUS_OK);
  coap_status_t pcode = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST);
  if (method == OC_PUT || method == OC_POST) {
    if (collection->res.set_properties.cb.set_props == NULL) {
      OC_ERR("internal collection error: set properties callback not set");
      oc_handle_collection_request_result_t result = { false, ecode, pcode };
      return result;
    }
    bool ok = collection->res.set_properties.cb.set_props(
      &collection->res, request->request_payload,
      collection->res.set_properties.user_data);
    if (!ok) {
      OC_ERR("set properties callback failed");
    }
    oc_handle_collection_request_result_t result = { ok, ecode, pcode };
    return result;
  }

  if (method == OC_GET) {
    oc_rep_start_root_object();

    oc_process_baseline_interface(request->resource);

    /* rts */
    collection_encode_supported_rts(collection);

    /* rts-m */
    collection_encode_mandatory_rts(collection);

    /* links */
    collection_encode_links(collection, request);

    /* custom properties */
    if (collection->res.get_properties.cb.get_props != NULL) {
      collection->res.get_properties.cb.get_props(
        &collection->res, OC_IF_BASELINE,
        collection->res.get_properties.user_data);
    }
    oc_rep_end_root_object();
    pcode = ecode = oc_status_code_unsafe(OC_STATUS_OK);
  }

  oc_handle_collection_request_result_t result = {
    .ok = true,
    .ecode = ecode,
    .pcode = pcode,
  };
  return result;
}

static void
oc_handle_collection_linked_list_request(oc_request_t *request)
{
  const oc_collection_t *collection = (oc_collection_t *)request->resource;
  oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
  oc_rep_start_links_array();
  while (link != NULL) {
    if (oc_filter_resource_by_rt(link->resource, request)) {
      oc_rep_object_array_start_item(links);
      oc_rep_set_text_string_v1(links, href, oc_string(link->resource->uri),
                                oc_string_len(link->resource->uri));
      oc_rep_set_string_array(links, rt, link->resource->types);
      oc_core_encode_interfaces_mask(oc_rep_object(links), link->interfaces,
                                     false);
      oc_rep_set_string_array(links, rel, link->rel);
      oc_rep_set_int(links, ins, link->ins);
      oc_link_params_t *p = (oc_link_params_t *)oc_list_head(link->params);
      while (p) {
        oc_rep_set_key_v1(oc_rep_object(links), oc_string(p->key),
                          oc_string_len(p->key));
        oc_rep_set_value_text_string_v1(links, oc_string(p->value),
                                        oc_string_len(p->value));
        p = p->next;
      }
      oc_rep_set_object(links, p);
      oc_rep_set_uint(
        p, bm,
        (uint8_t)(link->resource->properties & ~(OC_PERIODIC | OC_SECURE)));
      oc_rep_close_object(links, p);

      // tag-pos-desc
      if (link->resource->tag_pos_desc > 0) {
        const char *desc =
          oc_enum_pos_desc_to_str(link->resource->tag_pos_desc);
        if (desc) {
          // clang-format off
          oc_rep_set_text_string(links, tag-pos-desc, desc);
          // clang-format on
        }
      }

      // tag-func-desc
      if (link->resource->tag_func_desc > 0) {
        const char *func = oc_enum_to_str(link->resource->tag_func_desc);
        if (func) {
          // clang-format off
          oc_rep_set_text_string(links, tag-func-desc, func);
          // clang-format on
        }
      }

      // tag-pos-rel
      const double *pos = link->resource->tag_pos_rel;
      if (pos[0] != 0 || pos[1] != 0 || pos[2] != 0) {
        oc_rep_set_key(oc_rep_object(links), "tag-pos-rel");
        oc_rep_start_array(oc_rep_object(links), tag_pos_rel);
        oc_rep_add_double(tag_pos_rel, pos[0]);
        oc_rep_add_double(tag_pos_rel, pos[1]);
        oc_rep_add_double(tag_pos_rel, pos[2]);
        oc_rep_end_array(oc_rep_object(links), tag_pos_rel);
      }

      // eps
      oc_rep_set_array(links, eps);
      oc_endpoint_t *eps =
        oc_connectivity_get_endpoints(link->resource->device);
      for (; eps != NULL; eps = eps->next) {
        if (oc_filter_out_ep_for_resource(eps, link->resource, request->origin,
                                          link->resource->device, false)) {
          continue;
        }
        oc_rep_object_array_start_item(eps);
        oc_string64_t ep;
        if (oc_endpoint_to_string64(eps, &ep)) {
          oc_rep_set_text_string_v1(eps, ep, oc_string(ep), oc_string_len(ep));
        }
        oc_rep_object_array_end_item(eps);
      }
      oc_rep_close_array(links, eps);

      oc_rep_object_array_end_item(links);
    }
    link = link->next;
  }
  oc_rep_end_links_array();
}

OC_NO_DISCARD_RETURN
static oc_handle_collection_request_result_t
oc_handle_collection_batch_request(oc_method_t method, oc_request_t *request,
                                   const oc_resource_t *notify_resource)
{
  assert(request != NULL);
  coap_status_t ecode = oc_status_code_unsafe(OC_STATUS_OK);
  coap_status_t pcode = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST);
  CborEncoder encoder;
  CborEncoder prev_link;
  oc_request_t rest_request;
  memset(&rest_request, 0, sizeof(oc_request_t));
  oc_response_t response;
  memset(&response, 0, sizeof(oc_response_t));
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(oc_response_buffer_t));
  bool method_not_found = false;
  bool get_delete = false;
  const oc_rep_t *rep = request->request_payload;
  const oc_string_t *href = NULL;
  const oc_collection_t *collection = (oc_collection_t *)request->resource;
  oc_link_t *link = NULL;

  response.response_buffer = &response_buffer;
  rest_request.response = &response;
  rest_request.origin = request->origin;
  rest_request.method = method;

  oc_rep_start_links_array();
  memcpy(&encoder, oc_rep_get_encoder(), sizeof(CborEncoder));
  if (method == OC_GET || method == OC_DELETE) {
    get_delete = true;
  }

  if (get_delete) {
    goto process_request;
  }

  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_OBJECT: {
      href = NULL;
      const oc_rep_t *pay = rep->value.object;
      while (pay != NULL) {
        switch (pay->type) {
        case OC_REP_STRING:
          href = &pay->value.string;
          break;
        case OC_REP_OBJECT:
          rest_request.request_payload = pay->value.object;
          break;
        default:
          break;
        }
        pay = pay->next;
      }
      if (href == NULL || oc_string_len(*href) == 0) {
        ecode = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST);
        goto processed_request;
      }
    process_request:
      link = (oc_link_t *)oc_list_head(collection->links);
      while (link != NULL) {
        if (link->resource &&
            (!notify_resource == !(link->resource == notify_resource))) {
          if (oc_filter_resource_by_rt(link->resource, request)) {
            if (!get_delete && href && oc_string_len(*href) > 0 &&
                (oc_string_len(*href) != oc_string_len(link->resource->uri) ||
                 memcmp(oc_string(*href), oc_string(link->resource->uri),
                        oc_string_len(*href)) != 0)) {
              goto next;
            }
            memcpy(&prev_link, &links_array, sizeof(CborEncoder));
            oc_rep_object_array_start_item(links);

            rest_request.query = 0;
            rest_request.query_len = 0;

            oc_rep_set_text_string_v1(links, href,
                                      oc_string(link->resource->uri),
                                      oc_string_len(link->resource->uri));
            oc_rep_set_key(oc_rep_object(links), "rep");
            memcpy(oc_rep_get_encoder(), &links_map, sizeof(CborEncoder));

            int size_before = oc_rep_get_encoded_payload_size();
            rest_request.resource = link->resource;
            response_buffer.code = 0;
            response_buffer.response_length = 0;
            method_not_found = false;
#ifdef OC_SECURITY
            if (request->origin != NULL &&
                !oc_sec_check_acl(method, link->resource, request->origin)) {
              response_buffer.code = oc_status_code_unsafe(OC_STATUS_FORBIDDEN);
            } else
#endif /* OC_SECURITY */
            {
              if ((link->resource != (oc_resource_t *)collection) &&
                  oc_check_if_collection(link->resource)) {
                request->resource = link->resource;
                if (!oc_handle_collection_request(
                      method, request, link->resource->default_interface,
                      NULL)) {
                  oc_handle_collection_request_result_t res = {
                    .ok = false,
                    .ecode = oc_status_code_unsafe(OC_STATUS_OK),
                    .pcode = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST),
                  };
                  return res;
                }
                request->resource = (oc_resource_t *)collection;
              } else {
                oc_interface_mask_t req_iface =
                  link->resource->default_interface;
                if (link->resource == (oc_resource_t *)collection) {
                  req_iface = OC_IF_BASELINE;
                }
                switch (method) {
                case OC_GET:
                  if (link->resource->get_handler.cb)
                    link->resource->get_handler.cb(
                      &rest_request, req_iface,
                      link->resource->get_handler.user_data);
                  else
                    method_not_found = true;
                  break;
                case OC_PUT:
                  if (link->resource->put_handler.cb)
                    link->resource->put_handler.cb(
                      &rest_request, req_iface,
                      link->resource->put_handler.user_data);
                  else
                    method_not_found = true;
                  break;
                case OC_POST:
                  if (link->resource->post_handler.cb)
                    link->resource->post_handler.cb(
                      &rest_request, req_iface,
                      link->resource->post_handler.user_data);
                  else
                    method_not_found = true;
                  break;
                case OC_DELETE:
                  if (link->resource->delete_handler.cb)
                    link->resource->delete_handler.cb(
                      &rest_request, req_iface,
                      link->resource->delete_handler.user_data);
                  else
                    method_not_found = true;
                  break;
                default:
                  break;
                }
              }
            }
            if (method_not_found) {
              ecode = oc_status_code_unsafe(OC_STATUS_METHOD_NOT_ALLOWED);
              memcpy(&links_array, &prev_link, sizeof(CborEncoder));
              goto next;
            } else {
              if ((method == OC_PUT || method == OC_POST) &&
                  response_buffer.code <
                    oc_status_code_unsafe(OC_STATUS_BAD_REQUEST)) {
              }
              if (response_buffer.code <
                  oc_status_code_unsafe(OC_STATUS_BAD_REQUEST)) {
                pcode = response_buffer.code;
              } else {
                ecode = response_buffer.code;
              }
              int size_after = oc_rep_get_encoded_payload_size();
              if (size_before == size_after) {
                oc_rep_start_root_object();
                oc_rep_end_root_object();
              }
            }

            memcpy(&links_map, oc_rep_get_encoder(), sizeof(CborEncoder));
            oc_rep_object_array_end_item(links);
          }
        }
      next:
        link = link->next;
      }
      if (get_delete) {
        goto processed_request;
      }
    } break;
    default:
      ecode = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST);
      goto processed_request;
    }
    rep = rep->next;
  }
processed_request:
  memcpy(oc_rep_get_encoder(), &encoder, sizeof(CborEncoder));
  oc_rep_end_links_array();

  oc_handle_collection_request_result_t result = {
    .ok = true,
    .ecode = ecode,
    .pcode = pcode,
  };
  return result;
}

bool
oc_handle_collection_request(oc_method_t method, oc_request_t *request,
                             oc_interface_mask_t iface_mask,
                             const oc_resource_t *notify_resource)
{
  coap_status_t ecode = oc_status_code_unsafe(OC_STATUS_OK);
  coap_status_t pcode = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST);
  switch (iface_mask) {
#ifdef OC_COLLECTIONS_IF_CREATE
  case OC_IF_CREATE:
    if (oc_handle_collection_create_request(method, request)) {
      pcode = ecode = oc_status_code_unsafe(OC_STATUS_OK);
    } else {
      pcode = ecode = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST);
    }
    break;
#endif /* OC_COLLECTIONS_IF_CREATE */
  case OC_IF_BASELINE: {
    oc_handle_collection_request_result_t res =
      oc_handle_collection_baseline_request(method, request);
    if (!res.ok) {
      return false;
    }
    pcode = res.pcode;
    ecode = res.ecode;
    break;
  }
  case OC_IF_LL:
    oc_handle_collection_linked_list_request(request);
    pcode = ecode = oc_status_code_unsafe(OC_STATUS_OK);
    break;
  case OC_IF_B: {
    oc_handle_collection_request_result_t res =
      oc_handle_collection_batch_request(method, request, notify_resource);
    if (!res.ok) {
      return false;
    }
    pcode = res.pcode;
    ecode = res.ecode;
    break;
  }
  default:
    break;
  }

  oc_collection_t *collection = (oc_collection_t *)request->resource;
  int size = oc_rep_get_encoded_payload_size();
  if (size == -1) {
    OC_ERR("failed to handle collection(%s) request: payload too large",
           oc_string_len(collection->res.uri) > 0
             ? oc_string(collection->res.uri)
             : "");
    return false;
  }

  oc_status_t code = OC_STATUS_BAD_REQUEST;
  if (ecode < oc_status_code_unsafe(OC_STATUS_BAD_REQUEST) &&
      pcode < oc_status_code_unsafe(OC_STATUS_BAD_REQUEST)) {
    switch (method) {
    case OC_GET:
      code = OC_STATUS_OK;
      break;
    case OC_POST:
    case OC_PUT:
      if (iface_mask == OC_IF_CREATE) {
        code = OC_STATUS_CREATED;
      } else {
        code = OC_STATUS_CHANGED;
      }
      break;
    case OC_DELETE:
      code = OC_STATUS_DELETED;
      break;
    default:
      break;
    }
  }
  oc_send_response_internal(request, code, APPLICATION_VND_OCF_CBOR, size,
                            true);

  coap_status_t status_code = oc_status_code_unsafe(code);
  if ((method == OC_PUT || method == OC_POST) &&
      status_code < oc_status_code_unsafe(OC_STATUS_BAD_REQUEST)) {
    if (iface_mask == OC_IF_CREATE) {
      coap_notify_collection_observers(
        collection, request->response->response_buffer, iface_mask);
    } else if (iface_mask == OC_IF_B) {
      oc_reset_delayed_callback(collection, collection_notify_batch_async, 0);
    }
  }

  return true;
}

#ifdef OC_HAS_FEATURE_ETAG

uint64_t
oc_collection_get_batch_etag(const oc_collection_t *collection)
{
  // TODO: finish this
#if 0
  uint64_t etag = collection->res.etag;
  // TODO: check oc_handle_collection_batch_request, some links may be skipped
  for (const oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
       link; link = link->next) {
    if (link->resource->etag > etag) {
      etag = link->resource->etag;
    }
  }
  return etag;
#endif
  (void)collection;
  return OC_ETAG_UNINITIALIZED;
}

#endif /* OC_HAS_FEATURE_ETAG */

oc_collection_t *
oc_collection_get_all(void)
{
  return (oc_collection_t *)oc_list_head(g_collections);
}

#endif /* OC_COLLECTIONS && OC_SERVER */
