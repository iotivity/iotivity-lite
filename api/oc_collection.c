/*
// Copyright (c) 2016-2019 Intel Corporation
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

#include "oc_collection.h"

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "messaging/coap/observe.h"
#include "oc_api.h"
#include "oc_core_res.h"
#ifdef OC_COLLECTIONS_IF_CREATE
#include "api/oc_resource_factory.h"
#endif /* OC_COLLECTIONS_IF_CREATE */
#include "util/oc_memb.h"
#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#endif /* OC_SECURITY */

OC_MEMB(oc_collections_s, oc_collection_t, OC_MAX_NUM_COLLECTIONS);
OC_LIST(oc_collections);
/* Allocator for links */
OC_MEMB(oc_links_s, oc_link_t, OC_MAX_APP_RESOURCES);
/* Allocator for oc_rtt_t */
OC_MEMB(rtt_s, oc_rt_t, 1);
/* Allocator for link parameters */
OC_MEMB(oc_params_s, oc_link_params_t, 1);
#ifdef OC_COLLECTIONS_IF_CREATE
/* Allocator for resource factories */
OC_MEMB(rts_s, oc_rt_factory_t, 1);
OC_LIST(rt_factories);
OC_LIST(params_list);
#endif /* OC_COLLECTIONS_IF_CREATE */

oc_collection_t *
oc_collection_alloc(void)
{
  oc_collection_t *collection = oc_memb_alloc(&oc_collections_s);
  if (collection) {
    OC_LIST_STRUCT_INIT(collection, supported_rts);
    OC_LIST_STRUCT_INIT(collection, mandatory_rts);
    OC_LIST_STRUCT_INIT(collection, links);
    return collection;
  }
  OC_WRN("insufficient memory to create new collection");
  return NULL;
}

void
oc_collection_free(oc_collection_t *collection)
{
  if (collection != NULL) {
    oc_list_remove(oc_collections, collection);
    oc_ri_free_resource_properties((oc_resource_t *)collection);

    oc_link_t *link;
    while ((link = oc_list_pop(collection->links)) != NULL) {
      oc_delete_link(link);
    }

    if (oc_list_length(collection->supported_rts) > 0) {
      oc_rt_t *rtt = (oc_rt_t *)oc_list_pop(collection->supported_rts);
      while (rtt) {
        oc_free_string(&rtt->rt);
        oc_memb_free(&rtt_s, rtt);
        rtt = (oc_rt_t *)oc_list_pop(collection->supported_rts);
      }
    }

    if (oc_list_length(collection->mandatory_rts) > 0) {
      oc_rt_t *rtt = (oc_rt_t *)oc_list_pop(collection->mandatory_rts);
      while (rtt) {
        oc_free_string(&rtt->rt);
        oc_memb_free(&rtt_s, rtt);
        rtt = (oc_rt_t *)oc_list_pop(collection->mandatory_rts);
      }
    }

    oc_memb_free(&oc_collections_s, collection);
  }
}

oc_link_t *
oc_new_link(oc_resource_t *resource)
{
  if (resource) {
    oc_link_t *link = oc_memb_alloc(&oc_links_s);
    if (link) {
      oc_new_string_array(&link->rel, 3);
      oc_string_array_add_item(link->rel, "hosts");
      link->resource = resource;
      resource->num_links++;
      link->next = 0;
      link->ins = (int64_t)oc_random_value();
      OC_LIST_STRUCT_INIT(link, params);
      return link;
    }
    OC_WRN("insufficient memory to create new link");
  }
  return NULL;
}

void
oc_delete_link(oc_link_t *link)
{
  if (link) {
    oc_link_params_t *p = (oc_link_params_t *)oc_list_pop(link->params);
    while (p) {
      oc_free_string(&p->key);
      oc_free_string(&p->value);
      oc_memb_free(&oc_params_s, p);
      p = (oc_link_params_t *)oc_list_pop(link->params);
    }
    if (link->resource) {
      link->resource->num_links--;
    }
    oc_free_string_array(&(link->rel));
    oc_memb_free(&oc_links_s, link);
  }
}

static oc_event_callback_retval_t
links_list_notify_collection(void *data)
{
  coap_notify_links_list(data);
  return OC_EVENT_DONE;
}

void
oc_collection_add_link(oc_resource_t *collection, oc_link_t *link)
{
  oc_collection_t *c = (oc_collection_t *)collection;
  oc_list_add(c->links, link);
  if (link->resource == collection) {
    oc_string_array_add_item(link->rel, "self");
  }
  oc_set_delayed_callback(collection, links_list_notify_collection, 0);
}

void
oc_collection_remove_link(oc_resource_t *collection, oc_link_t *link)
{
  if (collection && link) {
    oc_collection_t *c = (oc_collection_t *)collection;
    oc_list_remove(c->links, link);
    oc_set_delayed_callback(collection, links_list_notify_collection, 0);
  }
}

oc_link_t *
oc_collection_get_links(oc_resource_t *collection)
{
  if (collection)
    return (oc_link_t *)oc_list_head(((oc_collection_t *)collection)->links);
  return NULL;
}

void
oc_link_add_rel(oc_link_t *link, const char *rel)
{
  if (link) {
    oc_string_array_add_item(link->rel, rel);
  }
}

void
oc_link_add_link_param(oc_link_t *link, const char *key, const char *value)
{
  if (link) {
    oc_link_params_t *p = oc_memb_alloc(&oc_params_s);
    if (p) {
      oc_new_string(&p->key, key, strlen(key));
      oc_new_string(&p->value, value, strlen(value));
      oc_list_add(link->params, p);
    }
  }
}

oc_collection_t *
oc_get_collection_by_uri(const char *uri_path, size_t uri_path_len,
                         size_t device)
{
  while (uri_path[0] == '/') {
    uri_path++;
    uri_path_len--;
  }
  oc_collection_t *collection = oc_list_head(oc_collections);
  while (collection != NULL) {
    if (oc_string_len(collection->uri) == (uri_path_len + 1) &&
        strncmp(oc_string(collection->uri) + 1, uri_path, uri_path_len) == 0 &&
        collection->device == device)
      break;
    collection = collection->next;
  }
  return collection;
}

oc_link_t *
oc_get_link_by_uri(oc_collection_t *collection, const char *uri_path,
                   int uri_path_len)
{
  oc_link_t *link = NULL;

  if (collection && uri_path && uri_path_len > 0) {
    while (uri_path[0] == '/') {
      uri_path++;
      uri_path_len--;
    }

    link = oc_list_head(collection->links);
    while (link != NULL) {
      if (link->resource &&
          (int)oc_string_len(link->resource->uri) == (uri_path_len + 1) &&
          strncmp(oc_string(link->resource->uri) + 1, uri_path, uri_path_len) ==
            0) {
        break;
      }
      link = link->next;
    }
  }

  return link;
}

bool
oc_check_if_collection(oc_resource_t *resource)
{
  oc_collection_t *collection = oc_list_head(oc_collections);
  while (collection != NULL) {
    if ((oc_collection_t *)resource == collection)
      return true;
    collection = collection->next;
  }
  return false;
}

void
oc_collection_add(oc_collection_t *collection)
{
  oc_list_add(oc_collections, collection);
}

static oc_rt_t *
is_known_rt(oc_list_t list, const char *rt)
{
  oc_rt_t *rtt = (oc_rt_t *)oc_list_head(list);
  while (rtt) {
    if (strlen(rt) == oc_string_len(rtt->rt) &&
        memcmp(rt, oc_string(rtt->rt), strlen(rt)) == 0) {
      return rtt;
    }
    rtt = rtt->next;
  }

  return NULL;
}

#ifdef OC_COLLECTIONS_IF_CREATE
static oc_rt_factory_t *
is_known_rtfactory(const char *rt)
{
  oc_rt_factory_t *rf = (oc_rt_factory_t *)oc_list_head(rt_factories);
  while (rf) {
    if (strlen(rt) == oc_string_len(rf->rt) &&
        memcmp(rt, oc_string(rf->rt), strlen(rt)) == 0) {
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
  oc_rt_factory_t *rf = (oc_rt_factory_t *)oc_list_pop(rt_factories);
  while (rf) {
    oc_free_string(&rf->rt);
    oc_memb_free(&rts_s, rf);
    rf = (oc_rt_factory_t *)oc_list_pop(rt_factories);
  }
}

bool
oc_collections_add_rt_factory(const char *rt,
                              oc_resource_get_instance_t get_instance,
                              oc_resource_free_instance_t free_instance)
{
  if (is_known_rtfactory(rt)) {
    return true;
  }

  oc_rt_factory_t *rf = (oc_rt_factory_t *)oc_memb_alloc(&rts_s);
  if (!rf) {
    return false;
  }

  oc_new_string(&rf->rt, rt, strlen(rt));
  rf->get_instance = get_instance;
  rf->free_instance = free_instance;
  oc_list_add(rt_factories, rf);

  return true;
}

static void
add_link_param(const char *key, const char *value)
{
  oc_link_params_t *p = oc_memb_alloc(&oc_params_s);

  if (p) {
    oc_new_string(&p->key, key, strlen(key));
    oc_new_string(&p->value, value, strlen(value));
    oc_list_add(params_list, p);
  }
}
#endif /* OC_COLLECTIONS_IF_CREATE */

bool
oc_collection_add_supported_rt(oc_resource_t *collection, const char *rt)
{
  oc_collection_t *col = (oc_collection_t *)collection;
  if (!is_known_rt(col->supported_rts, rt)) {
    oc_rt_t *rtt = (oc_rt_t *)oc_memb_alloc(&rtt_s);
    if (rtt) {
      oc_new_string(&rtt->rt, rt, strlen(rt));
      oc_list_add(col->supported_rts, rtt);
      return true;
    }
  }
  return false;
}

bool
oc_collection_add_mandatory_rt(oc_resource_t *collection, const char *rt)
{
  oc_collection_t *col = (oc_collection_t *)collection;
  if (!is_known_rt(col->mandatory_rts, rt)) {
    oc_rt_t *rtt = (oc_rt_t *)oc_memb_alloc(&rtt_s);
    if (rtt) {
      oc_new_string(&rtt->rt, rt, strlen(rt));
      oc_list_add(col->mandatory_rts, rtt);
      return true;
    }
  }
  return false;
}

oc_collection_t *
oc_get_next_collection_with_link(oc_resource_t *resource,
                                 oc_collection_t *start)
{
  oc_collection_t *collection = start;

  if (!collection) {
    collection = oc_collection_get_all();
  } else {
    collection = collection->next;
  }

  while (collection && collection->device == resource->device) {
    oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
    while (link) {
      if (link->resource == resource) {
        return collection;
      }
      link = link->next;
    }
    collection = collection->next;
  }

  return collection;
}

static oc_event_callback_retval_t
batch_notify_collection_for_link(void *data)
{
  coap_notify_observers(data, NULL, NULL);
  return OC_EVENT_DONE;
}

bool
oc_handle_collection_request(oc_method_t method, oc_request_t *request,
                             oc_interface_mask_t iface_mask,
                             oc_resource_t *notify_resource)
{
  int ecode = oc_status_code(OC_STATUS_OK);
  int pcode = oc_status_code(OC_STATUS_BAD_REQUEST);
  oc_collection_t *collection = (oc_collection_t *)request->resource;
  oc_link_t *link = oc_list_head(collection->links);
  switch (iface_mask) {
#ifdef OC_COLLECTIONS_IF_CREATE
  case OC_IF_CREATE: {
    bool bad_request = false;
    if (method == OC_PUT || method == OC_POST) {
      oc_rep_t *rep = request->request_payload;
      oc_string_array_t *rt = NULL;
      oc_interface_mask_t interfaces = 0;
      oc_resource_properties_t bm = 0;
      oc_rep_t *payload = NULL;
      while (rep) {
        switch (rep->type) {
        case OC_REP_STRING_ARRAY: {
          size_t i;
          if (oc_string_len(rep->name) == 2 &&
              strncmp(oc_string(rep->name), "rt", 2) == 0) {
            rt = &rep->value.array;
          } else {
            for (i = 0;
                 i < oc_string_array_get_allocated_size(rep->value.array);
                 i++) {
              interfaces |= oc_ri_get_interface_mask(
                oc_string_array_get_item(rep->value.array, i),
                oc_string_array_get_item_size(rep->value.array, i));
            }
          }
        } break;
        case OC_REP_OBJECT: {
          oc_rep_t *obj = rep->value.object;
          if (obj && oc_string_len(rep->name) == 1 &&
              *(oc_string(rep->name)) == 'p' && obj->type == OC_REP_INT &&
              oc_string_len(obj->name) == 2 &&
              memcmp(oc_string(obj->name), "bm", 2) == 0) {
            bm = obj->value.integer;
          } else if (oc_string_len(rep->name) == 3 &&
                     memcmp(oc_string(rep->name), "rep", 3) == 0) {
            payload = obj;
          }
        } break;
        case OC_REP_STRING:
          /* Other arbitrary link parameters to be stored in the link to the
           * created resource.
           */
          add_link_param(oc_string(rep->name), oc_string(rep->value.string));
          break;
        default:
          break;
        }
        rep = rep->next;
      }

      if (rt && (interfaces != 0)) {
#ifdef OC_SECURITY
        bm |= OC_SECURE;
#endif /* OC_SECURITY */
        const char *type = oc_string_array_get_item(*rt, 0);
        oc_rt_factory_t *rf = NULL;
        if (oc_list_length(collection->supported_rts) > 0 &&
            is_known_rt(collection->supported_rts, type)) {
          rf = is_known_rtfactory(type);
          if (!rf) {
            bad_request = true;
          }
        } else if (oc_list_length(collection->mandatory_rts) > 0 &&
                   is_known_rt(collection->mandatory_rts, type)) {
          rf = is_known_rtfactory(type);
          if (!rf) {
            bad_request = true;
          }
        } else {
          bad_request = true;
        }

        if (!bad_request) {
          oc_rt_created_t *new_res = oc_rt_factory_create_resource(
            collection, rt, bm, interfaces, rf, request->resource->device);
          if (new_res) {
            if (!payload || !new_res->resource->set_properties.cb.set_props(
                              new_res->resource, payload,
                              new_res->resource->set_properties.user_data)) {
              oc_rt_factory_free_created_resource(new_res, rf);
              bad_request = true;
            }

            if (!bad_request) {
              CborEncoder encoder;
              oc_link_t *link = oc_new_link(new_res->resource);
              oc_collection_add_link((oc_resource_t *)collection, link);

              oc_rep_start_root_object();
              memcpy(&encoder, &g_encoder, sizeof(CborEncoder));
              oc_rep_set_text_string(root, href,
                                     oc_string(new_res->resource->uri));
              oc_rep_set_string_array(root, rt, new_res->resource->types);
              oc_core_encode_interfaces_mask(oc_rep_object(root),
                                             new_res->resource->interfaces);
              oc_rep_set_object(root, p);
              oc_rep_set_uint(p, bm,
                              (uint8_t)(bm & ~(OC_PERIODIC | OC_SECURE)));
              oc_rep_close_object(root, p);
              oc_rep_set_int(root, ins, link->ins);
              oc_rep_set_key(oc_rep_object(root), "rep");
              memcpy(&g_encoder, &root_map, sizeof(CborEncoder));
              oc_rep_start_root_object();
              new_res->resource->get_properties.cb.get_props(
                new_res->resource, OC_IF_BASELINE,
                new_res->resource->get_properties.user_data);
              oc_rep_end_root_object();
              memcpy(&root_map, &g_encoder, sizeof(CborEncoder));
              memcpy(&g_encoder, &encoder, sizeof(CborEncoder));

              oc_link_params_t *p =
                (oc_link_params_t *)oc_list_pop(params_list);
              while (p) {
                oc_rep_set_key(oc_rep_object(root), oc_string(p->key));
                oc_rep_set_value_text_string(root, oc_string(p->value));
                oc_list_add(link->params, p);
                p = (oc_link_params_t *)oc_list_pop(params_list);
              }

              oc_rep_end_root_object();

#ifdef OC_SECURITY
              oc_sec_acl_add_created_resource_ace(
                oc_string(new_res->resource->uri), request->origin,
                request->resource->device,
                false); /* TODO: handle creation of Collections */
#endif                  /* OC_SECURITY */
            }
          } else {
            bad_request = true;
          }
        }
      } else {
        bad_request = true;
      }
    } else {
      if (method == OC_GET) {
        oc_rep_start_root_object();
        oc_rep_end_root_object();
      } else {
        bad_request = true;
      }
    }

    if (bad_request) {
      oc_link_params_t *p = (oc_link_params_t *)oc_list_pop(params_list);
      while (p) {
        oc_free_string(&p->key);
        oc_free_string(&p->value);
        oc_memb_free(&oc_params_s, p);
        p = (oc_link_params_t *)oc_list_pop(params_list);
      }
    }

    if (!bad_request) {
      pcode = ecode = oc_status_code(OC_STATUS_OK);
    } else {
      pcode = ecode = oc_status_code(OC_STATUS_BAD_REQUEST);
    }
  } break;
#endif /* OC_COLLECTIONS_IF_CREATE */
  case OC_IF_BASELINE: {
    if (method == OC_GET) {
      oc_rep_start_root_object();
      oc_process_baseline_interface(request->resource);
      /* rts */
      oc_rep_open_array(root, rts);
      oc_rt_t *rtt = (oc_rt_t *)oc_list_head(collection->supported_rts);
      while (rtt) {
        oc_rep_add_text_string(rts, oc_string(rtt->rt));
        rtt = rtt->next;
      }
      oc_rep_close_array(root, rts);
      /* rts-m */
      const char *rtsm_key = "rts-m";
      oc_rep_set_key(oc_rep_object(root), rtsm_key);
      oc_rep_start_array(oc_rep_object(root), rtsm);
      oc_rt_t *rtt = (oc_rt_t *)oc_list_head(collection->mandatory_rts);
      while (rtt) {
        oc_rep_add_text_string(rtsm, oc_string(rtt->rt));
        rtt = rtt->next;
      }
      oc_rep_end_array(oc_rep_object(root), rtsm);
      oc_rep_set_array(root, links);
      while (link != NULL) {
        if (oc_filter_resource_by_rt(link->resource, request)) {
          oc_rep_object_array_start_item(links);
          oc_rep_set_text_string(links, href, oc_string(link->resource->uri));
          oc_rep_set_string_array(links, rt, link->resource->types);
          oc_core_encode_interfaces_mask(oc_rep_object(links),
                                         link->resource->interfaces);
          oc_rep_set_string_array(links, rel, link->rel);
          oc_rep_set_int(links, ins, link->ins);
          oc_link_params_t *p = (oc_link_params_t *)oc_list_head(link->params);
          while (p) {
            oc_rep_set_key(oc_rep_object(links), oc_string(p->key));
            oc_rep_set_value_text_string(links, oc_string(p->value));
            p = p->next;
          }
          oc_rep_set_object(links, p);
          oc_rep_set_uint(
            p, bm,
            (uint8_t)(link->resource->properties & ~(OC_PERIODIC | OC_SECURE)));
          oc_rep_close_object(links, p);

          // eps
          oc_rep_set_array(links, eps);
          oc_endpoint_t *eps =
            oc_connectivity_get_endpoints(link->resource->device);
          while (eps != NULL) {
            /*  If this resource has been explicitly tagged as SECURE on the
             *  application layer, skip all coap:// endpoints, and only include
             *  coaps:// endpoints.
             *  Also, exclude all endpoints that are not associated with the
             * interface through which this request arrived. This is achieved
             * by checking if the interface index matches.
             */
            if ((link->resource->properties & OC_SECURE &&
                 !(eps->flags & SECURED)) ||
                (request->origin && request->origin->interface_index != -1 &&
                 request->origin->interface_index != eps->interface_index)) {
              goto next_eps1;
            }
            oc_rep_object_array_start_item(eps);
            oc_string_t ep;
            if (oc_endpoint_to_string(eps, &ep) == 0) {
              oc_rep_set_text_string(eps, ep, oc_string(ep));
              oc_free_string(&ep);
            }
            oc_rep_object_array_end_item(eps);
          next_eps1:
            eps = eps->next;
          }
          oc_rep_close_array(links, eps);

          oc_rep_object_array_end_item(links);
        }
        link = link->next;
      }
      oc_rep_close_array(root, links);
      if (collection->get_properties.cb.get_props) {
        collection->get_properties.cb.get_props(
          (oc_resource_t *)collection, OC_IF_BASELINE,
          collection->get_properties.user_data);
      }
      oc_rep_end_root_object();

      pcode = ecode = oc_status_code(OC_STATUS_OK);
    } else if (method == OC_PUT || method == OC_POST) {
      if (collection->set_properties.cb.set_props) {
        collection->set_properties.cb.set_props(
          (oc_resource_t *)collection, request->request_payload,
          collection->set_properties.user_data);
      }
    }
  } break;
  case OC_IF_LL: {
    oc_rep_start_links_array();
    while (link != NULL) {
      if (oc_filter_resource_by_rt(link->resource, request)) {
        oc_rep_object_array_start_item(links);
        oc_rep_set_text_string(links, href, oc_string(link->resource->uri));
        oc_rep_set_string_array(links, rt, link->resource->types);
        oc_core_encode_interfaces_mask(oc_rep_object(links),
                                       link->resource->interfaces);
        oc_rep_set_string_array(links, rel, link->rel);
        oc_rep_set_int(links, ins, link->ins);
        oc_link_params_t *p = (oc_link_params_t *)oc_list_head(link->params);
        while (p) {
          oc_rep_set_key(oc_rep_object(links), oc_string(p->key));
          oc_rep_set_value_text_string(links, oc_string(p->value));
          p = p->next;
        }
        oc_rep_set_object(links, p);
        oc_rep_set_uint(
          p, bm,
          (uint8_t)(link->resource->properties & ~(OC_PERIODIC | OC_SECURE)));
        oc_rep_close_object(links, p);

        // eps
        oc_rep_set_array(links, eps);
        oc_endpoint_t *eps =
          oc_connectivity_get_endpoints(link->resource->device);
        while (eps != NULL) {
          /* If this resource has been explicitly tagged as SECURE on the
           * application layer, skip all coap:// endpoints, and only include
           * coaps:// endpoints.
           * Also, exclude all endpoints that are not associated with the
           * interface through which this request arrived. This is achieved by
           * checking if the interface index matches.
           */
          if ((link->resource->properties & OC_SECURE &&
               !(eps->flags & SECURED)) ||
              (request->origin && request->origin->interface_index != -1 &&
               request->origin->interface_index != eps->interface_index)) {
            goto next_eps2;
          }
          oc_rep_object_array_start_item(eps);
          oc_string_t ep;
          if (oc_endpoint_to_string(eps, &ep) == 0) {
            oc_rep_set_text_string(eps, ep, oc_string(ep));
            oc_free_string(&ep);
          }
          oc_rep_object_array_end_item(eps);
        next_eps2:
          eps = eps->next;
        }
        oc_rep_close_array(links, eps);

        oc_rep_object_array_end_item(links);
      }
      link = link->next;
    }
    oc_rep_end_links_array();

    pcode = ecode = oc_status_code(OC_STATUS_OK);
  } break;
  case OC_IF_B: {
    CborEncoder encoder, prev_link;
    oc_request_t rest_request = { 0 };
    oc_response_t response = { 0 };
    oc_response_buffer_t response_buffer;
    bool method_not_found = false, get_delete = false;
    oc_rep_t *rep = request->request_payload;
    oc_string_t *href = NULL;

    response.response_buffer = &response_buffer;
    rest_request.response = &response;
    rest_request.origin = request->origin;

    oc_rep_start_links_array();
    memcpy(&encoder, &g_encoder, sizeof(CborEncoder));
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
        oc_rep_t *pay = rep->value.object;
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
      process_request:
        link = oc_list_head(collection->links);
        while (link != NULL) {
          if (link->resource &&
              (!notify_resource == !(link->resource == notify_resource))) {
            if (oc_filter_resource_by_rt(link->resource, request)) {
              if (!get_delete && href && oc_string_len(*href) > 0 &&
                  (oc_string_len(*href) != oc_string_len(link->resource->uri) ||
                   memcmp(oc_string(*href), oc_string(link->resource->uri),
                          oc_string_len(*href))) != 0) {
                goto next;
              }
              memcpy(&prev_link, &links_array, sizeof(CborEncoder));
              oc_rep_object_array_start_item(links);

              rest_request.query = 0;
              rest_request.query_len = 0;

              oc_rep_set_text_string(links, href,
                                     oc_string(link->resource->uri));
              oc_rep_set_key(oc_rep_object(links), "rep");
              memcpy(&g_encoder, &links_map, sizeof(CborEncoder));

              int size_before = oc_rep_get_encoded_payload_size();
              rest_request.resource = link->resource;
              response_buffer.code = 0;
              response_buffer.response_length = 0;
              method_not_found = false;
#ifdef OC_SECURITY
              if (request && request->origin &&
                  !oc_sec_check_acl(method, link->resource, request->origin)) {
                response_buffer.code = oc_status_code(OC_STATUS_FORBIDDEN);
              } else
#endif /* OC_SECURITY */
              {
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
                }
              }

              if (method_not_found ||
                  (href && oc_string_len(*href) > 0 &&
                   response_buffer.code >=
                     oc_status_code(OC_STATUS_BAD_REQUEST))) {
                ecode = response_buffer.code;
                memcpy(&links_array, &prev_link, sizeof(CborEncoder));
                goto next;
              } else {
                if ((method == OC_PUT || method == OC_POST) &&
                    response_buffer.code <
                      oc_status_code(OC_STATUS_BAD_REQUEST)) {
                  oc_set_delayed_callback(link->resource,
                                          batch_notify_collection_for_link, 0);
                }
                if (response_buffer.code <
                    oc_status_code(OC_STATUS_BAD_REQUEST)) {
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

              memcpy(&links_map, &g_encoder, sizeof(CborEncoder));
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
        break;
      }
      rep = rep->next;
    }
  processed_request:
    memcpy(&g_encoder, &encoder, sizeof(CborEncoder));
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }

  int code = oc_status_code(OC_STATUS_BAD_REQUEST);

  int size = oc_rep_get_encoded_payload_size();

  if (ecode < oc_status_code(OC_STATUS_BAD_REQUEST) &&
      pcode < oc_status_code(OC_STATUS_BAD_REQUEST)) {
    switch (method) {
    case OC_GET:
      code = oc_status_code(OC_STATUS_OK);
      break;
    case OC_POST:
    case OC_PUT:
      if (iface_mask == OC_IF_CREATE) {
        code = oc_status_code(OC_STATUS_CREATED);
      } else {
        code = oc_status_code(OC_STATUS_CHANGED);
      }
      break;
    case OC_DELETE:
      code = oc_status_code(OC_STATUS_DELETED);
      break;
    }
  }

  request->response->response_buffer->response_length = (uint16_t)size;
  request->response->response_buffer->code = code;

  if ((method == OC_PUT || method == OC_POST) &&
      code < oc_status_code(OC_STATUS_BAD_REQUEST)) {
    coap_notify_collection_observers(
      request->resource, request->response->response_buffer, iface_mask);
  }

  return true;
}

oc_collection_t *
oc_collection_get_all(void)
{
  return (oc_collection_t *)oc_list_head(oc_collections);
}

#endif /* OC_COLLECTIONS && OC_SERVER */
