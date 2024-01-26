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

#include "api/oc_core_res_internal.h"
#include "api/oc_enums_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_resource_internal.h"
#include "oc_ri.h"
#include "port/oc_log_internal.h"
#include "util/oc_numeric_internal.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS */

#include <assert.h>
#include <float.h>
#include <math.h>

bool
oc_resource_is_initialized(const oc_resource_t *resource)
{
  assert(resource != NULL);
  return oc_string(resource->uri) != NULL;
}

bool
oc_resource_supports_interface(const oc_resource_t *resource,
                               oc_interface_mask_t iface)
{
  assert(resource != NULL);
  return (resource->interfaces & iface) == iface;
}

bool
oc_resource_get_method_handler(const oc_resource_t *resource,
                               oc_method_t method,
                               oc_request_handler_t *handler)
{
  assert(resource != NULL);
  const oc_request_handler_t *h = NULL;
  switch (method) {
  case OC_FETCH:
    // TODO: implement fetch
    break;
  case OC_GET:
    h = &resource->get_handler;
    break;
  case OC_POST:
    h = &resource->post_handler;
    break;
  case OC_PUT:
    h = &resource->put_handler;
    break;
  case OC_DELETE:
    h = &resource->delete_handler;
    break;
  }
  if (h == NULL || h->cb == NULL) {
    return false;
  }
  if (handler) {
    *handler = *h;
  }
  return true;
}

bool
oc_resource_match_uri(oc_string_view_t canonicalURI, oc_string_view_t uri)
{
  assert(canonicalURI.data != NULL);
  const char *p_uri = canonicalURI.data;
  size_t p_urilen = canonicalURI.length;
  if (uri.length > 0 && uri.data[0] != '/') {
    ++p_uri;
    --p_urilen;
  }
  return uri.length == p_urilen && memcmp(uri.data, p_uri, p_urilen) == 0;
}

void
oc_resources_iterate_platform(oc_resource_iterate_fn_t fn, void *data)
{
  for (int type = 0; type < OCF_CON; ++type) {
    oc_resource_t *res = oc_core_get_resource_by_index(type, 0);
    if (res != NULL && !fn(res, data)) {
      return;
    }
  }
}

void
oc_resources_iterate_core(size_t device, oc_resource_iterate_fn_t fn,
                          void *data)
{
  for (int type = OCF_CON; type <= OCF_D; ++type) {
    if (type == OCF_CON && !oc_get_con_res_announced()) {
      continue;
    }
    oc_resource_t *core_res = oc_core_get_resource_by_index(type, device);
    if (core_res != NULL && !fn(core_res, data)) {
      return;
    }
  }
}

#ifdef OC_SERVER

void
oc_resources_iterate_dynamic(size_t device, oc_resource_iterate_fn_t fn,
                             void *data)
{
  for (oc_resource_t *app_res = oc_ri_get_app_resources(); app_res != NULL;
       app_res = app_res->next) {
    if (app_res->device != device) {
      continue;
    }
    if (!fn(app_res, data)) {
      return;
    }
  }
}

#ifdef OC_COLLECTIONS

void
oc_resources_iterate_collections(size_t device, oc_resource_iterate_fn_t fn,
                                 void *data)
{
  for (oc_collection_t *col = oc_collection_get_all(); col != NULL;
       col = (oc_collection_t *)col->res.next) {
    if (col->res.device != device) {
      continue;
    }
    if (!fn(&col->res, data)) {
      return;
    }
  }
}

#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

void
oc_resources_iterate(size_t device, bool includePlatform, bool includeCore,
                     bool includeDynamic, bool includeCollections,
                     oc_resource_iterate_fn_t fn, void *data)
{
  if (includePlatform) {
    oc_resources_iterate_platform(fn, data);
  }

  // core resources
  if (includeCore) {
    oc_resources_iterate_core(device, fn, data);
  }

#ifdef OC_SERVER
  // app resources
  if (includeDynamic) {
    oc_resources_iterate_dynamic(device, fn, data);
  }

#ifdef OC_COLLECTIONS
  // collections
  if (includeCollections) {
    oc_resources_iterate_collections(device, fn, data);
  }
#else  /* OC_COLLECTIONS */
  (void)includeCollections;
#endif /* OC_COLLECTIONS */
#else  /* OC_SERVER */
  (void)includeDynamic;
  (void)includeCollections;
#endif /* OC_SERVER */
}

void
oc_resource_tag_pos_desc(oc_resource_t *resource, oc_pos_description_t pos)
{
  resource->tag_pos_desc = pos;
}

void
oc_resource_tag_pos_rel(oc_resource_t *resource, double x, double y, double z)
{
  resource->tag_pos_rel[0] = x;
  resource->tag_pos_rel[1] = y;
  resource->tag_pos_rel[2] = z;
}

bool
oc_tag_pos_rel_is_empty(double pos1, double pos2, double pos3)
{
  return oc_double_is_zero(pos1) && oc_double_is_zero(pos2) &&
         oc_double_is_zero(pos3);
}

void
oc_resource_tag_func_desc(oc_resource_t *resource, oc_enum_t func)
{
  resource->tag_func_desc = func;
}

void
oc_resource_tag_locn(oc_resource_t *resource, oc_locn_t locn)
{
  resource->tag_locn = locn;
}

static void
resource_encode_name(CborEncoder *object, const char *name, size_t name_len)
{
  if (name == NULL) {
    return;
  }
  g_err |= oc_rep_object_set_text_string(
    object, OC_BASELINE_PROP_NAME, OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_NAME),
    name, name_len);
}

static void
resource_encode_tag_pos_desc(CborEncoder *object,
                             oc_pos_description_t tag_pos_desc)
{
  oc_string_view_t desc = oc_enum_pos_desc_to_string_view(tag_pos_desc);
  if (desc.data == NULL) {
    return;
  }
  /* tag-pos-desc will be handled as a string */
  g_err |= oc_rep_object_set_text_string(
    object, OC_BASELINE_PROP_TAG_POS_DESC,
    OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_TAG_POS_DESC), desc.data, desc.length);
}

static void
resource_encode_tag_func_desc(CborEncoder *object, oc_enum_t tag_func_desc)
{
  oc_string_view_t func = oc_enum_to_string_view(tag_func_desc);
  if (func.data == NULL) {
    return;
  }
  /* tag-func-desc will be handled as a string */
  g_err |= oc_rep_object_set_text_string(
    object, OC_BASELINE_PROP_FUNC_DESC,
    OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_FUNC_DESC), func.data, func.length);
}

static void
resource_encode_tag_locn(CborEncoder *object, oc_locn_t tag_locn)
{
  oc_string_view_t locn = oc_enum_locn_to_string_view(tag_locn);
  if (locn.data == NULL) {
    return;
  }
  /* tag-locn will be handled as a string */
  g_err |= oc_rep_object_set_text_string(
    object, OC_BASELINE_PROP_TAG_LOCN,
    OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_TAG_LOCN), locn.data, locn.length);
}

static void
resource_encode_tag_pos_rel(CborEncoder *object, double pos1, double pos2,
                            double pos3)
{
  if (oc_tag_pos_rel_is_empty(pos1, pos2, pos3)) {
    return;
  }
  oc_rep_set_key(object, "tag-pos-rel");
  oc_rep_start_array(object, tag_pos_rel);
  oc_rep_add_double(tag_pos_rel, pos1);
  oc_rep_add_double(tag_pos_rel, pos2);
  oc_rep_add_double(tag_pos_rel, pos3);
  oc_rep_end_array(object, tag_pos_rel);
}

void
oc_resource_encode_baseline_properties(
  CborEncoder *object, const oc_resource_t *resource,
  oc_resource_properties_filter_fn_t filter, void *filter_data)
{
  if (filter == NULL ||
      filter(OC_STRING_VIEW(OC_BASELINE_PROP_NAME), filter_data)) {
    resource_encode_name(object, oc_string(resource->name),
                         oc_string_len(resource->name));
  }
  if (filter == NULL ||
      filter(OC_STRING_VIEW(OC_BASELINE_PROP_RT), filter_data)) {
    g_err |= oc_rep_object_set_string_array(
      object, OC_BASELINE_PROP_RT, OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_RT),
      &resource->types);
  }
  if (filter == NULL ||
      filter(OC_STRING_VIEW(OC_BASELINE_PROP_IF), filter_data)) {
    oc_core_encode_interfaces_mask(object, resource->interfaces, false);
  }
  if (filter == NULL ||
      filter(OC_STRING_VIEW(OC_BASELINE_PROP_TAG_LOCN), filter_data)) {
    resource_encode_tag_locn(object, resource->tag_locn);
  }
  if (filter == NULL ||
      filter(OC_STRING_VIEW(OC_BASELINE_PROP_TAG_POS_REL), filter_data)) {
    resource_encode_tag_pos_rel(object, resource->tag_pos_rel[0],
                                resource->tag_pos_rel[1],
                                resource->tag_pos_rel[2]);
  }
  if (filter == NULL ||
      filter(OC_STRING_VIEW(OC_BASELINE_PROP_TAG_POS_DESC), filter_data)) {
    resource_encode_tag_pos_desc(object, resource->tag_pos_desc);
  }
  if (filter == NULL ||
      filter(OC_STRING_VIEW(OC_BASELINE_PROP_FUNC_DESC), filter_data)) {
    resource_encode_tag_func_desc(object, resource->tag_func_desc);
  }
}

void
oc_process_baseline_interface(const oc_resource_t *resource)
{
  oc_resource_encode_baseline_properties(oc_rep_object(root), resource, NULL,
                                         NULL);
}

static bool
resource_is_tag(oc_string_view_t property_name, void *data)
{
  (void)data;
  oc_string_view_t tag_property[] = {
    OC_STRING_VIEW(OC_BASELINE_PROP_TAG_LOCN),
    OC_STRING_VIEW(OC_BASELINE_PROP_TAG_POS_REL),
    OC_STRING_VIEW(OC_BASELINE_PROP_TAG_POS_DESC),
    OC_STRING_VIEW(OC_BASELINE_PROP_FUNC_DESC),
  };
  for (size_t i = 0; i < OC_ARRAY_SIZE(tag_property); ++i) {
    if (property_name.length == tag_property[i].length &&
        memcmp(property_name.data, tag_property[i].data,
               tag_property[i].length) == 0) {
      return true;
    }
  }
  return false;
}

void
oc_resource_encode_tag_properties(CborEncoder *object,
                                  const oc_resource_t *resource)
{
  oc_resource_encode_baseline_properties(object, resource, resource_is_tag,
                                         NULL);
}

oc_resource_t *
oc_resource_get_by_uri(const char *uri, size_t uri_len, size_t device)
{
  /* Check against list of declared core resources. */
  oc_resource_t *resource =
    oc_core_get_resource_by_uri_v1(uri, uri_len, device);

#ifdef OC_SERVER
  if (resource != NULL) {
    return resource;
  }

  /* Check against list of declared application resources. */
  resource = oc_ri_get_app_resource_by_uri(uri, uri_len, device);
#endif /* OC_SERVER */

  return resource;
}
