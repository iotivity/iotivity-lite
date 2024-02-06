/******************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_cloud_endpoint_internal.h"
#include "port/oc_log_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#include <string.h>

// max two endpoint addresses per device with static allocation
OC_MEMB(g_cloud_endpoint_s, oc_cloud_endpoint_t,
        OC_CLOUD_MAX_ENDPOINT_ADDRESSES);

static bool
cloud_endpoint_uri_is_valid(oc_string_view_t uri)
{
  return uri.length > 0 && uri.length < OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH;
}

static void
cloud_endpoints_set_selected(oc_cloud_endpoints_t *ce,
                             const oc_cloud_endpoint_t *selected)
{
  if (ce->selected == selected) {
    return;
  }
  ce->selected = selected;
  if (ce->on_selected_change != NULL) {
    ce->on_selected_change(ce->on_selected_change_data);
  }
}

static oc_cloud_endpoint_t *
cloud_endpoint_item_allocate_and_add(oc_cloud_endpoints_t *ce,
                                     oc_string_view_t uri, oc_uuid_t id)
{
  if (!cloud_endpoint_uri_is_valid(uri)) {
    return NULL;
  }

  oc_cloud_endpoint_t *cei = oc_memb_alloc(&g_cloud_endpoint_s);
  if (cei == NULL) {
    return NULL;
  }
  oc_new_string(&cei->uri, uri.data, uri.length);
  if (oc_string(cei->uri) == NULL) {
    oc_memb_free(&g_cloud_endpoint_s, cei);
    return NULL;
  }
  cei->id = id;

  // automatically select the first endpoint added
  if (ce->selected == NULL) {
    assert(oc_list_length(ce->endpoints) == 0);
    cloud_endpoints_set_selected(ce, cei);
  }

  oc_list_add(ce->endpoints, cei);
  return cei;
}

static void
cloud_endpoint_item_free(oc_cloud_endpoint_t *cei)
{
  oc_free_string(&cei->uri);
  oc_memb_free(&g_cloud_endpoint_s, cei);
}

const oc_string_t *
oc_cloud_endpoint_uri(const oc_cloud_endpoint_t *endpoint)
{
  return &endpoint->uri;
}

void
oc_cloud_endpoint_set_id(oc_cloud_endpoint_t *ce, oc_uuid_t id)
{
  ce->id = id;
}

oc_uuid_t
oc_cloud_endpoint_id(const oc_cloud_endpoint_t *ce)
{
  return ce->id;
}

bool
oc_cloud_endpoints_init(oc_cloud_endpoints_t *ce,
                        on_selected_change_fn_t on_selected_change,
                        void *on_selected_change_data,
                        oc_string_view_t default_uri, oc_uuid_t default_id)
{
  memset(ce, 0, sizeof(oc_cloud_endpoints_t));
  OC_LIST_STRUCT_INIT(ce, endpoints);

  if (default_uri.length > 0) {
    const oc_cloud_endpoint_t *cei =
      cloud_endpoint_item_allocate_and_add(ce, default_uri, default_id);
    if (cei == NULL) {
      return false;
    }
  }

  ce->on_selected_change = on_selected_change;
  ce->on_selected_change_data = on_selected_change_data;
  return true;
}

void
oc_cloud_endpoints_deinit(oc_cloud_endpoints_t *ce)
{
  if (ce->endpoints == NULL) {
    return;
  }
  oc_cloud_endpoint_t *cei = oc_list_pop(ce->endpoints);
  while (cei != NULL) {
    cloud_endpoint_item_free(cei);
    cei = oc_list_pop(ce->endpoints);
  }
}

bool
oc_cloud_endpoints_reinit(oc_cloud_endpoints_t *ce,
                          oc_string_view_t default_uri, oc_uuid_t default_id)
{
  oc_cloud_endpoints_deinit(ce);
  return oc_cloud_endpoints_init(ce, ce->on_selected_change,
                                 ce->on_selected_change_data, default_uri,
                                 default_id);
}

size_t
oc_cloud_endpoints_size(const oc_cloud_endpoints_t *ce)
{
  return ce->endpoints == NULL ? 0 : oc_list_length(ce->endpoints);
}

bool
oc_cloud_endpoints_is_empty(const oc_cloud_endpoints_t *ce)
{
  return oc_cloud_endpoints_size(ce) == 0;
}

void
oc_cloud_endpoints_iterate(const oc_cloud_endpoints_t *ce,
                           oc_cloud_endpoints_iterate_fn_t fn, void *data)
{
  if (ce->endpoints == NULL) {
    return;
  }
  oc_cloud_endpoint_t *cei = (oc_cloud_endpoint_t *)oc_list_head(ce->endpoints);
  while (cei != NULL) {
    oc_cloud_endpoint_t *next = cei->next;
    if (!fn(cei, data)) {
      return;
    }
    cei = next;
  }
}

void
oc_cloud_endpoints_clear(oc_cloud_endpoints_t *ce)
{
  oc_cloud_endpoint_t *cei = oc_list_pop(ce->endpoints);
  while (cei != NULL) {
    cloud_endpoint_item_free(cei);
    cei = oc_list_pop(ce->endpoints);
  }
  cloud_endpoints_set_selected(ce, NULL);
}

typedef struct
{
  oc_string_view_t uri;
  oc_cloud_endpoint_t *found;
} cloud_endpoint_item_match_t;

static bool
cloud_endpoint_item_match(oc_cloud_endpoint_t *cei, void *data)
{
  cloud_endpoint_item_match_t *match = (cloud_endpoint_item_match_t *)data;
  if (oc_string_view_is_equal(oc_string_view2(&cei->uri), match->uri)) {
    match->found = cei;
    return false;
  }
  return true;
}

oc_cloud_endpoint_t *
oc_cloud_endpoint_find(const oc_cloud_endpoints_t *ce, oc_string_view_t uri)
{
  cloud_endpoint_item_match_t match = {
    .uri = uri,
    .found = NULL,
  };
  oc_cloud_endpoints_iterate(ce, cloud_endpoint_item_match, &match);
  return match.found;
}

bool
oc_cloud_endpoint_contains(const oc_cloud_endpoints_t *ce, oc_string_view_t uri)
{
  if (ce->endpoints == NULL) {
    return false;
  }
  const oc_cloud_endpoint_t *cei =
    (oc_cloud_endpoint_t *)oc_list_head(ce->endpoints);
  while (cei != NULL) {
    if (oc_string_view_is_equal(oc_string_view2(&cei->uri), uri)) {
      return true;
    }
    cei = cei->next;
  }
  return false;
}

oc_cloud_endpoint_t *
oc_cloud_endpoint_add(oc_cloud_endpoints_t *ce, oc_string_view_t uri,
                      oc_uuid_t id)
{
  if (!cloud_endpoint_uri_is_valid(uri)) {
    OC_DBG("oc_cloud_endpoint_add: invalid uri(%s)",
           uri.data != NULL ? uri.data : "null");
    return NULL;
  }
  if (oc_cloud_endpoint_contains(ce, uri)) {
    OC_DBG("oc_cloud_endpoint_add: uri already exists");
    return NULL;
  }

  return cloud_endpoint_item_allocate_and_add(ce, uri, id);
}

static const oc_cloud_endpoint_t *
cloud_endpoint_item_next(const oc_cloud_endpoints_t *ce,
                         const oc_cloud_endpoint_t *item,
                         const oc_cloud_endpoint_t *item_next)
{
  assert(item != NULL);
  if (item_next != NULL || oc_list_head(ce->endpoints) == item) {
    return item_next;
  }
  return oc_list_head(ce->endpoints);
}

bool
oc_cloud_endpoint_remove(oc_cloud_endpoints_t *ce,
                         const oc_cloud_endpoint_t *ep)
{
  const oc_cloud_endpoint_t *ep_next = ep->next;
  oc_cloud_endpoint_t *found =
    (oc_cloud_endpoint_t *)oc_list_remove2(ce->endpoints, ep);
  if (found == NULL) {
    return false;
  }
  if (ce->selected == ep) {
    cloud_endpoints_set_selected(
      ce, cloud_endpoint_item_next(ce, ce->selected, ep_next));
  }
  cloud_endpoint_item_free(found);
  return true;
}

bool
oc_cloud_endpoint_remove_by_uri(oc_cloud_endpoints_t *ce, oc_string_view_t uri)
{
  const oc_cloud_endpoint_t *ep = oc_cloud_endpoint_find(ce, uri);
  if (ep == NULL) {
    return false;
  }
  return oc_cloud_endpoint_remove(ce, ep);
}

bool
oc_cloud_endpoint_select_by_uri(oc_cloud_endpoints_t *ce, oc_string_view_t uri)
{
  const oc_cloud_endpoint_t *found = oc_cloud_endpoint_find(ce, uri);
  if (found == NULL) {
    return false;
  }
  cloud_endpoints_set_selected(ce, found);
  return true;
}

bool
oc_cloud_endpoint_is_selected(const oc_cloud_endpoints_t *ce,
                              oc_string_view_t uri)
{
  return ce->selected != NULL &&
         oc_string_view_is_equal(oc_string_view2(&ce->selected->uri), uri);
}

const oc_string_t *
oc_cloud_endpoint_selected_address(const oc_cloud_endpoints_t *ce)
{
  if (ce->selected == NULL) {
    return NULL;
  }
  return &ce->selected->uri;
}

const oc_uuid_t *
oc_cloud_endpoint_selected_id(const oc_cloud_endpoints_t *ce)
{
  if (ce->selected == NULL) {
    return NULL;
  }
  return &ce->selected->id;
}

typedef struct
{
  CborEncoder *ci_servers;
  CborError error;
} cloud_endpoint_encoder_t;

static bool
cloud_encode_server(oc_cloud_endpoint_t *endpoint, void *data)
{
  cloud_endpoint_encoder_t *encoder = (cloud_endpoint_encoder_t *)data;
  oc_string_view_t uri = oc_string_view2(&endpoint->uri);

  CborEncoder endpoint_map;
  memset(&endpoint_map, 0, sizeof(endpoint_map));
  encoder->error |= oc_rep_encoder_create_map(
    encoder->ci_servers, &endpoint_map, CborIndefiniteLength);
  oc_rep_object_set_text_string(&endpoint_map, "uri", OC_CHAR_ARRAY_LEN("uri"),
                                uri.data, uri.length);
  char sid_str[OC_UUID_LEN] = { 0 };
  int sid_str_len = oc_uuid_to_str_v1(&endpoint->id, sid_str, OC_UUID_LEN);
  assert(sid_str_len > 0);
  oc_rep_object_set_text_string(&endpoint_map, "id", OC_CHAR_ARRAY_LEN("id"),
                                sid_str, (size_t)sid_str_len);

  encoder->error |=
    oc_rep_encoder_close_container(encoder->ci_servers, &endpoint_map);
  return true;
}

CborError
oc_cloud_endpoints_encode(CborEncoder *encoder, const oc_cloud_endpoints_t *ce,
                          oc_string_view_t key, bool skipIfSingleAndSelected)
{
  if (oc_cloud_endpoints_size(ce) == 0) {
    return CborNoError;
  }

  if (skipIfSingleAndSelected && oc_cloud_endpoints_size(ce) == 1) {
    // when there is a single element in the list, it should always be selected
    assert(ce->selected != NULL);
    return CborNoError;
  }

  cloud_endpoint_encoder_t enc = { 0 };
  enc.error = oc_rep_encode_text_string(encoder, key.data, key.length);
  oc_rep_begin_array(encoder, ci_servers);
  enc.ci_servers = oc_rep_array(ci_servers);
  oc_cloud_endpoints_iterate(ce, cloud_encode_server, &enc);
  oc_rep_end_array(encoder, ci_servers);
  return enc.error;
}
