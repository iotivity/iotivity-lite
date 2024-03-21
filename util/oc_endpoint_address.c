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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST

#include "api/oc_helpers_internal.h"
#include "oc_cloud.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "port/oc_log_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include "util/oc_endpoint_address_internal.h"

#include <assert.h>
#include <string.h>

oc_endpoint_address_view_t
oc_endpoint_address_view(const oc_endpoint_address_t *ea)
{
  if (ea->metadata.id_type == OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID) {
    return oc_endpoint_address_make_view_with_uuid(oc_string_view2(&ea->uri),
                                                   ea->metadata.id.uuid);
  }
  return oc_endpoint_address_make_view_with_name(
    oc_string_view2(&ea->uri), oc_string_view2(&ea->metadata.id.name));
}

oc_endpoint_address_view_t
oc_endpoint_address_make_view_with_uuid(oc_string_view_t uri, oc_uuid_t uuid)
{
  return (oc_endpoint_address_view_t){
    .uri = uri,
    .metadata = {
      .id = {
        .uuid = uuid,
      },
      .id_type = OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID,
    },
  };
}

oc_endpoint_address_view_t
oc_endpoint_address_make_view_with_name(oc_string_view_t uri,
                                        oc_string_view_t name)
{
  return (oc_endpoint_address_view_t){
    .uri = uri,
    .metadata = {
      .id = {
        .name = name,
      },
      .id_type = OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME,
    },
  };
}

const oc_string_t *
oc_endpoint_address_uri(const oc_endpoint_address_t *ea)
{
  return &ea->uri;
}

static void
OC_NONNULL()
  endpoint_address_free_metadata_id(oc_endpoint_address_metadata_t *metadata)
{
  if (metadata->id_type == OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME) {
    oc_free_string(&metadata->id.name);
  }
}

void
oc_endpoint_address_set_uuid(oc_endpoint_address_t *ea, oc_uuid_t uuid)
{
  endpoint_address_free_metadata_id(&ea->metadata);
  ea->metadata.id_type = OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID;
  ea->metadata.id.uuid = uuid;
}

const oc_uuid_t *
oc_endpoint_address_uuid(const oc_endpoint_address_t *ea)
{
  if (ea->metadata.id_type != OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID) {
    return NULL;
  }
  return &ea->metadata.id.uuid;
}

void
oc_endpoint_address_set_name(oc_endpoint_address_t *ea, const char *name,
                             size_t name_len)
{
  endpoint_address_free_metadata_id(&ea->metadata);
  ea->metadata.id_type = OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME;
  if (name == NULL) {
    memset(&ea->metadata.id.name, 0, sizeof(oc_string_t));
    return;
  }
  oc_new_string(&ea->metadata.id.name, name, name_len);
}

const oc_string_t *
oc_endpoint_address_name(const oc_endpoint_address_t *ea)
{
  if (ea->metadata.id_type != OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME) {
    return NULL;
  }
  return &ea->metadata.id.name;
}

static bool
endpoint_address_is_valid(oc_string_view_t uri)
{
  return uri.length > 0 && uri.length < OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH;
}

static bool OC_NONNULL(1)
  endpoint_address_select(oc_endpoint_addresses_t *eas,
                          const oc_endpoint_address_t *selected)
{
  if (eas->selected == selected) {
    return false;
  }
  eas->selected = selected;
  if (eas->on_selected_change.cb != NULL) {
    eas->on_selected_change.cb(eas->on_selected_change.cb_data);
  }
  return true;
}

static bool
OC_NONNULL()
  endpoint_address_set_metadata(oc_endpoint_address_t *ea,
                                oc_endpoint_address_metadata_view_t metadata)
{
  ea->metadata.id_type = metadata.id_type;
  if (metadata.id_type == OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID) {
    ea->metadata.id.uuid = metadata.id.uuid;
    return true;
  }
  if (metadata.id.name.data == NULL) {
    return true;
  }
  oc_new_string(&ea->metadata.id.name, metadata.id.name.data,
                metadata.id.name.length);
  return oc_string(ea->metadata.id.name) != NULL;
}

static oc_endpoint_address_t *
OC_NONNULL() endpoint_address_allocate_and_add(
  oc_endpoint_addresses_t *eas, oc_string_view_t uri,
  oc_endpoint_address_metadata_view_t metadata)
{
  if (!endpoint_address_is_valid(uri)) {
    return NULL;
  }

  assert(eas->pool != NULL);
  oc_endpoint_address_t *ea = oc_memb_alloc(eas->pool);
  if (ea == NULL) {
    return NULL;
  }
  oc_new_string(&ea->uri, uri.data, uri.length);
  if (oc_string(ea->uri) == NULL) {
    oc_memb_free(eas->pool, ea);
    return NULL;
  }

  if (!endpoint_address_set_metadata(ea, metadata)) {
    oc_free_string(&ea->uri);
    oc_memb_free(eas->pool, ea);
    return NULL;
  }

  // automatically select the first endpoint address added
  if (eas->selected == NULL) {
    assert(oc_list_length(eas->addresses) == 0);
    endpoint_address_select(eas, ea);
  }

  oc_list_add(eas->addresses, ea);
  return ea;
}

bool
oc_endpoint_addresses_init(
  oc_endpoint_addresses_t *eas, oc_memb_t *pool,
  on_selected_endpoint_address_change_fn_t on_selected_change,
  void *on_selected_change_data, oc_endpoint_address_view_t default_ea)
{
  memset(eas, 0, sizeof(oc_endpoint_addresses_t));
  OC_LIST_STRUCT_INIT(eas, addresses);
  eas->pool = pool;

  // set callback before calling allocate and add, because it may trigger the
  // callback
  eas->on_selected_change.cb = on_selected_change;
  eas->on_selected_change.cb_data = on_selected_change_data;

  if (default_ea.uri.length > 0) {
    const oc_endpoint_address_t *ea = endpoint_address_allocate_and_add(
      eas, default_ea.uri, default_ea.metadata);
    if (ea == NULL) {
      return false;
    }
  }

  return true;
}

static void
OC_NONNULL()
  endpoint_address_free(oc_endpoint_addresses_t *eas, oc_endpoint_address_t *ea)
{
  oc_free_string(&ea->uri);
  endpoint_address_free_metadata_id(&ea->metadata);
  oc_memb_free(eas->pool, ea);
}

void
oc_endpoint_addresses_deinit(oc_endpoint_addresses_t *eas)
{
  if (eas->addresses == NULL) {
    return;
  }
  oc_endpoint_address_t *ea = oc_list_pop(eas->addresses);
  while (ea != NULL) {
    endpoint_address_free(eas, ea);
    ea = oc_list_pop(eas->addresses);
  }
  eas->selected = NULL;
}

bool
oc_endpoint_addresses_reinit(oc_endpoint_addresses_t *eas,
                             oc_endpoint_address_view_t default_ea)
{
  oc_endpoint_addresses_deinit(eas);
  return oc_endpoint_addresses_init(eas, eas->pool, eas->on_selected_change.cb,
                                    eas->on_selected_change.cb_data,
                                    default_ea);
}

void
oc_endpoint_addresses_set_on_selected_change(
  oc_endpoint_addresses_t *eas, on_selected_endpoint_address_change_fn_t cb,
  void *data)
{
  eas->on_selected_change.cb = cb;
  eas->on_selected_change.cb_data = data;
}

oc_endpoint_addresses_on_selected_change_t
oc_endpoint_addresses_get_on_selected_change(const oc_endpoint_addresses_t *eas)
{
  return eas->on_selected_change;
}

size_t
oc_endpoint_addresses_size(const oc_endpoint_addresses_t *eas)
{
  return eas->addresses == NULL ? 0 : oc_list_length(eas->addresses);
}

bool
oc_endpoint_addresses_is_empty(const oc_endpoint_addresses_t *eas)
{
  return oc_endpoint_addresses_size(eas) == 0;
}

bool
oc_endpoint_addresses_contains(const oc_endpoint_addresses_t *eas,
                               oc_string_view_t uri)
{
  if (eas->addresses == NULL) {
    return false;
  }
  const oc_endpoint_address_t *ea =
    (oc_endpoint_address_t *)oc_list_head(eas->addresses);
  while (ea != NULL) {
    if (oc_string_view_is_equal(oc_string_view2(&ea->uri), uri)) {
      return true;
    }
    ea = ea->next;
  }
  return false;
}

oc_endpoint_address_t *
oc_endpoint_addresses_add(oc_endpoint_addresses_t *eas,
                          oc_endpoint_address_view_t ea)
{
  if (!endpoint_address_is_valid(ea.uri)) {
    OC_ERR("cannot add endpoint address: invalid uri(%s)",
           ea.uri.data != NULL ? ea.uri.data : "null");
    return NULL;
  }
  if (oc_endpoint_addresses_contains(eas, ea.uri)) {
    OC_DBG("oc_endpoint_addresses_add: uri already exists");
    return NULL;
  }

  return endpoint_address_allocate_and_add(eas, ea.uri, ea.metadata);
}

static const oc_endpoint_address_t *OC_NONNULL(1)
  endpoint_address_next(const oc_endpoint_addresses_t *eas,
                        const oc_endpoint_address_t *item_next)
{
  if (item_next != NULL) {
    return item_next;
  }
  return oc_list_head(eas->addresses);
}

bool
oc_endpoint_addresses_remove(oc_endpoint_addresses_t *eas,
                             const oc_endpoint_address_t *ea)
{
  const oc_endpoint_address_t *eam_next = ea->next;
  oc_endpoint_address_t *found =
    (oc_endpoint_address_t *)oc_list_remove2(eas->addresses, ea);
  if (found == NULL) {
    return false;
  }
  if (eas->selected == ea) {
    endpoint_address_select(eas, endpoint_address_next(eas, eam_next));
  }
  endpoint_address_free(eas, found);
  return true;
}

bool
oc_endpoint_addresses_remove_by_uri(oc_endpoint_addresses_t *eas,
                                    oc_string_view_t uri)
{
  const oc_endpoint_address_t *ea = oc_endpoint_addresses_find(eas, uri);
  if (ea == NULL) {
    return false;
  }
  return oc_endpoint_addresses_remove(eas, ea);
}

void
oc_endpoint_addresses_clear(oc_endpoint_addresses_t *eas)
{
  oc_endpoint_address_t *ea = oc_list_pop(eas->addresses);
  while (ea != NULL) {
    endpoint_address_free(eas, ea);
    ea = oc_list_pop(eas->addresses);
  }
  endpoint_address_select(eas, NULL);
}

void
oc_endpoint_addresses_iterate(const oc_endpoint_addresses_t *eas,
                              oc_endpoint_addresses_iterate_fn_t fn, void *data)
{
  if (eas->addresses == NULL) {
    return;
  }
  oc_endpoint_address_t *ea =
    (oc_endpoint_address_t *)oc_list_head(eas->addresses);
  while (ea != NULL) {
    oc_endpoint_address_t *next = ea->next;
    if (!fn(ea, data)) {
      return;
    }
    ea = next;
  }
}

typedef struct
{
  oc_string_view_t uri;
  oc_endpoint_address_t *found;
} endpoint_address_match_t;

static bool
OC_NONNULL() endpoint_address_match(oc_endpoint_address_t *ea, void *data)
{
  endpoint_address_match_t *match = (endpoint_address_match_t *)data;
  if (oc_string_view_is_equal(oc_string_view2(&ea->uri), match->uri)) {
    match->found = ea;
    return false;
  }
  return true;
}

oc_endpoint_address_t *
oc_endpoint_addresses_find(const oc_endpoint_addresses_t *eas,
                           oc_string_view_t uri)
{
  endpoint_address_match_t match = {
    .uri = uri,
    .found = NULL,
  };
  oc_endpoint_addresses_iterate(eas, endpoint_address_match, &match);
  return match.found;
}

bool
oc_endpoint_addresses_select(oc_endpoint_addresses_t *eas,
                             const oc_endpoint_address_t *selected)
{
  if (!oc_list_has_item(eas->addresses, selected)) {
    return false;
  }
  endpoint_address_select(eas, selected);
  return true;
}

bool
oc_endpoint_addresses_select_by_uri(oc_endpoint_addresses_t *eas,
                                    oc_string_view_t uri)
{
  const oc_endpoint_address_t *found = oc_endpoint_addresses_find(eas, uri);
  if (found == NULL) {
    return false;
  }
  endpoint_address_select(eas, found);
  return true;
}

bool
oc_endpoint_addresses_select_next(oc_endpoint_addresses_t *eas)
{
  if (eas->selected == NULL) {
    return false;
  }
  return endpoint_address_select(
    eas, endpoint_address_next(eas, eas->selected->next));
}

bool
oc_endpoint_addresses_is_selected(const oc_endpoint_addresses_t *eas,
                                  oc_string_view_t uri)
{
  return eas->selected != NULL &&
         oc_string_view_is_equal(oc_string_view2(&eas->selected->uri), uri);
}

const oc_endpoint_address_t *
oc_endpoint_addresses_selected(const oc_endpoint_addresses_t *eas)
{
  return eas->selected;
}

const oc_string_t *
oc_endpoint_addresses_selected_uri(const oc_endpoint_addresses_t *eas)
{
  if (eas->selected == NULL) {
    return NULL;
  }
  return &eas->selected->uri;
}

const oc_uuid_t *
oc_endpoint_addresses_selected_uuid(const oc_endpoint_addresses_t *eas)
{
  if (eas->selected == NULL || eas->selected->metadata.id_type !=
                                 OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID) {
    return NULL;
  }
  return &eas->selected->metadata.id.uuid;
}

const oc_string_t *
oc_endpoint_addresses_selected_name(const oc_endpoint_addresses_t *eas)
{
  if (eas->selected == NULL || eas->selected->metadata.id_type !=
                                 OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME) {
    return NULL;
  }
  return &eas->selected->metadata.id.name;
}

typedef struct
{
  CborEncoder *ci_servers;
  CborError error;
} endpoint_address_encoder_t;

CborError
oc_endpoint_address_encode(CborEncoder *encoder, oc_string_view_t uri_key,
                           oc_string_view_t uuid_key, oc_string_view_t name_key,
                           oc_endpoint_address_view_t eav)
{
  CborError error = oc_rep_object_set_text_string(
    encoder, uri_key.data, uri_key.length, eav.uri.data, eav.uri.length);

  if (eav.metadata.id_type == OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME) {
    if (name_key.length == 0) { // skip encoding if the key is empty
      return error;
    }
    error |= oc_rep_object_set_text_string(
      encoder, name_key.data, name_key.length, eav.metadata.id.name.data,
      eav.metadata.id.name.length);
    return error;
  }

  if (uuid_key.length == 0) { // skip encoding if the key is empty
    return error;
  }
  char sid_str[OC_UUID_LEN] = { 0 };
  int sid_str_len =
    oc_uuid_to_str_v1(&eav.metadata.id.uuid, sid_str, OC_UUID_LEN);
  assert(sid_str_len > 0);
  error |= oc_rep_object_set_text_string(
    encoder, uuid_key.data, uuid_key.length, sid_str, (size_t)sid_str_len);
  return error;
}

static bool
OC_NONNULL() endpoint_addresses_encode(oc_endpoint_address_t *ea, void *data)
{
  endpoint_address_encoder_t *encoder = (endpoint_address_encoder_t *)data;

  CborEncoder endpoint_map;
  memset(&endpoint_map, 0, sizeof(endpoint_map));
  encoder->error |= oc_rep_encoder_create_map(
    encoder->ci_servers, &endpoint_map, CborIndefiniteLength);
  encoder->error |= oc_endpoint_address_encode(
    &endpoint_map, OC_STRING_VIEW(OC_ENDPOINT_ADDRESS_URI),
    OC_STRING_VIEW(OC_ENDPOINT_ADDRESS_ID),
    OC_STRING_VIEW(OC_ENDPOINT_ADDRESS_NAME), oc_endpoint_address_view(ea));
  encoder->error |=
    oc_rep_encoder_close_container(encoder->ci_servers, &endpoint_map);
  return true;
}

CborError
oc_endpoint_addresses_encode(CborEncoder *encoder,
                             const oc_endpoint_addresses_t *eas,
                             oc_string_view_t key, bool skipIfSingleAndSelected)
{
  size_t ea_size = oc_endpoint_addresses_size(eas);
  if (ea_size == 0) {
    return CborNoError;
  }

  if (skipIfSingleAndSelected && ea_size == 1) {
    // when there is a single element in the list, it should always be
    // selected
    assert(eas->selected != NULL);
    return CborNoError;
  }

  endpoint_address_encoder_t enc = { 0 };
  enc.error = oc_rep_encode_text_string(encoder, key.data, key.length);
  oc_rep_begin_array(encoder, ci_servers);
  enc.ci_servers = oc_rep_array(ci_servers);
  oc_endpoint_addresses_iterate(eas, endpoint_addresses_encode, &enc);
  oc_rep_end_array(encoder, ci_servers);
  return enc.error;
}

#endif /* OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST */
