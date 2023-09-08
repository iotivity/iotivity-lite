/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 ***************************************************************************/

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ETAG

#include "api/oc_etag_internal.h"
#include "api/oc_resource_internal.h"
#include "messaging/coap/coap_options.h"
#include "oc_base64.h"
#include "oc_core_res.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "util/oc_macros_internal.h"

#ifdef OC_STORAGE
#include "api/oc_storage_internal.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS */

#endif /* OC_STORAGE */

#include <inttypes.h>
#include <stdint.h>

static uint64_t g_etag = 0;

static uint64_t
etag_random(void)
{
  return (oc_random_value() % 1000) + 1;
}

uint64_t
oc_etag_global(void)
{
  return g_etag;
}

uint64_t
oc_etag_set_global(uint64_t etag)
{
  if (etag == OC_ETAG_UNINITIALIZED) {
    etag = 1;
  }
  if (etag < g_etag) {
    // TODO: handle wrap around = all resource etags must be reinitialized
    OC_DBG("etag wrap around detected: %" PRIu64 " -> %" PRIu64, g_etag, etag);
  }
  return (g_etag = etag);
}

uint64_t
oc_etag_get(void)
{
  uint64_t now = oc_clock_time();
  uint64_t etag = g_etag;
  if (now > etag) {
    etag = now;
  }
  etag += etag_random();
  return oc_etag_set_global(etag);
}

#ifdef OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES

bool
oc_etag_has_incremental_updates_query(const char *query, size_t query_len)
{
  return oc_ri_query_exists_v1(
    query, query_len, OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY,
    OC_CHAR_ARRAY_LEN(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY));
}

static bool
etag_process_incremental_updates_value(
  const char *value, size_t value_len,
  oc_etag_iterate_incremental_updates_fn_t etag_fn, void *etag_fn_data)
{
  // decode base64
#define ETAG_BASE64_BUFFER_SIZE (12)
  uint8_t buffer[ETAG_BASE64_BUFFER_SIZE] = { 0 };
  int len =
    oc_base64_decode_v1(OC_BASE64_ENCODING_URL, false, (const uint8_t *)value,
                        value_len, buffer, OC_ARRAY_SIZE(buffer));
  if (len < 0) {
    OC_DBG("oc_etag: failed to decode value (%.*s)", (int)value_len, value);
    return true;
  }
  uint64_t etag;
  if ((size_t)len != sizeof(etag)) {
    OC_DBG("oc_etag: invalid etag size(%d)", len);
    return true;
  }
  memcpy(&etag, buffer, sizeof(etag));
  OC_DBG("oc_etag: decoded etag: %" PRIu64, etag);
  return etag_fn(etag, etag_fn_data);
}

static bool
etag_process_incremental_updates_values(
  const char *value, size_t value_len,
  oc_etag_iterate_incremental_updates_fn_t etag_fn, void *etag_fn_data)
{
  size_t pos = 0;
  while (pos < value_len) {
    if (value[pos] == ',') {
      ++pos;
      continue;
    }
    const char *item = value + pos;
    size_t end = pos;
    while (end < value_len && value[end] != ',') {
      ++end;
    }
    size_t len = end - pos;
    if (!etag_process_incremental_updates_value(item, len, etag_fn,
                                                etag_fn_data)) {
      return false;
    }
    pos = end;
  }

  return true;
}

void
oc_etag_iterate_incremental_updates_query(
  const char *query, size_t query_len,
  oc_etag_iterate_incremental_updates_fn_t etag_fn, void *etag_fn_data)
{
  for (size_t pos = 0; pos < query_len;) {
    const char *value = NULL;
    int value_len = oc_ri_get_query_value_v1(
      query + pos, query_len - pos, OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY,
      OC_CHAR_ARRAY_LEN(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY), &value);
    if (value_len == -1) {
      return;
    }
    OC_DBG("oc_etag: incremental update query %.*s", (int)value_len, value);
    pos = (value - query) + value_len + 1;

    if (!etag_process_incremental_updates_values(value, value_len, etag_fn,
                                                 etag_fn_data)) {
      OC_DBG("oc_etag: incremental update query iteration stopped");
      return;
    }
  }
}

#endif /* OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES */

#ifdef OC_STORAGE

bool
oc_etag_clear_storage(void)
{
  bool success = true;
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    if (!oc_storage_data_clear(OC_ETAG_STORE_NAME, i)) {
      OC_ERR("failed to clear etag storage for device %zu", i);
      success = false;
    }
  }
  return success;
}

static bool
etag_iterate_encode_resource(oc_resource_t *resource, void *data)
{
  (void)data;
  OC_DBG("encoding resource [%zu:]%s", resource->device,
         oc_string(resource->uri));
  uint64_t etag = oc_resource_get_etag(resource);
  if (etag == OC_ETAG_UNINITIALIZED) {
    OC_DBG("skipping uninitialized etag for resource %s",
           oc_string(resource->uri));
    return true;
  }
  CborError err =
    oc_rep_encode_text_string(oc_rep_object(root), oc_string(resource->uri),
                              oc_string_len(resource->uri));
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  err |= oc_rep_encoder_create_map(oc_rep_object(root), &etag_map,
                                   CborIndefiniteLength);
  err |=
    oc_rep_encode_text_string(&etag_map, "etag", OC_CHAR_ARRAY_LEN("etag"));
  err |= oc_rep_encode_uint(&etag_map, etag);
  err |= oc_rep_encoder_close_container(oc_rep_object(root), &etag_map);

  if (err != CborNoError) {
    OC_ERR("failed to encode device(%zu) resource %s", resource->device,
           oc_string(resource->uri));
    g_err |= err;
    return false;
  }
  return true;
}

static int
etag_store_encode(size_t device, void *data)
{
  (void)data;
  oc_rep_start_root_object();
  // we store platform resources only for device 0
  oc_resources_iterate(device, device == 0, true, true, true,
                       etag_iterate_encode_resource, NULL);
  oc_rep_end_root_object();
  return oc_rep_get_cbor_errno();
}

bool
oc_etag_dump_for_device(size_t device)
{
  long ret =
    oc_storage_data_save(OC_ETAG_STORE_NAME, device, etag_store_encode, NULL);
  if (ret <= 0) {
    OC_ERR("failed to dump etag for device %zu", device);
    return false;
  }
  return true;
}

bool
oc_etag_dump(void)
{
  bool success = true;
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    if (!oc_etag_dump_for_device(i)) {
      success = false;
    }
  }
  return success;
}

typedef struct etag_update_from_rep_data_t
{
  const oc_rep_t *rep;
  uint64_t *etag;
} etag_update_from_rep_data_t;

static bool
etag_iterate_update_resources_by_rep(oc_resource_t *resource, void *data)
{
  etag_update_from_rep_data_t *rep_data = (etag_update_from_rep_data_t *)data;
  oc_rep_t *res_rep;
  if (!oc_rep_get_object(rep_data->rep, oc_string(resource->uri), &res_rep)) {
    OC_DBG("no representation for resource %s", oc_string(resource->uri));
    return true;
  }

  int64_t etag = 0;
  if (!oc_rep_get_int(res_rep, "etag", &etag) || etag < 0 ||
      etag == OC_ETAG_UNINITIALIZED) {
    OC_DBG("ignoring invalid etag for resource %s", oc_string(resource->uri));
    return true;
  }

  oc_resource_set_etag(resource, (uint64_t)etag);
  if ((uint64_t)etag > *rep_data->etag) {
    *rep_data->etag = (uint64_t)etag;
  }
  return true;
}

static bool
etag_iterate_clear_etag(oc_resource_t *resource, void *data)
{
  (void)data;
  oc_resource_set_etag(resource, OC_ETAG_UNINITIALIZED);
  return true;
}

static int
etag_store_decode_etags(const oc_rep_t *rep, size_t device, void *data)
{
  // iterate all resources update etag from rep and find the max etag value in
  // rep
  uint64_t *etag = (uint64_t *)data;
  etag_update_from_rep_data_t rep_data = { rep, etag };
  oc_resources_iterate(device, device == 0, true, true, true,
                       etag_iterate_update_resources_by_rep, &rep_data);
  return 0;
}

static bool
etag_iterate_update_empty_etag(oc_resource_t *resource, void *data)
{
  (void)data;
  if (oc_resource_get_etag(resource) == OC_ETAG_UNINITIALIZED) {
    oc_resource_set_etag(resource, oc_etag_get());
  }
  return true;
}

bool
oc_etag_load_from_storage(bool from_storage_only)
{
  bool success = true;
  // load g_etag and resource etags from storage
  uint64_t etag = oc_clock_time();
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    if (!from_storage_only) {
      // clear all etags
      oc_resources_iterate(i, i == 0, true, true, true, etag_iterate_clear_etag,
                           NULL);
    }

    // load etags from storage
    long ret = oc_storage_data_load(OC_ETAG_STORE_NAME, i,
                                    etag_store_decode_etags, &etag);
    if (ret <= 0) {
      OC_DBG("failed to load etags for device %zu", i);
      success = false;
    }
  }
  etag += etag_random();
  oc_etag_set_global(etag);
  OC_DBG("g_tag: %" PRIu64, oc_etag_global());

  if (!from_storage_only) {
    // update empty etags
    for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
      oc_resources_iterate(i, i == 0, true, true, true,
                           etag_iterate_update_empty_etag, NULL);
    }
  }
  return success;
}

bool
oc_etag_load_and_clear(void)
{
  bool success = oc_etag_load_from_storage(false);
  success = oc_etag_clear_storage() && success;
  return success;
}

#endif /* OC_STORAGE */

void
oc_resource_set_etag(oc_resource_t *resource, uint64_t etag)
{
  assert(resource != NULL);
  resource->etag = etag;
  OC_DBG("oc_etag: set resource %s etag to %" PRIu64, oc_string(resource->uri),
         etag);
}

uint64_t
oc_resource_get_etag(const oc_resource_t *resource)
{
  assert(resource != NULL);
  return resource->etag;
}

void
oc_resource_update_etag(oc_resource_t *resource)
{
  oc_resource_set_etag(resource, oc_etag_get());
}

#endif /* OC_HAS_FEATURE_ETAG */
