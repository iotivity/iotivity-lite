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

#include "api/oc_discovery_internal.h"
#include "api/oc_etag_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_rep_decode_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/options_internal.h"
#include "oc_base64.h"
#include "oc_core_res.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "util/oc_macros_internal.h"
#include "util/oc_mmem_internal.h"

#ifdef OC_SECURITY
#include "oc_csr.h"
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_STORAGE
#include "api/oc_storage_internal.h"
#include "util/oc_crc_internal.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS */

#endif /* OC_STORAGE */

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(OC_STORAGE) && !defined(OC_HAS_FEATURE_CRC_ENCODER)
#error "CRC encoder must be enabled to use the ETag feature with storage"
#endif /* OC_STORAGE && !OC_HAS_FEATURE_CRC_ENCODER */

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
  if (!oc_storage_data_clear(OC_ETAG_PLATFORM_STORE_NAME, 0)) {
    OC_ERR("failed to clear etag storage for platform resources");
    success = false;
  }
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    if (!oc_storage_data_clear(OC_ETAG_STORE_NAME, i)) {
      OC_ERR("failed to clear etag storage for device %zu", i);
      success = false;
    }
  }
  return success;
}

bool
oc_etag_dump_ignore_resource(const char *uri, size_t uri_len)
{
#ifdef OC_WKCORE
  if (uri_len == OC_CHAR_ARRAY_LEN(OC_WELLKNOWNCORE_URI) &&
      memcmp(uri, OC_WELLKNOWNCORE_URI, uri_len) == 0) {
    return true;
  }
#endif /* OC_WKCORE */
#ifdef OC_SECURITY
  if (uri_len == OC_CHAR_ARRAY_LEN(OCF_SEC_CSR_URI) &&
      memcmp(uri, OCF_SEC_CSR_URI, uri_len) == 0) {
    return true;
  }
#endif /* OC_SECURITY */
  (void)uri;
  (void)uri_len;
  return false;
}

oc_resource_encode_status_t
oc_etag_encode_resource_etag(CborEncoder *encoder, oc_resource_t *resource)
{
  oc_string_view_t uri = oc_string_view2(&resource->uri);
  uint64_t etag = oc_resource_get_etag(resource);
  if (etag == OC_ETAG_UNINITIALIZED) {
    OC_DBG("skipping uninitialized etag for resource %s", uri.data);
    return OC_RESOURCE_ENCODE_SKIPPED;
  }

  uint64_t crc64 = 0;
  if (oc_resource_get_crc64(resource, &crc64) != OC_RESOURCE_CRC64_OK) {
    OC_DBG("cannot calculate crc64 for device(%zu) resource(%s)",
           resource->device, uri.data);
    return OC_RESOURCE_ENCODE_SKIPPED;
  }

  CborError err = oc_rep_encode_text_string(encoder, uri.data, uri.length);
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  err |= oc_rep_encoder_create_map(encoder, &etag_map, CborIndefiniteLength);
  err |=
    oc_rep_encode_text_string(&etag_map, "etag", OC_CHAR_ARRAY_LEN("etag"));
  err |= oc_rep_encode_uint(&etag_map, etag);
  err |= oc_rep_encode_text_string(&etag_map, "crc", OC_CHAR_ARRAY_LEN("crc"));
  err |= oc_rep_encode_uint(&etag_map, crc64);
  err |= oc_rep_encoder_close_container(encoder, &etag_map);

  if (err != CborNoError) {
    OC_ERR("failed to encode device(%zu) resource %s", resource->device,
           uri.data);
    g_err |= err;
    return OC_RESOURCE_ENCODE_ERROR;
  }
  return OC_RESOURCE_ENCODE_OK;
}

static bool
etag_iterate_encode_resource(oc_resource_t *resource, void *data)
{
  (void)data;
  oc_string_view_t uri = oc_string_view2(&resource->uri);
  OC_DBG("encoding resource [%zu:%s]", resource->device, uri.data);
  if (oc_etag_dump_ignore_resource(uri.data, uri.length)) {
    OC_DBG("skipping resource %s", uri.data);
    return true;
  }
  return oc_etag_encode_resource_etag(oc_rep_object(root), resource) !=
         OC_RESOURCE_ENCODE_ERROR;
}

typedef struct etag_encode_data_t
{
  bool platform_only;
} etag_encode_data_t;

static int
etag_store_encode(size_t device, void *data)
{
  etag_encode_data_t *encode_data = (etag_encode_data_t *)data;
  oc_rep_start_root_object();
  oc_resources_iterate(device, encode_data->platform_only,
                       !encode_data->platform_only, !encode_data->platform_only,
                       !encode_data->platform_only,
                       etag_iterate_encode_resource, NULL);
  oc_rep_end_root_object();
  return oc_rep_get_cbor_errno();
}

static bool
etag_dump_platform_resources(void)
{
  etag_encode_data_t encode_data = { true };
  long ret = oc_storage_data_save(OC_ETAG_PLATFORM_STORE_NAME, 0,
                                  etag_store_encode, &encode_data);
  if (ret <= 0) {
    OC_ERR("failed to dump etag for platform resources");
    return false;
  }
  return true;
}

bool
oc_etag_dump(void)
{
  bool success = etag_dump_platform_resources();
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    etag_encode_data_t encode_data = { false };
    if (oc_storage_data_save(OC_ETAG_STORE_NAME, i, etag_store_encode,
                             &encode_data) <= 0) {
      OC_ERR("failed to dump etag for device %zu", i);
      success = false;
    }
  }
  return success;
}

bool
oc_etag_decode_resource_etag(oc_resource_t *resource, const oc_rep_t *rep,
                             uint64_t *etag)
{
  int64_t etag_store = 0;
  if (!oc_rep_get_int(rep, "etag", &etag_store) ||
      etag_store == OC_ETAG_UNINITIALIZED) {
    OC_DBG("etag missing or invalid for resource %zu:%s", resource->device,
           oc_string(resource->uri));
    return false;
  }

  int64_t crc64_store = 0;
  if (!oc_rep_get_int(rep, "crc", &crc64_store)) {
    OC_DBG("no checksum for resource %zu:%s", resource->device,
           oc_string(resource->uri));
    return false;
  }

  uint64_t crc64 = 0;
  if (oc_resource_get_crc64(resource, &crc64) != OC_RESOURCE_CRC64_OK) {
    OC_DBG("cannot calculate crc64 for resource %zu:%s", resource->device,
           oc_string(resource->uri));
    return false;
  }

  if ((uint64_t)crc64_store != crc64) {
    OC_DBG("ignoring invalid checksum for resource %zu:%s: store (%" PRIu64
           ") vs current(%" PRIu64 ")",
           resource->device, oc_string(resource->uri), (uint64_t)crc64_store,
           crc64);
    return false;
  }
  *etag = (uint64_t)etag_store;
  return true;
}

typedef struct etag_update_from_rep_data_t
{
  const oc_rep_t *rep;
  uint64_t *etag;
  bool update_device_resources;
} etag_update_from_rep_data_t;

static bool
etag_iterate_update_resources_by_rep(oc_resource_t *resource, void *data)
{
  etag_update_from_rep_data_t *rep_data = (etag_update_from_rep_data_t *)data;
  oc_rep_t *res_rep;
  if (!oc_rep_get_object(rep_data->rep, oc_string(resource->uri), &res_rep)) {
    OC_DBG("no representation for resource %zu:%s", resource->device,
           oc_string(resource->uri));
    return true;
  }

  uint64_t etag;
  if (!oc_etag_decode_resource_etag(resource, res_rep, &etag)) {
    OC_DBG("failed to decode etag for resource %zu:%s", resource->device,
           oc_string(resource->uri));
    return true;
  }

  if (etag > *rep_data->etag) {
    *rep_data->etag = etag;
  }
  if (rep_data->update_device_resources) {
    oc_resource_set_etag(resource, etag);
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

typedef struct etag_decode_data_t
{
  uint64_t *etag;
  bool platform_only;
  bool update_device_resources;
} etag_decode_data_t;

static int
etag_store_decode_etags(const oc_rep_t *rep, size_t device, void *data)
{
  // iterate all resources update etag from rep and find the max etag value in
  // rep
  etag_decode_data_t *decode_data = (etag_decode_data_t *)data;
  etag_update_from_rep_data_t rep_data = {
    rep, decode_data->etag, decode_data->update_device_resources
  };
  oc_resources_iterate(device, decode_data->platform_only,
                       !decode_data->platform_only, !decode_data->platform_only,
                       !decode_data->platform_only,
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

static bool
etag_can_update_device(size_t device)
{
#ifdef OC_SECURITY
  return oc_sec_pstat_is_in_dos_state(device,
                                      OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP));
#else  /* OC_SECURITY */
  (void)device;
  return true;
#endif /* OC_SECURITY */
}

bool
oc_etag_load_from_storage(bool from_storage_only)
{
  bool success = true;
  // load g_etag and resource etags from storage
  uint64_t etag = oc_etag_get();

  if (!from_storage_only) {
    // clear etags of platform resources
    oc_resources_iterate(0, true, false, false, false, etag_iterate_clear_etag,
                         NULL);
  }
  etag_decode_data_t decode_data = { &etag, true, true };
  if (oc_storage_data_load(OC_ETAG_PLATFORM_STORE_NAME, 0,
                           etag_store_decode_etags, &decode_data) <= 0) {
    OC_DBG("failed to load etags for platform resources");
    success = false;
  }

  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    bool can_update_device = etag_can_update_device(i);
    if (!from_storage_only && can_update_device) {
      // clear all resource etags of given device
      oc_resources_iterate(i, false, true, true, true, etag_iterate_clear_etag,
                           NULL);
    }

    // load etags from storage
    decode_data.platform_only = false;
    decode_data.update_device_resources = can_update_device;
    if (oc_storage_data_load(OC_ETAG_STORE_NAME, i, etag_store_decode_etags,
                             &decode_data) <= 0) {
      OC_DBG("failed to load etags for device %zu", i);
      success = false;
    }
  }
  etag += etag_random();
  oc_etag_set_global(etag);
  OC_DBG("g_tag: %" PRIu64, oc_etag_global());

  if (!from_storage_only) {
    // update empty etags of platform resources
    oc_resources_iterate(0, true, false, false, false,
                         etag_iterate_update_empty_etag, NULL);

    // update empty etags of resources of all devices
    for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
      if (!etag_can_update_device(i)) {
        continue;
      }
      oc_resources_iterate(i, false, true, true, true,
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

static bool
resource_get_payload_by_encoder(oc_rep_encoder_type_t type,
                                oc_resource_t *resource,
                                oc_interface_mask_t iface,
                                oc_response_buffer_t *response_buffer,
                                size_t buffer_max_size)
{
  oc_rep_encoder_set_type(type);

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  response.response_buffer = response_buffer;
  request.response = &response;
  request.resource = resource;
  request.method = OC_GET;

#ifdef OC_DYNAMIC_ALLOCATION
  if (buffer_max_size != 0) {
    oc_rep_new_realloc_v1(&response_buffer->buffer,
                          response_buffer->buffer_size, buffer_max_size);
  } else {
    oc_rep_new_v1(response_buffer->buffer, response_buffer->buffer_size);
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  (void)buffer_max_size;
  oc_rep_new_v1(response_buffer->buffer, response_buffer->buffer_size);
#endif /* !OC_DYNAMIC_ALLOCATION */

#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
  if (oc_check_if_collection(resource)) {
    if (!oc_handle_collection_request(OC_GET, &request, iface, NULL)) {
      OC_ERR("cannot calculate crc64 for device(%zu) resource(%s): failed to "
             "handle collection request",
             resource->device, oc_string(resource->uri));
      return false;
    }
    return true;
  }
#endif /* OC_SERVER && OC_COLLECTIONS */
  resource->get_handler.cb(&request, iface, resource->get_handler.user_data);
  return true;
}

#if OC_DBG_IS_ENABLED

static void
resource_print_payload(oc_resource_t *resource, oc_interface_mask_t iface)
{
  // GCOVR_EXCL_START
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer = calloc(1, OC_MIN_APP_DATA_SIZE);
  if (buffer == NULL) {
    return;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MIN_APP_DATA_SIZE] = { 0 };
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_APP_DATA_SIZE;

  if (!resource_get_payload_by_encoder(OC_REP_CBOR_ENCODER, resource, iface,
                                       &response_buffer,
                                       OC_MAX_APP_DATA_SIZE)) {
#ifdef OC_DYNAMIC_ALLOCATION
    free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
    return;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  // might have been reallocated by the handler
  buffer = response_buffer.buffer;
#else  /* !OC_DYNAMIC_ALLOCATION */
  size_t avail_bytes = oc_mmem_available_size(BYTE_POOL);
  if (avail_bytes < response_buffer.response_length) {
    OC_DBG("not enough memory to print payload of resource(%s)",
           oc_string(resource->uri));
    return;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_rep_decoder_t decoder = oc_rep_decoder(OC_REP_CBOR_DECODER);
  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
  oc_rep_t *rep = NULL;
  if (CborNoError != decoder.parse(response_buffer.buffer,
                                   response_buffer.response_length, &rep)) {
    oc_rep_set_pool(prev_rep_objects);
#ifdef OC_DYNAMIC_ALLOCATION
    free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  size_t json_size = oc_rep_to_json(rep, NULL, 0, true);
  char *json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
#else  /* !OC_DYNAMIC_ALLOCATION */
  char json[4096] = { 0 };
  oc_rep_to_json(rep, json, OC_ARRAY_SIZE(json), true);
#endif /* OC_DYNAMIC_ALLOCATION */
  OC_DBG("Resource(%s) payload: %s", oc_string(resource->uri), json);
  oc_free_rep(rep);
  oc_rep_set_pool(prev_rep_objects);
#ifdef OC_DYNAMIC_ALLOCATION
  free(json);
  free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  // GCOVR_EXCL_STOP
}

#endif /* OC_DBG_IS_ENABLED */

oc_resource_crc64_status_t
oc_resource_get_crc64(oc_resource_t *resource, uint64_t *crc64)
{
  assert(resource != NULL);
  assert(crc64 != NULL);

  bool is_collection = false;
#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
  if (oc_check_if_collection(resource)) {
    is_collection = true;
  }
#endif /* OC_SERVER && OC_COLLECTIONS */

  if (!is_collection && resource->get_handler.cb == NULL) {
    OC_ERR("cannot calculate crc64 for device(%zu) resource(%s): get handler "
           "not available",
           resource->device, oc_string(resource->uri));
    return OC_RESOURCE_CRC64_ERROR;
  }

  oc_rep_encoder_reset_t prevEncoder = oc_rep_global_encoder_reset(NULL);

  oc_interface_mask_t iface = OC_IF_BASELINE;
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
  if (oc_resource_supports_interface(resource, PLGD_IF_ETAG)) {
    iface = PLGD_IF_ETAG;
  }
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */

#if OC_DBG_IS_ENABLED
  resource_print_payload(resource, iface);
#endif /* OC_DBG_IS_ENABLED */

  uint8_t buffer[sizeof(*crc64)] = { 0 };
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_ARRAY_SIZE(buffer);
  if (!resource_get_payload_by_encoder(OC_REP_CRC_ENCODER, resource, iface,
                                       &response_buffer, 0)) {
    return OC_RESOURCE_CRC64_ERROR;
  }

  int payload_size = oc_rep_get_encoded_payload_size();
  if (payload_size == 0) {
    OC_DBG("ignoring empty payload for device(%zu) resource(%s)",
           resource->device, oc_string(resource->uri));
    oc_rep_global_encoder_reset(&prevEncoder);
    return OC_RESOURCE_CRC64_NO_PAYLOAD;
  }

  if (payload_size != sizeof(*crc64)) {
    OC_ERR("cannot calculate crc64 for device(%zu) resource(%s): failed to "
           "encode payload",
           resource->device, oc_string(resource->uri));
    oc_rep_global_encoder_reset(&prevEncoder);
    return -1;
  }
  memcpy(crc64, buffer, sizeof(*crc64));

  oc_rep_global_encoder_reset(&prevEncoder);
  return OC_RESOURCE_CRC64_OK;
}

#endif /* OC_STORAGE */

#ifdef OC_SECURITY

static bool
etag_iterate_reset_etag(oc_resource_t *resource, void *data)
{
  (void)data;
  oc_resource_set_etag(resource, oc_etag_get());
  return true;
}

void
oc_etag_on_reset(size_t device)
{
  // reset all resource etags of given device
  oc_resources_iterate(device, false, true, true, true, etag_iterate_reset_etag,
                       NULL);
#ifdef OC_STORAGE
  oc_storage_data_clear(OC_ETAG_STORE_NAME, device);
#endif /* OC_STORAGE */
}

#endif /* OC_SECURITY */

void
oc_resource_set_etag(oc_resource_t *resource, uint64_t etag)
{
  assert(resource != NULL);
  resource->etag = etag;
  OC_DBG("oc_etag: set resource %zu:%s etag to %" PRIu64, resource->device,
         oc_string(resource->uri), etag);
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
