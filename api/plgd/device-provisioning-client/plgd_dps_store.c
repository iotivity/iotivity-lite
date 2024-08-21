/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#include "plgd_dps_apis_internal.h"
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_endpoints_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_store_internal.h"

#include "api/oc_rep_internal.h"
#include "oc_helpers.h"           // oc_string, oc_string_len
#include "port/oc_connectivity.h" // OC_MAX_APP_DATA_SIZE
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_macros_internal.h"

#include <stdint.h>
#include <string.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_STORAGE
#error OC_STORAGE is not defined check oc_config.h and make sure OC_STORAGE is defined
#endif

#define DPS_STORE_NAME "dps"
#define DPS_STORE_ENDPOINT "ep"
#define DPS_STORE_ENDPOINT_NAME "epname"
#define DPS_STORE_ENDPOINTS "eps"
#define DPS_STORE_ENDPOINTS_URI "uri"
#define DPS_STORE_ENDPOINTS_NAME "name"
#define DPS_STORE_OWNER "owner"
#define DPS_STORE_HAS_BEEN_PROVISIONED_SINCE_RESET                             \
  "hasBeenProvisionedSinceReset"

// NOLINTNEXTLINE(modernize-*)
#define DPS_TAG_MAX (32)

oc_event_callback_retval_t
dps_store_dump_handler(void *data)
{
  const plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  if (dps_store_dump(&ctx->store, ctx->device) != 0) {
    DPS_ERR("[DPS_STORE] failed to dump storage in async handler");
  }
  return OC_EVENT_DONE;
}

void
dps_store_dump_async(plgd_dps_context_t *ctx)
{
  dps_reset_delayed_callback(ctx, dps_store_dump_handler, 0);
  _oc_signal_event_loop();
}

void
dps_store_init(plgd_dps_store_t *store,
               on_selected_endpoint_address_change_fn_t on_dps_endpoint_change,
               void *on_dps_endpoint_change_data)
{
  dps_store_deinit(store);
  dps_endpoints_init(&store->endpoints, on_dps_endpoint_change,
                     on_dps_endpoint_change_data);
}

void
dps_store_deinit(plgd_dps_store_t *store)
{
  oc_endpoint_addresses_deinit(&store->endpoints);
  oc_set_string(&store->owner, NULL, 0);
  store->has_been_provisioned_since_reset = false;
}

bool
dps_store_set_endpoints(plgd_dps_store_t *store,
                        const oc_string_t *selected_uri,
                        const oc_string_t *selected_name,
                        const oc_rep_t *endpoints)
{
  if (!oc_endpoint_addresses_reinit(
        &store->endpoints,
        oc_endpoint_address_make_view_with_name(
          oc_string_view2(selected_uri), oc_string_view2(selected_name)))) {
    return false;
  }
  if (endpoints == NULL) {
    return true;
  }

  for (const oc_rep_t *ep = endpoints; ep != NULL; ep = ep->next) {
    const oc_rep_t *rep = oc_rep_get_by_type_and_key(
      ep->value.object, OC_REP_STRING, DPS_STORE_ENDPOINTS_URI,
      OC_CHAR_ARRAY_LEN(DPS_STORE_ENDPOINTS_URI));
    if (rep == NULL) {
      DPS_ERR("[DPS_STORE] invalid endpoint element: uri missing");
      continue;
    }
    oc_string_view_t uri = oc_string_view2(&rep->value.string);

    oc_string_view_t name = OC_STRING_VIEW_NULL;
    rep = oc_rep_get_by_type_and_key(
      ep->value.object, OC_REP_STRING, DPS_STORE_ENDPOINTS_NAME,
      OC_CHAR_ARRAY_LEN(DPS_STORE_ENDPOINTS_NAME));
    if (rep != NULL) {
      name = oc_string_view2(&rep->value.string);
    }

    if (oc_endpoint_addresses_contains(&store->endpoints, uri)) {
      DPS_DBG("[DPS_STORE] cannot add endpoint:uri(%s) already exists",
              uri.data);
      continue;
    }

    if (!oc_endpoint_addresses_add(
          &store->endpoints,
          oc_endpoint_address_make_view_with_name(uri, name))) {
      return false;
    }
    DPS_DBG("[DPS_STORE] added endpoint [uri=%s, name=%s]", uri.data,
            name.data != NULL ? name.data : "(null)");
  }

  return true;
}

void
dps_store_decode(const oc_rep_t *rep, plgd_dps_store_t *store)
{
  typedef struct
  {
    const oc_rep_t *endpoints;
    const oc_string_t *endpoint;
    const oc_string_t *endpoint_name;
    const oc_string_t *owner;
    const bool *has_been_provisioned_since_reset;
  } dps_store_data_t;
  dps_store_data_t dsd;
  memset(&dsd, 0, sizeof(dps_store_data_t));

  for (const oc_rep_t *store_rep = rep; store_rep != NULL;
       store_rep = store_rep->next) {
    if (dps_is_property(store_rep, OC_REP_OBJECT_ARRAY, DPS_STORE_ENDPOINTS,
                        OC_CHAR_ARRAY_LEN(DPS_STORE_ENDPOINTS))) {
      dsd.endpoints = store_rep->value.object_array;
      continue;
    }
    if (dps_is_property(store_rep, OC_REP_STRING, DPS_STORE_ENDPOINT,
                        OC_CHAR_ARRAY_LEN(DPS_STORE_ENDPOINT))) {
      dsd.endpoint = &store_rep->value.string;
      continue;
    }
    if (dps_is_property(store_rep, OC_REP_STRING, DPS_STORE_ENDPOINT_NAME,
                        OC_CHAR_ARRAY_LEN(DPS_STORE_ENDPOINT_NAME))) {
      dsd.endpoint_name = &store_rep->value.string;
      continue;
    }
    if (dps_is_property(store_rep, OC_REP_STRING, DPS_STORE_OWNER,
                        OC_CHAR_ARRAY_LEN(DPS_STORE_OWNER))) {
      dsd.owner = &store_rep->value.string;
      continue;
    }
    if (dps_is_property(
          store_rep, OC_REP_BOOL, DPS_STORE_HAS_BEEN_PROVISIONED_SINCE_RESET,
          OC_CHAR_ARRAY_LEN(DPS_STORE_HAS_BEEN_PROVISIONED_SINCE_RESET))) {
      dsd.has_been_provisioned_since_reset = &store_rep->value.boolean;
      continue;
    }
    DPS_ERR("[DPS_STORE] Unknown property %s", oc_string(store_rep->name));
  }

#if DPS_DBG_IS_ENABLED
  // GCOVR_EXCL_START
  oc_string_view_t endpointv = oc_string_view2(dsd.endpoint);
  oc_string_view_t endpoint_namev = oc_string_view2(dsd.endpoint_name);
  oc_string_view_t ownerv = oc_string_view2(dsd.owner);
  DPS_DBG("[DPS_STORE] endpoint: %s, endpoint_name: %s, owner: %s, "
          "has_been_provisioned_since_reset: %s",
          endpointv.length > 0 ? endpointv.data : "(null)",
          endpoint_namev.length > 0 ? endpoint_namev.data : "(null)",
          ownerv.length > 0 ? ownerv.data : "(null)",
          dsd.has_been_provisioned_since_reset != NULL
            ? (*dsd.has_been_provisioned_since_reset ? "true" : "false")
            : "(null)");
  // GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */

  if ((dsd.endpoints != NULL || !oc_string_is_null_or_empty(dsd.endpoint)) &&
      !dps_store_set_endpoints(store, dsd.endpoint, dsd.endpoint_name,
                               dsd.endpoints)) {
    DPS_WRN("[DPS_STORE] failed to set endpoints");
  }
  if (!oc_string_is_null_or_empty(dsd.owner)) {
    oc_copy_string(&store->owner, dsd.owner);
  }
  if (dsd.has_been_provisioned_since_reset != NULL) {
    store->has_been_provisioned_since_reset =
      *dsd.has_been_provisioned_since_reset;
  }
}

static void
dps_store_gen_tag(const char *name, size_t device, char *dps_tag)
{
  int dps_tag_len = snprintf(dps_tag, DPS_TAG_MAX, "%s_%zd", name, device);
  dps_tag_len =
    (dps_tag_len < DPS_TAG_MAX - 1) ? dps_tag_len + 1 : DPS_TAG_MAX - 1;
  dps_tag[dps_tag_len] = '\0';
}

static long
dps_store_get_storage(size_t device, uint8_t *buffer, size_t buffer_size)
{
  char dps_tag[DPS_TAG_MAX];
  dps_store_gen_tag(DPS_STORE_NAME, device, dps_tag);
  return oc_storage_read(dps_tag, buffer, buffer_size);
}

static void
dps_store_rep_set_text_string(CborEncoder *object_map, const char *key,
                              size_t key_len, const char *value,
                              size_t value_len)
{
  g_err |= oc_rep_encode_text_string(object_map, key, key_len);
  if (value != NULL) {
    g_err |= oc_rep_encode_text_string(object_map, value, value_len);
  } else {
    g_err |= oc_rep_encode_text_string(object_map, "", 0);
  }
}

static void
dps_store_rep_set_bool(CborEncoder *object_map, const char *key, size_t keylen,
                       bool value)
{
  g_err |= oc_rep_encode_text_string(object_map, key, keylen);
  g_err |= oc_rep_encode_boolean(object_map, value);
}

static void
dps_store_encode_with_map(CborEncoder *object_map,
                          const plgd_dps_store_t *store)
{
  const oc_endpoint_address_t *selected =
    oc_endpoint_addresses_selected(&store->endpoints);
  if (selected != NULL) {
    oc_endpoint_address_encode(object_map, OC_STRING_VIEW(DPS_STORE_ENDPOINT),
                               OC_STRING_VIEW_NULL,
                               OC_STRING_VIEW(DPS_STORE_ENDPOINT_NAME),
                               oc_endpoint_address_view(selected));
  }
  g_err |= oc_endpoint_addresses_encode(
    object_map, &store->endpoints, OC_STRING_VIEW(DPS_STORE_ENDPOINTS), true);
  dps_store_rep_set_text_string(
    object_map, DPS_STORE_OWNER, OC_CHAR_ARRAY_LEN(DPS_STORE_OWNER),
    oc_string(store->owner), oc_string_len(store->owner));
  dps_store_rep_set_bool(
    object_map, DPS_STORE_HAS_BEEN_PROVISIONED_SINCE_RESET,
    OC_CHAR_ARRAY_LEN(DPS_STORE_HAS_BEEN_PROVISIONED_SINCE_RESET),
    store->has_been_provisioned_since_reset);
}

int
dps_store_load(plgd_dps_store_t *store, size_t device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (buf == NULL) {
    DPS_ERR("[DPS_STORE] alloc failed!");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE] = { 0 };
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = dps_store_get_storage(device, buf, OC_MAX_APP_DATA_SIZE);
  if (size <= 0) {
    dps_store_deinit(store);
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
    return -2;
  }

  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  struct oc_memb *pool = oc_rep_reset_pool(&rep_objects);
  oc_rep_t *rep = oc_parse_rep(buf, (size_t)size);
  dps_store_decode(rep, store);
  oc_free_rep(rep);
  oc_rep_set_pool(pool); // Reset representation pool
#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return 0;
}

bool
dps_store_encode(const plgd_dps_store_t *store)
{
  oc_rep_start_root_object();
  dps_store_encode_with_map(&root_map, store);
  oc_rep_end_root_object();
  return oc_rep_get_cbor_errno() == CborNoError;
}

static int
dps_store_dump_internal(const char *store_name, const plgd_dps_store_t *store)
{
  assert(store_name != NULL);
  assert(store != NULL);

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (buf == NULL) {
    return -1;
  }
  oc_rep_new_realloc_v1(&buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MIN_APP_DATA_SIZE];
  oc_rep_new_v1(buf, OC_MIN_APP_DATA_SIZE);
#endif /* !OC_DYNAMIC_ALLOCATION */

  // Dumping dps and accesspoint information.
  if (!dps_store_encode(store)) {
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
    return -1;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  buf = oc_rep_shrink_encoder_buf(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  long size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    size = oc_storage_write(store_name, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  if (size >= 0) {
    return 0;
  }
  return (int)size;
}

int
dps_store_dump(const plgd_dps_store_t *store, size_t device)
{
  char dps_tag[DPS_TAG_MAX];
  dps_store_gen_tag(DPS_STORE_NAME, device, dps_tag);
  // Calling dump for dps and access point info
  return dps_store_dump_internal(dps_tag, store);
}
