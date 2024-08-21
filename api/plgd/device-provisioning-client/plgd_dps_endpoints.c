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

#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_endpoints_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_store_internal.h"

#include "oc_helpers.h"
#include "util/oc_endpoint_address.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_memb.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>
#include <string.h>

OC_MEMB(g_dps_endpoint_address_pool, oc_endpoint_address_t,
        2 * OC_MAX_NUM_DEVICES);

int
dps_set_endpoint(plgd_dps_context_t *ctx, const char *endpoint,
                 size_t endpoint_len, bool notify)
{
  assert(ctx != NULL);
  assert(endpoint != NULL);
  DPS_DBG("DPS Service endpoint=%s", endpoint);

  if (oc_endpoint_addresses_size(&ctx->store.endpoints) == 1 &&
      oc_endpoint_addresses_contains(&ctx->store.endpoints,
                                     oc_string_view(endpoint, endpoint_len))) {
    DPS_DBG("DPS Service endpoint already set");
    return DPS_ENDPOINT_NOT_CHANGED;
  }
  dps_endpoint_disconnect(ctx);
  if (!oc_endpoint_addresses_reinit(
        &ctx->store.endpoints,
        oc_endpoint_address_make_view_with_name(
          oc_string_view(endpoint, endpoint_len), OC_STRING_VIEW_NULL))) {
    DPS_ERR("DPS Service failed to set endpoint");
    return -1;
  }
  if (notify) {
    dps_notify_observers(ctx);
  }
  DPS_INFO("DPS Service endpoint set to %s", endpoint);
  return DPS_ENDPOINT_CHANGED;
}

bool
dps_set_endpoints(plgd_dps_context_t *ctx, const oc_string_t *selected_endpoint,
                  const oc_string_t *selected_endpoint_name,
                  const oc_rep_t *endpoints)
{
  assert(ctx != NULL);
  bool changed = !oc_endpoint_addresses_is_selected(
    &ctx->store.endpoints, oc_string_view2(selected_endpoint));
  if (!dps_store_set_endpoints(&ctx->store, selected_endpoint,
                               selected_endpoint_name, endpoints)) {
    DPS_ERR("DPS Service failed to set endpoints");
    return false;
  }
  if (changed) {
    dps_endpoint_disconnect(ctx);
  }
  return true;
}

void
plgd_dps_set_endpoint(plgd_dps_context_t *ctx, const char *endpoint)
{
  size_t len = oc_strnlen(endpoint, OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH);
  assert(len < OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH);
  dps_set_endpoint(ctx, endpoint, len, /* notify */ true);
}

int
plgd_dps_get_endpoint(const plgd_dps_context_t *ctx, char *buffer,
                      size_t buffer_size)
{
  assert(ctx != NULL);
  assert(buffer != NULL);

  const oc_string_t *ep_addr =
    oc_endpoint_addresses_selected_uri(&ctx->store.endpoints);
  if (ep_addr == NULL) {
    DPS_DBG("No endpoint set");
    return 0;
  }
  if (buffer_size < ep_addr->size) {
    DPS_ERR(
      "cannot copy endpoint to buffer: buffer too small (minimal size=%zu)",
      ep_addr->size);
    return -1;
  }
  memcpy(buffer, ep_addr->ptr, ep_addr->size);
  return (int)ep_addr->size;
}

bool
plgd_dps_endpoint_is_empty(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return oc_endpoint_addresses_selected(&ctx->store.endpoints) == NULL;
}

bool
dps_endpoints_init(oc_endpoint_addresses_t *eas,
                   on_selected_endpoint_address_change_fn_t on_selected_change,
                   void *on_selected_change_data)
{
  return oc_endpoint_addresses_init(
    eas, &g_dps_endpoint_address_pool, on_selected_change,
    on_selected_change_data,
    oc_endpoint_address_make_view_with_name(OC_STRING_VIEW_NULL,
                                            OC_STRING_VIEW_NULL));
}

oc_endpoint_address_t *
plgd_dps_add_endpoint_address(plgd_dps_context_t *ctx, const char *uri,
                              size_t uri_len, const char *name, size_t name_len)
{
  return oc_endpoint_addresses_add(
    &ctx->store.endpoints,
    oc_endpoint_address_make_view_with_name(oc_string_view(uri, uri_len),
                                            oc_string_view(name, name_len)));
}

bool
plgd_dps_remove_endpoint_address(plgd_dps_context_t *ctx,
                                 const oc_endpoint_address_t *address)
{
  return oc_endpoint_addresses_remove(&ctx->store.endpoints, address);
}

void
plgd_dps_iterate_server_addresses(const plgd_dps_context_t *ctx,
                                  oc_endpoint_addresses_iterate_fn_t iterate_fn,
                                  void *iterate_fn_data)
{
  oc_endpoint_addresses_iterate(&ctx->store.endpoints, iterate_fn,
                                iterate_fn_data);
}

bool
plgd_dps_select_endpoint_address(plgd_dps_context_t *ctx,
                                 const oc_endpoint_address_t *address)
{
  return oc_endpoint_addresses_select(&ctx->store.endpoints, address);
}

const oc_endpoint_address_t *
plgd_dps_selected_endpoint_address(const plgd_dps_context_t *ctx)
{
  return oc_endpoint_addresses_selected(&ctx->store.endpoints);
}
