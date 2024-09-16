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

#include "plgd_dps_context_internal.h"
#include "plgd_dps_apis_internal.h"
#include "plgd_dps_log_internal.h" // DPS_DBG
#include "plgd_dps_endpoint_internal.h"
#include "plgd/plgd_dps.h" // plgd_dps_context_t

#include "oc_api.h"     // oc_remove_delayed_callback
#include "oc_rep.h"     // oc_rep_get_by_type_and_key
#include "oc_ri.h"      // oc_ri_add_timed_event_callback_ticks
#include "oc_helpers.h" // oc_string_t
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <string.h>

bool
dps_is_equal_string_len(oc_string_t str1, const char *str2, size_t str2_len)
{
  if (oc_string(str1) == NULL) {
    return str2 == NULL;
  }
  return str2 != NULL && oc_string_len_unsafe(str1) == str2_len &&
         memcmp(oc_string(str1), str2, str2_len) == 0;
}

bool
dps_is_equal_string(oc_string_t str1, oc_string_t str2)
{
  return str1.size == str2.size &&
         (str1.size == 0 ||
          memcmp(oc_string(str1), oc_string(str2), str1.size) == 0);
}

bool
dps_is_property(const oc_rep_t *rep, oc_rep_value_type_t ptype,
                const char *pname, size_t pname_len)
{
  size_t prop_len = oc_string_len_unsafe(rep->name);
  const char *prop = oc_string(rep->name);
  return rep->type == ptype && prop_len == pname_len &&
         memcmp(prop, pname, pname_len) == 0;
}

static uint64_t
dps_get_time_max(void)
{
  if (sizeof(oc_clock_time_t) >= sizeof(uint64_t)) {
    return UINT64_MAX;
  }
  if (sizeof(oc_clock_time_t) >= sizeof(uint32_t)) {
    return UINT32_MAX;
  }
  return UINT16_MAX;
}

void
dps_reset_delayed_callback_ms(void *cb_data, oc_trigger_t callback,
                              uint64_t milliseconds)
{
  oc_remove_delayed_callback(cb_data, callback);
  const uint64_t oc_clock_time_max = dps_get_time_max();

#define MILLISECONDS_IN_SECONDS 1000
#define OC_CLOCK_MILLISECOND (OC_CLOCK_SECOND / MILLISECONDS_IN_SECONDS)
  if (oc_clock_time_max / OC_CLOCK_MILLISECOND < milliseconds) {
    DPS_DBG("delayed callback interval truncated to %lu", oc_clock_time_max);
    milliseconds = oc_clock_time_max / OC_CLOCK_MILLISECOND;
  }
  oc_clock_time_t interval = milliseconds * OC_CLOCK_MILLISECOND;
  oc_ri_add_timed_event_callback_ticks(cb_data, callback, interval);
}

void
dps_reset_delayed_callback(void *cb_data, oc_trigger_t callback,
                           uint64_t seconds)
{
#define MILLISECONDS_IN_SECONDS 1000
  dps_reset_delayed_callback_ms(cb_data, callback,
                                seconds * MILLISECONDS_IN_SECONDS);
}

bool
dps_is_timeout_error_code(oc_status_t code)
{
  return code == OC_REQUEST_TIMEOUT || code == OC_TRANSACTION_TIMEOUT;
}

bool
dps_is_connection_error_code(oc_status_t code)
{
  return code == OC_STATUS_SERVICE_UNAVAILABLE ||
         code == OC_STATUS_GATEWAY_TIMEOUT;
}

bool
dps_is_error_code(oc_status_t code)
{
  return code >= OC_STATUS_BAD_REQUEST;
}

plgd_dps_error_t
dps_response_get_error_code(oc_status_t code)
{
  if (dps_is_timeout_error_code(code) || dps_is_connection_error_code(code)) {
    return PLGD_DPS_ERROR_CONNECT;
  }
  if (dps_is_error_code(code)) {
    return PLGD_DPS_ERROR_RESPONSE;
  }
  return PLGD_DPS_OK;
}

bool
dps_handle_redirect_response(plgd_dps_context_t *ctx, const oc_rep_t *payload)
{
#define REDIRECTURI_KEY "redirecturi"
  const oc_rep_t *redirect =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, REDIRECTURI_KEY,
                               OC_CHAR_ARRAY_LEN(REDIRECTURI_KEY));
  if (redirect == NULL) {
    return true;
  }
  const oc_string_t *redirecturi = &redirect->value.string;
  if (oc_string_is_empty(redirecturi)) {
    DPS_ERR("invalid redirect uri");
    return false;
  }

  if (oc_endpoint_addresses_is_selected(&ctx->store.endpoints,
                                        oc_string_view2(redirecturi))) {
    return true;
  }
  DPS_INFO("Redirect to endpoint: %s detected", oc_string(*redirecturi));

  const oc_endpoint_address_t *ep_selected =
    oc_endpoint_addresses_selected(&ctx->store.endpoints);
  oc_string_view_t ep_selected_name = OC_STRING_VIEW_NULL;
  if (ep_selected != NULL) {
    assert(ep_selected->metadata.id_type ==
           OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME);
    ep_selected_name = oc_string_view2(&ep_selected->metadata.id.name);
  }

  if (!oc_endpoint_addresses_contains(&ctx->store.endpoints,
                                      oc_string_view2(redirecturi)) &&
      oc_endpoint_addresses_add(
        &ctx->store.endpoints,
        oc_endpoint_address_make_view_with_name(oc_string_view2(redirecturi),
                                                ep_selected_name)) == NULL) {
    DPS_ERR("failed to add endpoint to the list");
    return false;
  }

  // remove the original server from the list
  if (ep_selected != NULL) {
    oc_endpoint_addresses_remove(&ctx->store.endpoints, ep_selected);
  }
  // select the new server
  oc_endpoint_addresses_select_by_uri(&ctx->store.endpoints,
                                      oc_string_view2(redirecturi));
  dps_endpoint_disconnect(ctx);
  return true;
}

plgd_dps_error_t
dps_check_response(plgd_dps_context_t *ctx, oc_status_t code,
                   const oc_rep_t *payload)
{
  plgd_dps_error_t err = dps_response_get_error_code(code);
  if (err != PLGD_DPS_OK) {
    return err;
  }

  if (payload == NULL) {
    return PLGD_DPS_OK;
  }
  DPS_DBG("dps_check_response OK %p", (void *)payload);
  if (!dps_handle_redirect_response(ctx, payload)) {
    DPS_WRN("failed to handle redirect response");
  }
  return PLGD_DPS_OK;
}
