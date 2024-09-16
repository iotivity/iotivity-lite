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

#ifndef PLGD_DPS_APIS_INTERNAL_H
#define PLGD_DPS_APIS_INTERNAL_H

#include "plgd/plgd_dps.h"

#include "oc_api.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Compare oc_string_t with a C-string with len
OC_NO_DISCARD_RETURN
bool dps_is_equal_string_len(oc_string_t str1, const char *str2,
                             size_t str2_len);

/// @brief Compare 2 oc_string_t
OC_NO_DISCARD_RETURN
bool dps_is_equal_string(oc_string_t str1, oc_string_t str2);

/// @brief Check if oc_rep_t is a property with a given name and type
OC_NO_DISCARD_RETURN
bool dps_is_property(const oc_rep_t *rep, oc_rep_value_type_t ptype,
                     const char *pname, size_t pname_len) OC_NONNULL();

/// @brief Remove scheduled callback (if it exists) and schedule it again
void dps_reset_delayed_callback(void *cb_data, oc_trigger_t callback,
                                uint64_t seconds);

/// @brief Remove scheduled callback (if it exists) and schedule it again
/// (interval in milliseconds)
void dps_reset_delayed_callback_ms(void *cb_data, oc_trigger_t callback,
                                   uint64_t milliseconds);

/// @brief Check if status code is the request timeout error
/// (OC_REQUEST_TIMEOUT)
bool dps_is_timeout_error_code(oc_status_t code);

/// @brief Check if status code is a request connection error
/// (OC_STATUS_SERVICE_UNAVAILABLE, OC_STATUS_GATEWAY_TIMEOUT)
bool dps_is_connection_error_code(oc_status_t code);

/// @brief Check if status code is an error code.
bool dps_is_error_code(oc_status_t code);

/// @brief Handle DPS redirect response
OC_NO_DISCARD_RETURN
bool dps_handle_redirect_response(plgd_dps_context_t *ctx,
                                  const oc_rep_t *payload) OC_NONNULL();

/**
 * @brief Check DPS service response for errors or redirect.
 *
 * @param ctx device context (cannot be NULL)
 * @param code response status code
 * @param payload payload to check for redirect
 * @return PLGD_DPS_OK on success
 * @return >PLGD_DPS_OK on error
 */
OC_NO_DISCARD_RETURN
plgd_dps_error_t dps_check_response(plgd_dps_context_t *ctx, oc_status_t code,
                                    const oc_rep_t *payload) OC_NONNULL(1);

/// @brief Convert oc_status_t code from request response to plgd_dps_error_t
OC_NO_DISCARD_RETURN
plgd_dps_error_t dps_response_get_error_code(oc_status_t code);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_APIS_INTERNAL_H */
