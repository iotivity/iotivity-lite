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

#ifndef PLGD_DPS_ENDPOINT_INTERNAL_H
#define PLGD_DPS_ENDPOINT_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "plgd_dps_context_internal.h"
#include "plgd_dps_log_internal.h"

#include "oc_config.h"
#include "oc_endpoint.h"
#include "security/oc_tls_internal.h" // oc_tls_peer_t
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

enum {
  PLGD_DPS_ENABLE_SELECT_IDENTITY_CERT_CHAIN = -1,
  PLGD_DPS_DISABLE_SELECT_IDENTITY_CERT_CHAIN = -2,
};

/**
 * @brief Initialize endpoint field parsing the provided string value.
 *
 * Function checks if ctx->endpoint field is empty and if it is, it initializes
 * by parsing the provided string value.
 *
 * @param ctx device context (cannot be NULL)
 * @param ep_str endpoint in string format
 * @return int 	0 	if endpoint is already set or has been successfully parsed
 * 				<0	on error
 */
OC_NO_DISCARD_RETURN
int dps_endpoint_init(plgd_dps_context_t *ctx, const oc_string_t *ep_str)
  OC_NONNULL(1);

/**
 * @brief Add endpoint to trusted peers without authorization.
 *
 * @param endpoint endpoint to add as peer
 * @return int 	0 	peer was created/found and added to trusted peers
 * 				-1	on error
 */
int dps_endpoint_add_unauthorized_peer(const oc_endpoint_t *endpoint);

/// @brief Close endpoint connection.
void dps_endpoint_close(const oc_endpoint_t *endpoint);

/// @brief Close endpoint connection, reset endpoint and set disconnected state.
void dps_endpoint_disconnect(plgd_dps_context_t *ctx);

/// @brief Check if endpoint is set to empty value.
bool dps_endpoint_is_empty(const oc_endpoint_t *endpoint);

/**
 * @brief Write endpoint address and session id ("endpoint(addr=%s,
 * session_id=%d)") to buffer.
 *
 * @param endpoint endpoint
 * @param[out] buffer output buffer
 * @param buffer_size size of the output buffer
 * @return true on success
 * @return false on failure
 */
bool dps_endpoint_log_string(const oc_endpoint_t *endpoint, char *buffer,
                             size_t buffer_size);

/**
 * @brief setup TLS for establishing a secure connection to DPS
 *
 * @param ctx dps context (cannot be NULL)
 */
void dps_setup_tls(const plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Reset TLS configuration for establishing a secure connection.
void dps_reset_tls(void);

/**
 * @brief Add endpoint to with configured mbedtls TLS.
 *
 * @param endpoint endpoint to add as peer
 * @return oc_tls_peer_t* pointer to peer or NULL on error
 */
oc_tls_peer_t *dps_endpoint_add_peer(const oc_endpoint_t *endpoint)
  OC_NONNULL();

#if DPS_DBG_IS_ENABLED
/// @brief Print peers.
void dps_endpoint_print_peers(const oc_endpoint_t *endpoint);
#endif /* DPS_DBG_IS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_ENDPOINT_INTERNAL_H */
