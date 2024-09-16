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

#ifndef PLGD_DPS_SECURITY_INTERNAL_H
#define PLGD_DPS_SECURITY_INTERNAL_H

#include "plgd/plgd_dps.h"
#include "plgd_dps_log_internal.h"

#include "oc_cred.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "security/oc_tls_internal.h"

#if DPS_DBG_IS_ENABLED
#include "mbedtls/build_info.h"
#include "mbedtls/md.h"
#endif /* DPS_DBG_IS_ENABLED */

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Check if device is in owned onboarding state.
bool dps_is_dos_owned(size_t device);

/// @brief Check if device is self-owned.
bool dps_is_self_owned(const plgd_dps_context_t *ctx);

/// @brief Set device owner.
bool dps_set_owner(plgd_dps_context_t *ctx, const oc_uuid_t *owner);

/// @brief Set device as self-owned.
bool dps_set_self_owned(plgd_dps_context_t *ctx);

/// @brief Check if DPS has a valid, non-self owner.
bool dps_has_owner(const plgd_dps_context_t *ctx);

/// @brief Reset self-owned device to default state.
///
/// @param device index of the logical device to reset
/// @param force true to reset immediately, false to reset after the 2 second
///   to terminate the connections (eg cloud deregistration)
int dps_factory_reset(size_t device, bool force);

/// @brief Check if ACLs from DPS exists (ACLs must contain at least one ACE
/// from DPS)
bool dps_has_acls(size_t device);

/// @brief Check if credential is annotated with the DPS_TAG.
bool dps_is_dps_cred(const oc_sec_cred_t *cred);

/// @brief Check credentials list for valid DPS credentials (list must contain
/// at least one valid identity cert and at least one valid trust anchor; all
/// DPS credentials must be valid). and schedule certificate renewal with
/// min_interval in milliseconds.
bool dps_check_credentials_and_schedule_renewal(plgd_dps_context_t *ctx,
                                                uint64_t min_interval);

/// @brief Get credid of a identity cert retrieved from DPS service.
int dps_get_identity_credid(size_t device);

/// @brief Check that the peer is a server.
bool dps_endpoint_peer_is_server(const oc_tls_peer_t *peer, void *user_data);

#if DPS_DBG_IS_ENABLED

/// @brief Print device's acls.
void dps_print_acls(size_t device);

/// @brief Print data of device's certificates.
void dps_print_certificates(size_t device);

/// @brief  Print basic peer data.
void dps_print_peers(void);

#endif /* DPS_DBG_IS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_SECURITY_INTERNAL_H */
