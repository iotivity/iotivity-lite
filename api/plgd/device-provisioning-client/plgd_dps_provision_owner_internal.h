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

#ifndef PLGD_DPS_PROVISION_OWNER_INTERNAL_H
#define PLGD_DPS_PROVISION_OWNER_INTERNAL_H

#include "plgd/plgd_dps.h"
#include "plgd_dps_log_internal.h"

#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLGD_DPS_OWNERSHIP_URI "/api/v1/provisioning/ownership"

/**
 * @brief Request ownership UUID.
 *
 * Prepare and send GET request to PLGD_DPS_OWNERSHIP_URI and register
 * handler for response with ownership data.
 *
 * @param ctx device registration context (cannot be NULL)
 * @return true POST request successfully dispatched
 * @return false on failure
 */
bool dps_get_owner(plgd_dps_context_t *ctx) OC_NONNULL();

/** Handler of get owner response */
int dps_handle_get_owner_response(oc_client_response_t *data) OC_NONNULL();

#if DPS_DBG_IS_ENABLED

/// @brief Print owner of device, pstat and doxm resources, acls and
/// credentials.
void dps_print_owner(size_t device);

#endif /* DPS_DBG_IS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_PROVISION_OWNER_INTERNAL_H */
