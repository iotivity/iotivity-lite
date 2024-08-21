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

#ifndef PLGD_DPS_INTERNAL_H
#define PLGD_DPS_INTERNAL_H

#include "plgd_dps_log_internal.h"
#include "plgd/plgd_dps.h" // plgd_dps_context_t, plgd_dps_manager_callbacks_t

#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLGD_DPS_PROVISIONED_MASK                                              \
  (PLGD_DPS_HAS_TIME | PLGD_DPS_HAS_OWNER | PLGD_DPS_HAS_CLOUD |               \
   PLGD_DPS_HAS_CREDENTIALS | PLGD_DPS_HAS_ACLS)
#define PLGD_DPS_PROVISIONED_ERROR_FLAGS                                       \
  (PLGD_DPS_TRANSIENT_FAILURE | PLGD_DPS_FAILURE)
#define PLGD_DPS_PROVISIONED_ALL_FLAGS                                         \
  (PLGD_DPS_INITIALIZED | PLGD_DPS_GET_TIME | PLGD_DPS_HAS_TIME |              \
   PLGD_DPS_GET_OWNER | PLGD_DPS_HAS_OWNER | PLGD_DPS_GET_CLOUD |              \
   PLGD_DPS_HAS_CLOUD | PLGD_DPS_GET_CREDENTIALS | PLGD_DPS_HAS_CREDENTIALS |  \
   PLGD_DPS_GET_ACLS | PLGD_DPS_HAS_ACLS | PLGD_DPS_CLOUD_STARTED |            \
   PLGD_DPS_RENEW_CREDENTIALS | PLGD_DPS_TRANSIENT_FAILURE | PLGD_DPS_FAILURE)

static const char kPlgdDpsStatusUninitialized[] = "uninitialized";
static const char kPlgdDpsStatusInitialized[] = "initialized";
static const char kPlgdDpsStatusGetTime[] = "provisioning time";
static const char kPlgdDpsStatusHasTime[] = "provisioned time";
static const char kPlgdDpsStatusGetOwner[] = "provisioning owner";
static const char kPlgdDpsStatusHasOwner[] = "provisioned owner";
static const char kPlgdDpsStatusGetCredentials[] = "provisioning credentials";
static const char kPlgdDpsStatusHasCredentials[] = "provisioned credentials";
static const char kPlgdDpsStatusGetAcls[] = "provisioning acls";
static const char kPlgdDpsStatusHasAcls[] = "provisioned acls";
static const char kPlgdDpsStatusGetCloud[] = "provisioning cloud";
static const char kPlgdDpsStatusHasCloud[] = "provisioned cloud";
static const char kPlgdDpsStatusProvisioned[] = "provisioned";
static const char kPlgdDpsStatusRenewCredentials[] = "renew credentials";
static const char kPlgdDpsStatusTransientFailure[] = "transient failure";
static const char kPlgdDpsStatusFailure[] = "failure";

/// @brief Convert DPS status flags to string in format "flag|flag|flag" for
/// logs and copy it into the output buffer
int dps_status_to_logstr(uint32_t status, char *buffer, size_t buffer_size);

#if DPS_DBG_IS_ENABLED
void dps_print_status(const char *prefix, uint32_t status);
#endif /* DPS_DBG_IS_ENABLED */

/// @brief Callback to report DPS status.
oc_event_callback_retval_t dps_status_callback_handler(void *data);

/// @brief Try set cloud to use the latest identity certificate chain provided
/// by DPS.
OC_NO_DISCARD_RETURN
bool dps_try_set_identity_chain(size_t device);

/// @brief Notifies observers about resource change.
void dps_notify_observers(plgd_dps_context_t *ctx);

/// @brief Converts DPS status flag to string.
const char *dps_status_flag_to_str(plgd_dps_status_t status);

#ifdef OC_SESSION_EVENTS

/// @brief Initialize session callbacks
void plgd_dps_session_callbacks_init(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Deinitialize session callbacks
void plgd_dps_session_callbacks_deinit(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Initialize interface callbacks
void plgd_dps_interface_callbacks_init(void);

/// @brief Deinitialize interface callbacks
void plgd_dps_interface_callbacks_deinit(void);

#endif /* OC_SESSION_EVENTS */

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_INTERNAL_H */
