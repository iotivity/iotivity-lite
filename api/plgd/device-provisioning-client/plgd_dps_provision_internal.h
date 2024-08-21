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

#ifndef PLGD_DPS_PROVISION_INTERNAL_H
#define PLGD_DPS_PROVISION_INTERNAL_H

#include "plgd/plgd_dps.h"

#include "oc_api.h"
#include "oc_client_state.h" // oc_client_response_t
#include "oc_config.h"
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check DPS service response to a request during provisioning.
 *
 * @param ctx device context (cannot be NULL)
 * @param code response status code
 * @param payload payload to check for redirect
 * @return 0 on success
 * @return -1 on error
 */
OC_NO_DISCARD_RETURN
int dps_provisioning_check_response(plgd_dps_context_t *ctx, oc_status_t code,
                                    const oc_rep_t *payload) OC_NONNULL(1);

/**
 * @brief Starting executing missing DPS provisioning steps.
 *
 * @param ctx device provisioning context (cannot be NULL)
 */
void dps_provisioning_start(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Callback to start executing DPS provisioning.
OC_NO_DISCARD_RETURN
oc_event_callback_retval_t dps_provisioning_start_async(void *user_data)
  OC_NONNULL();

/**
 * @brief Schedule next step in DPS provisioning.
 *
 * @param ctx device provisioning context (cannot be NULL)
 */
void dps_provisioning_schedule_next_step(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Callback to start executing next step DPS provisioning.
OC_NO_DISCARD_RETURN
oc_event_callback_retval_t dps_provision_next_step_async(void *user_data)
  OC_NONNULL();

/**
 * @brief Finish DPS provisioning and start cloud manager.
 *
 * @param ctx device provisioning context (cannot be NULL)
 * @return true on success
 * @return false on error
 */
OC_NO_DISCARD_RETURN
bool dps_provisioning_start_cloud(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Check if all provisioning steps have been successfully executed so
/// cloud can be started.
OC_NO_DISCARD_RETURN
bool dps_is_provisioned(const plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Check if provisioning of the device is finished and cloud is started.
OC_NO_DISCARD_RETURN
bool dps_is_provisioned_with_cloud_started(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/// @brief Handle failure of a provisioning step
void dps_provisioning_handle_failure(plgd_dps_context_t *ctx, oc_status_t code,
                                     bool schedule_retry) OC_NONNULL();

/// @brief Return next provisioning step to be executed.
plgd_dps_status_t dps_provision_get_next_action(const plgd_dps_context_t *ctx)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_PROVISION_INTERNAL_H */
