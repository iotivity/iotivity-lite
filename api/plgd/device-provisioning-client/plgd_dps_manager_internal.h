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

#ifndef PLGD_DPS_MANAGER_INTERNAL_H
#define PLGD_DPS_MANAGER_INTERNAL_H

#include "plgd/plgd_dps.h"

#include "oc_api.h"
#include "oc_config.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Start DPS process.
void dps_manager_start(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Start DPS process from an async callback.
oc_event_callback_retval_t dps_manager_start_async(void *user_data)
  OC_NONNULL();

/// @brief Stop DPS process.
void dps_manager_stop(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Force reprovisioning, and restart manager and cloud manager.
void dps_manager_reprovision_and_restart(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Asynchrounous wrapper for @ref dps_manager_reprovision_and_restart.
oc_event_callback_retval_t dps_manager_reprovision_and_restart_async(void *data)
  OC_NONNULL();

/**
 * @brief Callback function to start DPS provisioning process.
 *
 * @param data User data provided to the callback (must be the DPS context of
 * the device)
 * @return oc_event_callback_retval_t OC_EVENT_DONE
 */
OC_NO_DISCARD_RETURN
oc_event_callback_retval_t dps_manager_provision_async(void *data) OC_NONNULL();

/**
 * @brief Callback to retry DPS provisioning in case of an error or a timeout.
 *
 * @note Each call increments the retry counter
 *
 * @param data User data provided to the callback (must be the DPS context of
 * the device)
 * @return oc_event_callback_retval_t OC_EVENT_DONE
 */
OC_NO_DISCARD_RETURN
oc_event_callback_retval_t dps_manager_provision_retry_async(void *data)
  OC_NONNULL();

typedef struct
{
  uint32_t provision_flags;
  uint8_t cloud_observer_status;
} provision_and_cloud_observer_flags_t;

/// @brief Get provision flags and cloud observer status based on current state
provision_and_cloud_observer_flags_t dps_get_provision_and_cloud_observer_flags(
  plgd_dps_context_t *ctx) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_MANAGER_INTERNAL_H */
