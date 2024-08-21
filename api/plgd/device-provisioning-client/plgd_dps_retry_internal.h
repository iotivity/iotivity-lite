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

#ifndef PLGD_DPS_RETRY_INTERNAL_H
#define PLGD_DPS_RETRY_INTERNAL_H

#include "plgd/plgd_dps.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_RESET_TIMEOUT (2)
// NOLINTNEXTLINE(modernize-*)
#define MILLISECONDS_PER_SECOND (1000)

typedef struct schedule_action_t
{
  plgd_dps_schedule_action_cb_t
    on_schedule_action; ///< callback to schedule action
  void *user_data;      ///< user data
  uint16_t timeout;     ///< timeout in seconds
  uint64_t delay;       ///< delay in milliseconds
} schedule_action_t;

/**
 * @brief Retry configuration and current value.
 *
 * The configuration of the retry counter consists of non-zero integer values
 * which will be interpretet as timeout values (in seconds).
 */
typedef struct plgd_dps_retry_t
{
  uint8_t default_cfg[PLGD_DPS_MAX_RETRY_VALUES_SIZE]; ///< retry counter
                                                       ///< configuration
  uint8_t count;                     ///< current retry counter value
  schedule_action_t schedule_action; ///< schedule action
} plgd_dps_retry_t;

/// @brief Initialize retry counter configuration with default values.
void dps_retry_init(plgd_dps_retry_t *ret);

/// @brief Get size of the timeout default_cfg array.
uint8_t dps_retry_size(const plgd_dps_retry_t *ret);

/**
 * @brief Increment retry counter value by 1.
 *
 * @note if counter reaches max value it is reset back to 0.
 */
void dps_retry_increment(plgd_dps_context_t *ctx, plgd_dps_status_t action);

/// @brief Reset retry counter value to 0.
void dps_retry_reset(plgd_dps_context_t *ctx, plgd_dps_status_t action);

/// @brief Get timeout value based on the current retry counter value.
uint16_t dps_retry_get_timeout(const plgd_dps_retry_t *ret);

/// @brief Get delay value based on the current retry counter value.
uint64_t dps_retry_get_delay(const plgd_dps_retry_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_RETRY_INTERNAL_H */
