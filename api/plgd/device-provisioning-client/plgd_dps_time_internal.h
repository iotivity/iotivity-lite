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

#ifndef PLGD_DPS_TIME_INTERNAL_H
#define PLGD_DPS_TIME_INTERNAL_H

#include "plgd_dps_internal.h"

#include "port/oc_clock.h"
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief URI to retrieve time
 *
 * Expected response:
 * {
 *   time: <date and time in rfc3339 format>
 * }
 */
#define PLGD_DPS_TIME_URI "/x.plgd.dev/time"

/**
 * @brief Check if the time of the device was synchronized previously.
 *
 * @return true time has been synchronize at least once
 * @return false time has not been yet synchronized
 */
bool dps_has_plgd_time(void);

/**
 * @brief Request current time from server.
 *
 * Prepare and send a GET request to PLGD_DPS_TIME_URI and register handler for
 * a response with the current server time.
 *
 * @param ctx device registration context (cannot be NULL)
 * @return true GET request was successfully dispatched
 * @return false on failure
 */
bool dps_get_plgd_time(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Get current time.
 *
 * If the plgd-time feature is active the function will return its current time
 * approximation. Otherwise time returned by oc_clock_time() is used.
 *
 * @return current time on success
 * @return (oc_clock_time_t)-1 on error
 */
oc_clock_time_t dps_time(void);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_TIME_INTERNAL_H */
