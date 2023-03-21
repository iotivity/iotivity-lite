/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifndef PLGD_TIME_H
#define PLGD_TIME_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME

#include "port/oc_clock.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  /* UNINITIALIZED = 0, */
  PLGD_TIME_STATUS_SYNCING = 1,
  PLGD_TIME_STATUS_IN_SYNC,
  PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE, // special status value, used when time
                                         // is loaded from storage
} plgd_time_status_t;

/**
 * @brief Function used to set time on the whole system invoked whenever the
 * plgd time is updated.
 *
 * @param time current time
 * @param user_data custom user data passed from the caller
 */
typedef int (*plgd_set_system_time_fn_t)(oc_clock_time_t time, void *user_data);

/**
 * @brief Configure the plgd time feature.
 *
 * @param use_in_mbedtls propagate the oc_plgd_time function to mbedTLS, if
 * false then the standard time function will be used in mbedTLS (only used in
 * OC_SECURE builds)
 * @param set_system_time function used to set time on the whole system (for
 * example: a wrapper over the settimeofday function on Linux) whenever the
 * plgd time is modified (by plgd_time_set_time or a POST request)
 * @param set_system_time_data user data passed to set_system_time
 * @return 0 on success
 * @return <0 on failure
 *
 * @note to report synchronization status use plgd_time_set_status
 *
 * @see plgd_time_set_time
 */
void plgd_time_configure(bool use_in_mbedtls,
                         plgd_set_system_time_fn_t set_system_time,
                         void *set_system_time_data);

/**
 * @brief Plgd time is active (ie it is set to a valid, non-zero value).
 *
 * @return true plgd time is synchronized
 * @return false otherwise
 *
 * @see plgd_time_set_time
 */
bool plgd_time_is_active(void);

/**
 * @brief Calculate current plgd time.
 *
 * The plgd time is calculated by adding synchronization time and elapsed
 * time since the synchronization.
 * The value should represent number of ticks since the Unix Epoch (1970-01-01
 * 00:00:00 +0000 UTC).
 *
 * @return >=0 number of system ticks since the Unix Epoch
 * @return -1 on error
 *
 * @see plgd_time_set_time
 */
oc_clock_time_t plgd_time(void);

/** @brief Calculate the number of seconds since the Unix Epoch */
unsigned long plgd_time_seconds(void);

/**
 * @brief Synchronize the plgd time.
 *
 * Store the synchronization time and the monotonic time of the synchronization.
 * The plgd time is then calculated as synchronization time + time since
 * elapsed since synchronization.
 *
 * @param time synchronization time
 * @return 0 on success
 * @return -1 on failure
 *
 * @note on successful call the plgd time status is set to
 * PLGD_TIME_STATUS_IN_SYNC
 */
int plgd_time_set_time(oc_clock_time_t time);

/** @brief Get the latest synchronization time */
oc_clock_time_t plgd_time_last_synced_time(void);

/** @brief Set plgd time status */
void plgd_time_set_status(plgd_time_status_t status);

/** @brief Get plgd time status */
plgd_time_status_t plgd_time_status(void);

/**
 * @brief Load persistent data of the plgd time resource from storage.
 *
 * @return true on success, data was loaded
 * @return false otherwise
 *
 * @note on successful call the plgd time status is set to
 * PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE
 */
bool plgd_time_load(void);

/**
 * @brief Save persistent data of the plgd time resource to storage.
 *
 * @return true on success
 * @return false on failure
 */
bool plgd_time_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_PLGD_TIME */

#endif /* PLGD_TIME_H */
