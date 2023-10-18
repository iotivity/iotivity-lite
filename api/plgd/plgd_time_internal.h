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

#ifndef PLGD_TIME_INTERNAL_H
#define PLGD_TIME_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME

#include "oc_rep.h"
#include "oc_ri.h"
#include "plgd/plgd_time.h"
#include "port/oc_clock.h"

#ifdef OC_SECURITY
#include <mbedtls/platform_time.h>
#endif /* OC_SECURITY */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLGD_TIME_URI "/x.plgd.dev/time"
#define PLGD_TIME_RT "x.plgd.dev.time"
#define PLGD_TIME_STORE_NAME "plgd_time"

#define PLGD_TIME_PROP_TIME "time"
#define PLGD_TIME_PROP_LAST_SYNCED_TIME "lastSyncedTime"
#define PLGD_TIME_PROP_STATUS "status"

#define PLGD_TIME_STATUS_SYNCING_STR "syncing"
#define PLGD_TIME_STATUS_IN_SYNC_STR "in-sync"
#define PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE_STR "in-sync-from-storage"

/**
 * @brief Create plgd time (/x.plgd.dev/time) resource
 */
void plgd_time_create_resource(void);

typedef struct plgd_time_store_t
{
  oc_clock_time_t last_synced_time;
} plgd_time_store_t;

typedef struct plgd_time_t
{
  plgd_time_store_t store;
  plgd_time_status_t status;
  oc_clock_time_t
    update_time; ///< monotonic time at the time of synchronization
  plgd_set_system_time_fn_t
    set_system_time;          ///< function to set the system time
  void *set_system_time_data; ///< user data passed to set_system_time
} plgd_time_t;

/**
 * @brief Get pointer to the global plgd time structure.
 *
 * @return plgd_time_t* pointer to the global plgd time structure
 */
plgd_time_t *plgd_time_get(void);

/**
 * @brief Manually set the global plgd time
 *
 * @param last_synced_time synchronization time
 * @param update_time monotonic time of the synchronization
 * @param dump save persistent data to storage after the update
 * @param notify notify about the resource change
 *
 * @note the status of the global plgd time is changed to
 * PLGD_TIME_STATUS_IN_SYNC
 */
void plgd_time_set(oc_clock_time_t last_synced_time,
                   oc_clock_time_t update_time, bool dump, bool notify);

typedef enum plgd_time_encode_flag_t {
  PLGD_TIME_ENCODE_FLAG_TO_STORAGE =
    1 << 0, // include properties for persistent storage
  PLGD_TIME_ENCODE_FLAG_SECURE = 1 << 1, // include secure properties
} plgd_time_encode_flag_t;

/**
 * @brief Encode plgd time properties to the global encoder.
 *
 * @param pt plgd time to encode
 * @param iface encoding interface
 * @param flags mask of encoding flags
 * @return 0 on success
 * @return -1 on error
 */
int plgd_time_encode(plgd_time_t pt, oc_interface_mask_t iface, int flags);

/**
 * @brief Decode representation to output structure.
 *
 * @param rep representation to decode
 * @param[out] pt plgd time structure to store decoded data (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool plgd_time_decode(const oc_rep_t *rep, plgd_time_t *pt);

/**
 * @brief Encode plgd_time_status_t to a string
 *
 * @param status status to encode
 * @return const char* on success
 * @return NULL on error
 */
const char *plgd_time_status_to_str(plgd_time_status_t status);

/**
 * @brief Parse string to plgd_time_status_t
 *
 * @param str string to parse (cannot be NULL)
 * @param str_len length of str
 * @return plgd_time_status_t on success
 * @return -1 on error
 */
int plgd_time_status_from_str(const char *str, size_t str_len);

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_PLGD_TIME */

#endif /* PLGD_TIME_INTERNAL_H */
