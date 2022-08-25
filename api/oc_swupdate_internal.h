/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#ifndef OC_SWUPDATE_INTERNAL_H
#define OC_SWUPDATE_INTERNAL_H

#include "oc_config.h"
#include "oc_helpers.h"
#include "util/oc_compiler.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  OC_SWUPDATE_STATE_IDLE,     ///< idle, waiting for updates
  OC_SWUPDATE_STATE_NSA,      ///< new software available
  OC_SWUPDATE_STATE_SVV,      ///< software version validation
  OC_SWUPDATE_STATE_SVA,      ///< software version available
  OC_SWUPDATE_STATE_UPGRADING ///< upgrading
} oc_swupdate_state_t;

typedef enum {
  OC_SWUPDATE_IDLE,   ///< nothing scheduled
  OC_SWUPDATE_ISAC,   ///< initiate software availability check
  OC_SWUPDATE_ISVV,   ///< initiate software version validation
  OC_SWUPDATE_UPGRADE ///< initiate secure software update
} oc_swupdate_action_t;

typedef struct oc_swupdate_t
{
  oc_string_t purl;    ///< package URL, source of the software package
  oc_string_t nv;      ///< new version, new available software version
  oc_string_t signage; ///< signage method of the software package
  oc_swupdate_action_t swupdateaction; ///< action to execute
  oc_swupdate_state_t swupdatestate;   ///< state of the software update
  int swupdateresult;                  ///< result of the software update
  oc_clock_time_t lastupdate;          ///< time of the last software update
  oc_clock_time_t updatetime; ///< scheduled time to execute swupdateaction
} oc_swupdate_t;

#define OCF_SW_UPDATE_URI "/oc/swu"
#define OCF_SW_UPDATE_RT "oic.r.softwareupdate"
#define OCF_SW_UPDATE_IF_MASK (OC_IF_BASELINE | OC_IF_RW)
#define OCF_SW_UPDATE_DEFAULT_IF (OC_IF_RW)
#define OCF_SW_UPDATE_STORE_NAME "sw"

/**
 * @brief Allocate and initialize Software Update (SWU) resources and data.
 */
void oc_swupdate_create(void);

/**
 * @brief Deallocate all SWU resource data.
 */
void oc_swupdate_free(void);

/**
 * @brief Get pointer to the SWU data of given device.
 *
 * @param device device index
 * @return oc_swupdate_t* SWU data for given device
 */
oc_swupdate_t *oc_swupdate_get(size_t device);

/**
 * @brief Reset SWU resource data to empty values.
 *
 * @param device device index
 */
void oc_swupdate_default(size_t device);

/**
 * @brief Copy SWU data from source to destination
 *
 * @param dst destination (cannot be NULL)
 * @param src source (cannot be NULL)
 */
void oc_swupdate_copy(oc_swupdate_t *dst, const oc_swupdate_t *src)
  OC_NONNULL();

/**
 * @brief Deallocate all SWU data and set them to zero.
 *
 * @param swu SWU data to clear (cannot be NULL)
 */
void oc_swupdate_clear(oc_swupdate_t *swu) OC_NONNULL();

/**
 * @brief Convert action to string representation
 *
 * @param action action to convert
 * @return NULL on failure
 * @return string representation on success
 */
const char *oc_swupdate_action_to_str(oc_swupdate_action_t action);

/**
 * @brief Convert string to oc_swupdate_action_t
 *
 * @param action string to convert (cannot be NULL)
 * @param action_len length of \p action
 * @return -1 on failure
 * @return oc_swupdate_action_t on success
 */
int oc_swupdate_action_from_str(const char *action, size_t action_len)
  OC_NONNULL();

/**
 * @brief Convert state to string representation
 *
 * @param state state to convert
 * @return NULL on failure
 * @return string representation on success
 */
const char *oc_swupdate_state_to_str(oc_swupdate_state_t state);

/**
 * @brief Convert string to oc_swupdate_state_t
 *
 * @param state a string (cannot be NULL)
 * @param state_len length of \p state
 * @return -1 on failure
 * @return oc_swupdate_state_t on success
 */
int oc_swupdate_state_from_str(const char *state, size_t state_len)
  OC_NONNULL();

typedef enum {
  OC_SWUPDATE_ENCODE_FLAG_INCLUDE_BASELINE =
    1 << 0,                                    // include baseline properties
  OC_SWUPDATE_ENCODE_FLAG_TO_STORAGE = 1 << 1, // encode to storage
} oc_swupdate_encode_flag_t;

/**
 * @brief Encode SWU data to global encoder
 *
 * @param swu SWU data to encode
 * @param swu_res resource with baseline properties (only used when flags
 * contain OC_SWUPDATE_ENCODE_FLAG_INCLUDE_BASELINE)
 * @param flags encoding flags
 * @return 0 on success
 * @return <0 on error
 */
int oc_swupdate_encode_with_resource(const oc_swupdate_t *swu,
                                     const oc_resource_t *swu_res, int flags)
  OC_NONNULL(1);

/**
 * @brief Convenience wrapper for oc_swupdate_encode_with_resource. Will encode
 * global SWU data and resource associated with given device.
 */
bool oc_swupdate_encode_for_device(size_t device, int flags);

typedef bool (*oc_swupdate_on_encode_timestamp_to_string_t)(const char *)
  OC_NONNULL();

bool oc_swupdate_encode_clocktime_to_string(
  oc_clock_time_t time, oc_swupdate_on_encode_timestamp_to_string_t encode);

typedef enum {
  OC_SWUPDATE_DECODE_FLAG_IGNORE_ERRORS = 1 << 0,
  OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE = 1 << 1,
  OC_SWUPDATE_DECODE_FLAG_COAP_UPDATE = 1 << 2,
} oc_swupdate_decode_flag_t;

/**
 * @brief Decode SWU payload.
 *
 * @param rep representation to decode
 * @param flags mask of decoding flags
 * @param dst output variable to store decoded data (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool oc_swupdate_decode(const oc_rep_t *rep, int flags, oc_swupdate_t *dst)
  OC_NONNULL(3);

/**
 * @brief Decode payload and update SWU data for given device
 *
 * @param rep representation to decode
 * @param flags mask of decoding flags
 * @param device device index
 * @return true on success, payload was decoded and data for device were updated
 * @return false on failure
 */
bool oc_swupdate_decode_for_device(const oc_rep_t *rep, int flags,
                                   size_t device);

/* Internal interface to swupdate resource used for handling sw update
 * requests via pstat */
void oc_swupdate_perform_action(oc_swupdate_action_t action, size_t device);

/**
 * @brief Schedule SWU action for given device
 *
 * @param device device index
 * @param schedule_at time when action should be performed
 */
void oc_swupdate_action_schedule(size_t device, oc_clock_time_t schedule_at);

/**
 * @brief Check if SWU action is scheduled for given device
 *
 * @param device device index
 * @return true update is scheduled
 * @return false update is not scheduled
 */
bool oc_swupdate_action_is_scheduled(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_SWUPDATE_INTERNAL_H */
