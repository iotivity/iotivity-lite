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

/**
 * @brief Initialize software update resources.
 *
 * Allocate swupdate helper structures, set them to default values and try to
 * load from storage.
 */
void oc_swupdate_init(void);

/**
 * @brief Save software update data to storage and deallocate helper structures.
 */
void oc_swupdate_free(void);

typedef struct oc_swupdate_t oc_swupdate_t;

/** Get software update context for given device */
oc_swupdate_t *oc_swupdate_get_context(size_t device);

/**
 * @brief Get package url from context
 *
 * @param ctx software update context (cannot be NULL)
 * @return package url
 */
const char *oc_swupdate_get_package_url(const oc_swupdate_t *ctx);

/**
 * @brief Get available version from context
 *
 * @param ctx software update context (cannot be NULL)
 * @return device index
 */
const char *oc_swupdate_get_new_version(const oc_swupdate_t *ctx);

/**
 * @brief Get current update action
 *
 * @param ctx software update context (cannot be NULL)
 * @return current update state
 */
oc_swupdate_action_t oc_swupdate_get_action(const oc_swupdate_t *ctx);

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
 * @return -1 on failure
 * @return oc_swupdate_action_t on success
 */
int oc_swupdate_action_from_str(const char *action);

/**
 * @brief Get current update state
 *
 * @param ctx software update context (cannot be NULL)
 * @return current update state
 */
oc_swupdate_state_t oc_swupdate_get_state(const oc_swupdate_t *ctx);

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
 * @return -1 on failure
 * @return oc_swupdate_state_t on success
 */
int oc_swupdate_state_from_str(const char *state);

/* Internal interface to swupdate resource used for handling sw update
 * requests via pstat */
void oc_swupdate_perform_action(oc_swupdate_action_t action, size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_SWUPDATE_INTERNAL_H */
