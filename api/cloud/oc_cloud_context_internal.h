/****************************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#ifndef OC_CLOUD_CONTEXT_INTERNAL_H
#define OC_CLOUD_CONTEXT_INTERNAL_H

#include "oc_cloud.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate and initialize cloud context for device
 *
 * @param device device index
 * @return allocated context on success
 * @return NULL on failure
 */
oc_cloud_context_t *cloud_context_init(size_t device);

/**
 * @brief Deinitialize and deallocate cloud context
 *
 * @param ctx context to deinitialize (cannot be NULL)
 */
void cloud_context_deinit(oc_cloud_context_t *ctx);

/// @brief Count number of allocated contexts
size_t cloud_context_size();

/**
 * @brief A function pointer for handling a single cloud context iteration;
 *
 * @param ctx cloud context (cannot be NULL)
 * @param user_data user data
 */
typedef void (*cloud_context_iterator_cb_t)(oc_cloud_context_t *ctx,
                                            void *user_data);

/// Iterate over allocated cloud contexts;
void cloud_context_iterate(cloud_context_iterator_cb_t cb, void *user_data);

/// @brief Clear cloud context values
void cloud_context_clear(oc_cloud_context_t *ctx);

/**
 * @brief Check whether access token is set.
 *
 * @return true refresh token is set
 * @return false otherwise
 */

bool cloud_context_has_access_token(const oc_cloud_context_t *ctx);

/**
 * @brief Checks whether the access token is set and whether it is permanent
 * (ie. the expires in time of the access token has special value which means
 * that the token is permanent).
 *
 * @return true access token is permanent
 * @return false otherwise
 */
bool cloud_context_has_permanent_access_token(const oc_cloud_context_t *ctx);

/** @brief Clear access token from context */
void cloud_context_clear_access_token(oc_cloud_context_t *ctx);

/**
 * @brief Check whether refresh token is set.
 *
 * @return true refresh token is set
 * @return false otherwise
 */
bool cloud_context_has_refresh_token(const oc_cloud_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_CONTEXT_INTERNAL_H */
