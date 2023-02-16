/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
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

#ifndef OC_CLOUD_DEREGISTER_INTERNAL_H
#define OC_CLOUD_DEREGISTER_INTERNAL_H

#include "oc_cloud.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Timeout for deregistering requests
#define CLOUD_DEREGISTER_TIMEOUT (10)

/// Error when attempting to multiple deregistrations concurrently
#define CLOUD_DEREGISTER_ERROR_ALREADY_DEREGISTERING (-2)

/**
 * @brief Execute cloud deregister
 *
 * @note If the device is not signed-in then access token is required in the
 * deregistering request. However, the size of the request header is limited, if
 * the access token is long then we will attempt to sign-in.
 * The deregistration operation because asynchronous in this case, since we have
 * to wait for responses from the server.
 *
 * @param ctx device context (cannot be NULL)
 * @param sync force synchronous execution (function won't attempt to login and
 * will just fail)
 * @param timeout request timeout
 * @param cb callback executed after successful deregister
 * @param data user data provided to deregister callback
 * @return 0 on success
 * @return CLOUD_DEREGISTER_ERROR_ALREADY_DEREGISTERING if deregister is already
 * being executed for given device
 * @return -1 on other errors
 */
int cloud_deregister(oc_cloud_context_t *ctx, bool sync, uint16_t timeout,
                     oc_cloud_cb_t cb, void *data);

/**
 * @brief Execute cloud deregister triggered by cloud_reset.
 *
 * @param ctx device context (cannot be NULL)
 * @param sync force synchronous execution (function won't attempt to login and
 * will just fail)
 * @param timeout request timeout
 * @return true on success
 * @return false on failure
 */
bool cloud_deregister_on_reset(oc_cloud_context_t *ctx, bool sync,
                               uint16_t timeout);

/**
 * @brief Clean-up all events by deregister.
 *
 * @param ctx device context (cannot be NULL);
 */
void cloud_deregister_stop(oc_cloud_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_DEREGISTER_INTERNAL_H */
