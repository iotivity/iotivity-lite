/****************************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
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

#ifndef OC_CLOUD_MANAGER_INTERNAL_H
#define OC_CLOUD_MANAGER_INTERNAL_H

#include "oc_cloud.h"
#include "oc_rep.h"
#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"
#define USER_ID_KEY "uid"
#define EXPIRESIN_KEY "expiresin"

/**
 * @brief Parse sign-up response retrieved from the server and store the data to
 * cloud context.
 *
 * @param[in] ctx cloud context (cannot be NULL)
 * @param[in] payload sing-up server response (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool cloud_manager_handle_register_response(oc_cloud_context_t *ctx,
                                            const oc_rep_t *payload)
  OC_NONNULL();

/**
 * @brief Parse received response and handle redirect key if it is present.
 *
 * @param[in] ctx cloud context (cannot be NULL)
 * @param[in] payload server response (cannot be NULL)
 * @return true valid redirect key was found in the response
 * @return false otherwise
 */
bool cloud_manager_handle_redirect_response(oc_cloud_context_t *ctx,
                                            const oc_rep_t *payload)
  OC_NONNULL();

/**
 * @brief Calculate the expiration time of the refresh token.
 *
 * The expiration time is used to determine when the refresh token should be
 * refreshed. It should be less than the actual expiration time of the token, so
 * it can be refreshed before it really expires.
 *
 * @param expires_in_ms expires_in value in milliseconds (must be >0)
 * @return uint64_t expiration time in milliseconds
 */
uint64_t cloud_manager_calculate_refresh_token_expiration(
  uint64_t expires_in_ms);

/**
 * @brief Parse refresh token response retrieved from the server and store the
 * data to cloud context.
 *
 * @param[in] ctx cloud context (cannot be NULL)
 * @param[in] payload refresh token server response (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool cloud_manager_handle_refresh_token_response(oc_cloud_context_t *ctx,
                                                 const oc_rep_t *payload)
  OC_NONNULL();

/**
 * @brief Start executing cloud provisioning steps
 *
 * @param ctx cloud context (cannot be NULL)
 */
void cloud_manager_start(oc_cloud_context_t *ctx) OC_NONNULL();

/**
 * @brief Stop executing cloud provisioning steps
 *
 * @param ctx cloud context (cannot be NULL)
 */
void cloud_manager_stop(const oc_cloud_context_t *ctx) OC_NONNULL();

/**
 * @brief Check if retry of the cloud registration step with changed server
 * should be attempted
 *
 * @param ctx cloud context (cannot be NULL)
 * @return true retry should be attempted
 * @return false otherwise
 */
bool cloud_manager_register_check_retry_with_changed_server(
  const oc_cloud_context_t *ctx) OC_NONNULL();

void oc_cloud_register_handler(oc_client_response_t *data) OC_NONNULL();
void oc_cloud_login_handler(oc_client_response_t *data) OC_NONNULL();
void oc_cloud_refresh_token_handler(oc_client_response_t *data) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_MANAGER_INTERNAL_H */
