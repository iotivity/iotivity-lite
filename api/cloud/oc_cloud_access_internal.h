/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef OC_CLOUD_ACCESS_INTERNAL_H
#define OC_CLOUD_ACCESS_INTERNAL_H

#include "oc_client_state.h"
#include "oc_endpoint.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Common configuration arguments for cloud_access functions
typedef struct oc_cloud_access_conf_t
{
  oc_endpoint_t *endpoint;       ///< cloud endpoint
  size_t device;                 ///< index of the device
  int selected_identity_cred_id; ///< selected identity certficate id
  oc_response_handler_t handler; ///< response callback
  void *user_data;               ///< data passed to response callback
  uint16_t timeout;              ///< timeout for response
} oc_cloud_access_conf_t;

/**
 * @brief Send request to register device to cloud.
 *
 * @param conf cloud access configuration
 * @param auth_provider authorization provider
 * @param auth_code authorization code
 * @param uid user id
 * @param access_token access token
 * @return true on success
 *         false otherwise
 */
bool cloud_access_register(oc_cloud_access_conf_t conf,
                           const char *auth_provider, const char *auth_code,
                           const char *uid, const char *access_token);

/**
 * @brief Generate URI query for deregister request.
 *
 * @return URI query, must be freed by caller
 */
oc_string_t cloud_access_deregister_query(const char *uid,
                                          const char *access_token,
                                          size_t device);
/**
 * @brief Send request to deregister device from cloud.
 *
 * The device must be registered and logged in for this call to succeed.
 *
 * @param conf cloud access configuration
 * @param uid user id
 * @param access_token access token
 * @return true on success
 *         false otherwise
 */
bool cloud_access_deregister(oc_cloud_access_conf_t conf, const char *uid,
                             const char *access_token);
/**
 * @brief Send request to sign in the device to the cloud.
 *
 * @param conf cloud access configuration
 * @param uid user id
 * @param access_token access token
 * @return true on success
 *         false otherwise
 */
bool cloud_access_login(oc_cloud_access_conf_t conf, const char *uid,
                        const char *access_token);
/**
 * @brief Send request to sign out the device to the cloud.
 *
 * @param conf cloud access configuration
 * @param uid user id
 * @param access_token access token
 * @return true on success
 *         false otherwise
 */
bool cloud_access_logout(oc_cloud_access_conf_t conf, const char *uid,
                         const char *access_token);
/**
 * @brief Send request to refresh the device access token to the cloud.
 *
 * @param conf cloud access configuration
 * @param uid user id
 * @param refresh_token refresh token
 * @return true on success
 *         false otherwise
 */
bool cloud_access_refresh_access_token(oc_cloud_access_conf_t conf,
                                       const char *uid,
                                       const char *refresh_token);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_INTERNAL_H */
