/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef OC_CLOUD_INTERNAL_H
#define OC_CLOUD_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "oc_api.h"
#include "oc_cloud.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Value of 0 means that the check which removes links after their Time to Live
 * property expires should be skipped. Thus the Time to Live of such link
 * is unlimited. This is the default value for the Time to Live property.
 */
#define RD_PUBLISH_TTL_UNLIMITED 0

typedef struct cloud_conf_update_t
{
  char *access_token; /**< Access Token resolved with an auth code. */
  size_t access_token_len;
  char *auth_provider; /**< Auth Provider ID*/
  size_t auth_provider_len;
  char *ci_server; /**< Cloud Interface Server URL which an Enrollee is going to
                      registered. */
  size_t ci_server_len;
  char *sid; /**< OCF Cloud Identity as defined in OCF CNC 2.0 Spec. */
  size_t sid_len;
} cloud_conf_update_t;

typedef struct cloud_api_param_t
{
  oc_cloud_context_t *ctx;
  oc_cloud_cb_t cb;
  void *data;
} cloud_api_param_t;

cloud_api_param_t *alloc_api_param(void);
void free_api_param(cloud_api_param_t *p);
int conv_cloud_endpoint(oc_cloud_context_t *ctx);

int oc_cloud_init(void);
void oc_cloud_shutdown(void);

void oc_cloud_register_handler(oc_client_response_t *data);
void oc_cloud_login_handler(oc_client_response_t *data);
void oc_cloud_refresh_token_handler(oc_client_response_t *data);
void oc_cloud_clear_context(oc_cloud_context_t *ctx);
int oc_cloud_reset_context(size_t device);

void cloud_close_endpoint(oc_endpoint_t *cloud_ep);

void cloud_store_dump_async(const oc_cloud_store_t *store);
void cloud_store_load(oc_cloud_store_t *store);
void cloud_store_dump(const oc_cloud_store_t *store);
void cloud_store_initialize(oc_cloud_store_t *store);
void cloud_manager_cb(oc_cloud_context_t *ctx);
void cloud_set_string(oc_string_t *dst, const char *data, size_t len);
void cloud_set_last_error(oc_cloud_context_t *ctx, oc_cloud_error_t error);
void cloud_set_cps(oc_cloud_context_t *ctx, oc_cps_t cps);
void cloud_set_cps_and_last_error(oc_cloud_context_t *ctx, oc_cps_t cps,
                                  oc_cloud_error_t error);
void cloud_update_by_resource(oc_cloud_context_t *ctx,
                              const cloud_conf_update_t *data);
/**
 * @brief Send request to register device to cloud.
 *
 * @param endpoint cloud endpoint
 * @param auth_provider authorization provider
 * @param auth_code authorization code
 * @param uid user id
 * @param access_token access token
 * @param device index of the device to deregister
 * @param selected_identity_cred_id selected identity certficate id
 * @param handler response callback
 * @param user_data data passed to response callback
 * @return true on success
 *         false otherwise
 */
bool cloud_access_register(oc_endpoint_t *endpoint, const char *auth_provider,
                           const char *auth_code, const char *uid,
                           const char *access_token, size_t device,
                           int selected_identity_cred_id,
                           oc_response_handler_t handler, void *user_data);

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
 * @param endpoint cloud endpoint
 * @param uid user id
 * @param access_token access token
 * @param device index of the device to deregister
 * @param selected_identity_cred_id selected identity certficate id
 * @param handler response callback
 * @param user_data data passed to response callback
 * @return true on success
 *         false otherwise
 */
bool cloud_access_deregister(oc_endpoint_t *endpoint, const char *uid,
                             const char *access_token, size_t device,
                             int selected_identity_cred_id,
                             oc_response_handler_t handler, void *user_data);
/**
 * @brief Send request to sign in the device to the cloud.
 *
 * @param endpoint cloud endpoint
 * @param uid user id
 * @param access_token access token
 * @param device index of the device to deregister
 * @param selected_identity_cred_id selected identity certficate id
 * @param handler response callback
 * @param user_data data passed to response callback
 * @return true on success
 *         false otherwise
 */
bool cloud_access_login(oc_endpoint_t *endpoint, const char *uid,
                        const char *access_token, size_t device,
                        int selected_identity_cred_id,
                        oc_response_handler_t handler, void *user_data);
/**
 * @brief Send request to sign out the device to the cloud.
 *
 * @param endpoint cloud endpoint
 * @param uid user id
 * @param access_token access token
 * @param device index of the device to deregister
 * @param selected_identity_cred_id selected identity certficate id
 * @param handler response callback
 * @param user_data data passed to response callback
 * @return true on success
 *         false otherwise
 */
bool cloud_access_logout(oc_endpoint_t *endpoint, const char *uid,
                         const char *access_token, size_t device,
                         int selected_identity_cred_id,
                         oc_response_handler_t handler, void *user_data);
/**
 * @brief Send request to refresh the device access token to the cloud.
 *
 * @param endpoint cloud endpoint
 * @param uid user id
 * @param refresh_token refresh token
 * @param device index of the device to deregister
 * @param selected_identity_cred_id selected identity certficate id
 * @param handler response callback
 * @param user_data data passed to response callback
 * @return true on success
 *         false otherwise
 */
bool cloud_access_refresh_access_token(oc_endpoint_t *endpoint, const char *uid,
                                       const char *refresh_token, size_t device,
                                       int selected_identity_cred_id,
                                       oc_response_handler_t handler,
                                       void *user_data);

/**
 * @brief Update resource links after manager status change.
 *
 * If cloud is in logged in state the function executes several resource links
 * updates: deletes links scheduled to be deleted, publishes links scheduled
 * to be published and republishes links that were already published.
 * Additionally, if Time to Live property is not equal to
 * RD_PUBLISH_TTL_UNLIMITED then published links are scheduled to be republished
 * each hour. (If cloud_rd_manager_status_changed function is triggered again
 * before the scheduled time passes the republishing is rescheduled with updated
 * time.)
 *
 * @param ctx Cloud context, must not be NULL
 */
void cloud_rd_manager_status_changed(oc_cloud_context_t *ctx);

/**
 * @brief Deallocate all resource directory context member variables.
 *
 * Deallocate the list of to be published resources, the list of published
 * resources and the list of to be deleted resources. Remove delayed callback
 * that republishes resources (if it's active).
 *
 * @param ctx Cloud context, must not be NULL
 */
void cloud_rd_deinit(oc_cloud_context_t *ctx);

/**
 * @brief Reset resource directory context member variables.
 *
 * Items in the list of published resources are moved to the list of to be
 * published resources. The list of to be deleted resources is cleared.
 *
 * @param ctx Cloud context, must not be NULL
 */
void cloud_rd_reset_context(oc_cloud_context_t *ctx);

void cloud_manager_start(oc_cloud_context_t *ctx);
void cloud_manager_stop(oc_cloud_context_t *ctx);

void oc_create_cloudconf_resource(size_t device);

/**
 * @brief Provides information whether expires in of the access token means
 * permanent.
 *
 * @return true if it is permanent
 */
bool cloud_is_permanent_access_token(int64_t expires_in);
#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_INTERNAL_H */
