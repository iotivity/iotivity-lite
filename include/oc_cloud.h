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
/**
 * @file
 */
#ifndef OC_CLOUD_H
#define OC_CLOUD_H

#include "oc_client_state.h"
#include "oc_export.h"
#include "oc_link.h"
#include "oc_ri.h"
#include "oc_session_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  @brief Cloud connection status.
*/
typedef enum {
  OC_CLOUD_INITIALIZED = 0,
  OC_CLOUD_REGISTERED = 1 << 0,
  OC_CLOUD_LOGGED_IN = 1 << 1,
  OC_CLOUD_TOKEN_EXPIRY = 1 << 2,
  OC_CLOUD_REFRESHED_TOKEN = 1 << 3,
  OC_CLOUD_LOGGED_OUT = 1 << 4,
  OC_CLOUD_FAILURE = 1 << 5,
  OC_CLOUD_DEREGISTERED = 1 << 6,
} oc_cloud_status_t;

typedef enum oc_cps_t {
  OC_CPS_UNINITIALIZED = 0,
  OC_CPS_READYTOREGISTER,
  OC_CPS_REGISTERING,
  OC_CPS_REGISTERED,
  OC_CPS_FAILED,
  OC_CPS_DEREGISTERING
} oc_cps_t;

typedef struct oc_cloud_store_t
{
  oc_string_t ci_server;
  oc_string_t auth_provider;
  oc_string_t uid;
  oc_string_t access_token;
  oc_string_t refresh_token;
  oc_string_t sid;
  int64_t expires_in;
  uint8_t status;
  oc_cps_t cps;
  size_t device;
} oc_cloud_store_t;

typedef enum {
  CLOUD_OK = 0,
  CLOUD_ERROR_RESPONSE = 1,
  CLOUD_ERROR_CONNECT = 2,
  CLOUD_ERROR_REFRESH_ACCESS_TOKEN = 3,
  CLOUD_ERROR_UNAUTHORIZED = 4,
} oc_cloud_error_t;

struct oc_cloud_context_t;

/**
  @brief A function pointer for handling the cloud status.
  @param ctx Cloud context (cannot be NULL)
  @param status Current status of the cloud.
  @param user_data User data
*/
typedef void (*oc_cloud_cb_t)(struct oc_cloud_context_t *ctx,
                              oc_cloud_status_t status, void *user_data);

/**
 * @brief Callback invoked by the cloud manager when cloud change state to
 * logged in or a keepalive response is received.
 *
 * @param response_received Keepalive response received, true if received,
 * otherwise false
 * @param next_ping Delay in milliseconds before next keepalive ping
 * @param next_ping_timeout Timeout in seconds for next keepalive ping
 * @param user_data User data passed from the caller
 *
 * @return true if the cloud manager should continue sending keepalive pings,
 * false if cloud manager should consider the connection lost
 */
typedef bool (*oc_cloud_on_keepalive_response_cb_t)(bool response_received,
                                                    uint64_t *next_ping,
                                                    uint16_t *next_ping_timeout,
                                                    void *user_data);

/**
 * @brief Cloud keepalive configuration.
 */
typedef struct oc_cloud_keepalive_t
{
  oc_cloud_on_keepalive_response_cb_t
    on_response;   /**< Callback invoked on keepalive response */
  void *user_data; /**< User data provided to the keepalive response callback */
  uint16_t ping_timeout; /**< Timeout for keepalive ping in seconds */
} oc_cloud_keepalive_t;

typedef struct oc_cloud_context_t
{
  struct oc_cloud_context_t *next;

  size_t device;

  oc_cloud_cb_t callback;
  void *user_data;

  oc_cloud_store_t store;

  oc_session_state_t cloud_ep_state;
  oc_endpoint_t *cloud_ep;
  uint8_t retry_count;
  uint8_t retry_refresh_token_count;
  oc_cloud_error_t last_error;
  uint32_t time_to_live; /**< Time to live of published resources in seconds */

  oc_link_t *rd_publish_resources;   /**< Resource links to publish */
  oc_link_t *rd_published_resources; /**< Resource links already published */
  oc_link_t *rd_delete_resources;    /**< Resource links to delete */

  oc_resource_t *cloud_conf;

  int selected_identity_cred_id; /**< Selected identity cert chain. -1(default)
                                    means any*/
  bool cloud_manager;

  oc_cloud_keepalive_t keepalive; /**< Keepalive configuration */
} oc_cloud_context_t;

/**
 * @brief Get cloud context for device.
 */
OC_API
oc_cloud_context_t *oc_cloud_get_context(size_t device);

/**
 * @brief Start cloud registration process.
 *
 * @param ctx cloud context (cannot be NULL)
 * @param cb callback function invoked on status change
 * @param data user data provided to the status change function
 * @return int 0 on success
 * @return int -1 on error
 */
OC_API
int oc_cloud_manager_start(oc_cloud_context_t *ctx, oc_cloud_cb_t cb,
                           void *data);
/**
 * @brief Stop cloud registration process, remove related pending delayed
 * callbacks and clean-up data.
 *
 * @param ctx cloud context (cannot be NULL)
 * @return int 0 on success
 * @return int -1 on error
 */
OC_API
int oc_cloud_manager_stop(oc_cloud_context_t *ctx);

/**
 * @brief Restart cloud registration process with the current configuration.
 *
 * @param ctx cloud context (cannot be NULL)
 */
OC_API
void oc_cloud_manager_restart(oc_cloud_context_t *ctx);

/**
 * @brief Send request to register device to cloud.
 *
 * @param ctx cloud context
 * @param cb callback function invoked on status change
 * @param data user data provided to the status change function
 * @return int 0 on success
 * @return int -1 on error
 */
OC_API
int oc_cloud_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);

/**
 * @brief Send request to sign in the device to the cloud.
 *
 * @param ctx cloud context
 * @param cb callback function invoked on status change
 * @param data user data provided to the status change function
 * @return int 0 on success
 * @return int -1 on error
 */
OC_API
int oc_cloud_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);

/**
 * @brief Send request to sign out the device to the cloud.
 *
 * @param ctx cloud context
 * @param cb callback function invoked on status change
 * @param data user data provided to the status change function
 * @return int 0 on success
 * @return int -1 on error
 */
OC_API
int oc_cloud_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);

/**
 * @brief Send request to deregister device from cloud.
 *
 * @note If the device is not signed in then the request requires additional
 * data. If the request becomes larger than is allowed because of this then
 * this call will attempt to sign in to avoid sending this additional data.
 *
 * @param ctx cloud context
 * @param cb callback function invoked on status change
 * @param data user data provided to the status change function
 * @return int 0 on success
 * @return int -1 on error
 *
 * @note oc_cloud_deregister shouldn't be called when oc_cloud_login or
 * oc_cloud_refresh_token have been invoked and haven't yet received a response.
 *
 * @see oc_cloud_login
 * @see oc_cloud_refresh_token
 */
OC_API
int oc_cloud_deregister(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);

/**
 * @brief Send request to refresh the device access token to the cloud.
 *
 * @param ctx cloud context
 * @param cb callback function invoked on status change
 * @param data user data provided to the status change function
 * @return int 0 on success
 * @return int -1 on error
 */
OC_API
int oc_cloud_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb,
                           void *data);

OC_API
int oc_cloud_get_token_expiry(const oc_cloud_context_t *ctx);

/**
 * @brief Set Time to Live value in the provided cloud context.
 *
 * @param ctx Cloud context to update, must not be NULL.
 * @param ttl Time to live value in seconds.
 */
OC_API
void oc_cloud_set_published_resources_ttl(oc_cloud_context_t *ctx,
                                          uint32_t ttl);

/**
 * @brief Publish resource to cloud.
 *
 * Function checks that resource is contained in list of published or to-be
 * published resources. If it is, the function does nothing. If it is not, then
 * the resource is added to the to-be published resources list and a publish
 * request with this list is sent to the cloud server.
 *
 * @param resource the resource to be published
 */
OC_API
int oc_cloud_add_resource(oc_resource_t *resource);

/**
 * @brief Unpublish resource from cloud.
 *
 * @param resource the resource to be unpublished
 */
OC_API
void oc_cloud_delete_resource(oc_resource_t *resource);

/**
 * @brief Republish previously published devices.
 *
 * @param device the device index
 */
OC_API
int oc_cloud_publish_resources(size_t device);

OC_API
int oc_cloud_discover_resources(const oc_cloud_context_t *ctx,
                                oc_discovery_all_handler_t handler,
                                void *user_data);

/**
 * @brief Configure cloud properties.
 *
 * @param ctx Cloud context to update (cannot be be NULL)
 * @param server Cloud server URL
 * @param access_token Access token from an Authorisation Provider
 * @param server_id Cloud server ID
 * @param auth_provider Name of the Authorization Provider which provided the
 * access token
 * @return 0 on success
 * @return -1 on failure
 *
 * @note Cloud manager will be restarted if is was started previously
 */
OC_API
int oc_cloud_provision_conf_resource(oc_cloud_context_t *ctx,
                                     const char *server,
                                     const char *access_token,
                                     const char *server_id,
                                     const char *auth_provider);
/**
 * @brief Set identity certificate chain to establish TLS connection.
 *
 * @param ctx Cloud context to update, must not be NULL.
 * @param selected_identity_cred_id Selected identity certificate chain id.
 * -1(default) means any.
 */
OC_API
void oc_cloud_set_identity_cert_chain(oc_cloud_context_t *ctx,
                                      int selected_identity_cred_id);
/**
 * @brief Get selected identity certificate chain to establish TLS connection.
 *
 * @param ctx Cloud context to update, must not be NULL.
 * @return Selected identity certificate chain id. -1 means any.
 */
OC_API
int oc_cloud_get_identity_cert_chain(const oc_cloud_context_t *ctx);

/**
 * @brief Set keepalive parameters for the cloud manager.
 *
 * @param ctx Cloud context to update, must not be NULL.
 * @param on_keepalive_response Callback invoked by the cloud manager when cloud
 * change state to logged in or a keepalive response is received.
 * @param user_data User data passed from the caller
 */
OC_API
void oc_cloud_set_keepalive(
  oc_cloud_context_t *ctx,
  oc_cloud_on_keepalive_response_cb_t on_keepalive_response, void *user_data);

/**
 * @brief Remove cloud context values, disconnect, and stop the cloud manager,
 * without releasing the context.
 *
 * @param ctx Cloud context to clear, must not be NULL.
 * @param dump_async If true, store the context to storage in an asynchronous
 * manner; otherwise, perform the dump while executing this function.
 */
OC_API
void oc_cloud_context_clear(oc_cloud_context_t *ctx, bool dump_async);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_H */
