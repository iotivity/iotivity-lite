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
/**
 * @file
 */
#ifndef OC_CLOUD_H
#define OC_CLOUD_H

#include "oc_client_state.h"
#include "oc_export.h"
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

OC_API
int oc_cloud_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
OC_API
int oc_cloud_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
OC_API
int oc_cloud_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
OC_API
int oc_cloud_deregister(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
OC_API
int oc_cloud_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb,
                           void *data);

OC_API
int oc_cloud_get_token_expiry(oc_cloud_context_t *ctx);

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
int oc_cloud_discover_resources(oc_cloud_context_t *ctx,
                                oc_discovery_all_handler_t handler,
                                void *user_data);

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
int oc_cloud_get_identity_cert_chain(oc_cloud_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_H */
