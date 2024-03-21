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

#include "api/cloud/oc_cloud_store_internal.h"
#include "oc_cloud.h"
#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * @brief Cloud retry configuration structure.
 */
typedef struct oc_cloud_schedule_action_t
{
  oc_cloud_schedule_action_cb_t
    on_schedule_action; /**< Callback invoked to set delay
                      and timeout for the action. */
  void *user_data;  /**< User data provided to the schedule action callback. */
  uint16_t timeout; /**< Timeout for the action in seconds. */
} oc_cloud_schedule_action_t;

typedef struct
{
  uint8_t count;
  uint8_t refresh_token_count;
} oc_cloud_retry_t;

/** Reset the retry counters */
void cloud_retry_reset(oc_cloud_retry_t *retry) OC_NONNULL(1);

/** When retrying the registration step, all available servers should be used
 * once and after that retrying should be stopped. */
typedef struct
{
  oc_string_t initial_server; ///< server address when cloud manager is started;
  uint8_t remaining_server_changes; ///< remaining number of server changes
                                    ///< allowed before cloud manager is stopped
  bool server_changed;
} oc_cloud_registration_context_t;

struct oc_cloud_context_t
{
  struct oc_cloud_context_t *next;

  size_t device;
  oc_cloud_on_status_change_t on_status_change;
  oc_cloud_store_t store;

  oc_cloud_retry_t retry; /**< Retry configuration */

  oc_cloud_keepalive_t keepalive; /**< Keepalive configuration */
  oc_cloud_schedule_action_t
    schedule_action; /**< Schedule action configuration */

  oc_session_state_t cloud_ep_state;
  oc_endpoint_t *cloud_ep;

  oc_link_t *rd_publish_resources;   /**< Resource links to publish */
  oc_link_t *rd_published_resources; /**< Resource links already published */
  oc_link_t *rd_delete_resources;    /**< Resource links to delete */

  oc_cloud_registration_context_t registration_ctx; /**< Registration context */

  int selected_identity_cred_id; /**< Selected identity cert chain. -1(default)
                                    means any*/
  oc_cloud_error_t last_error;

  uint32_t time_to_live; /**< Time to live of published resources in seconds */

  bool cloud_manager; /**< cloud manager has been started */
};

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
 * @param ctx context to deinitialize
 */
void cloud_context_deinit(oc_cloud_context_t *ctx);

/// @brief Count number of allocated contexts
size_t cloud_context_size(void);

/**
 * @brief A function pointer for handling a single cloud context iteration;
 *
 * @param ctx cloud context (cannot be NULL)
 * @param user_data user data
 */
typedef void (*cloud_context_iterator_cb_t)(oc_cloud_context_t *ctx,
                                            void *user_data) OC_NONNULL(1);

/// Iterate over allocated cloud contexts;
void cloud_context_iterate(cloud_context_iterator_cb_t cb, void *user_data)
  OC_NONNULL(1);

/// @brief Clear cloud context values
void cloud_context_clear(oc_cloud_context_t *ctx) OC_NONNULL();

/**
 * @brief Check whether access token is set.
 *
 * @return true refresh token is set
 * @return false otherwise
 */

bool cloud_context_has_access_token(const oc_cloud_context_t *ctx) OC_NONNULL();

/**
 * @brief Checks whether the access token is set and whether it is permanent
 * (ie. the expires in time of the access token has special value which means
 * that the token is permanent).
 *
 * @return true access token is permanent
 * @return false otherwise
 */
bool cloud_context_has_permanent_access_token(const oc_cloud_context_t *ctx)
  OC_NONNULL();

/** @brief Clear access token from context */
void cloud_context_clear_access_token(oc_cloud_context_t *ctx) OC_NONNULL();

/**
 * @brief Check whether refresh token is set.
 *
 * @return true refresh token is set
 * @return false otherwise
 */
bool cloud_context_has_refresh_token(const oc_cloud_context_t *ctx)
  OC_NONNULL();

/** @brief Callback invoked by ctx::store::ci_servers when the selected cloud
 * server is changed  */
void cloud_context_on_server_change(void *data) OC_NONNULL();

/** @brief Initialize the registration context */
void oc_cloud_registration_context_init(oc_cloud_registration_context_t *regctx,
                                        const oc_endpoint_addresses_t *servers)
  OC_NONNULL();

/** @brief Deinitialize the registration context */
void oc_cloud_registration_context_deinit(
  oc_cloud_registration_context_t *regctx) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_CONTEXT_INTERNAL_H */
