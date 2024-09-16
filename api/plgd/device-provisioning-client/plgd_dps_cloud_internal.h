/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifndef DPS_CLOUD_INTERNAL_H
#define DPS_CLOUD_INTERNAL_H

#include "plgd/plgd_dps.h"

#include "oc_api.h"
#include "oc_cloud.h"
#include "oc_config.h"
#include "oc_rep.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPS_CLOUD_ACCESSTOKEN "at"
#define DPS_CLOUD_AUTHPROVIDER "apn"
#define DPS_CLOUD_CISERVER "cis"
#define DPS_CLOUD_SERVERID "sid"
#define DPS_CLOUD_ENDPOINTS "x.org.iotivity.servers"
#define DPS_CLOUD_ENDPOINT_ID "id"
#define DPS_CLOUD_ENDPOINT_URI "uri"

/// @brief Check whether cloud has been started.
bool dps_cloud_is_started(size_t device);

/**
 * @brief Check cloud registration status.
 *
 * @param device index of the device
 * @return true device has been successfully registered to cloud
 * @return false otherwise
 */
bool dps_cloud_is_registered(size_t device);

/**
 * @brief Check cloud login status.
 *
 * @param device index of the device
 * @return true device has been successfully logged in to cloud
 * @return false otherwise
 */
bool dps_cloud_is_logged_in(size_t device);

typedef struct
{
  oc_string_t initial_endpoint_uri; ///< the URI of the first endpoint when
                                    ///< provisioning was started
  oc_uuid_t last_endpoint_uuid;     ///< uuid of the last tried endpoint
  uint8_t
    remaining_endpoint_changes; ///< remaining number of server changes allowed
                                ///< before full provisioning is triggered
  uint8_t last_status;          ///< latest observed cloud status
  uint8_t retry_count;          ///< current retry counter

  oc_endpoint_addresses_on_selected_change_t
    original_on_selected_change; ///< original on_selected_change callback on
                                 ///< the cloud context
  plgd_cloud_status_observer_configuration_t cfg;
} plgd_cloud_status_observer_t;

/// @brief Initialize the cloud observer
void dps_cloud_observer_init(plgd_cloud_status_observer_t *obs) OC_NONNULL();

/// @brief Load cloud observer values from the cloud context
bool dps_cloud_observer_load(plgd_cloud_status_observer_t *obs,
                             const oc_cloud_context_t *cloud_ctx) OC_NONNULL();

/// @brief Deinitialize the cloud observer
void dps_cloud_observer_deinit(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Copy the endpoint UUID to the cloud observer
bool dps_cloud_observer_copy_endpoint_uuid(plgd_cloud_status_observer_t *obs,
                                           const oc_uuid_t *uuid) OC_NONNULL(1);

/**
 * @brief Callback to handle cloud provisioning start
 *
 * @param ctx device provisioning context (cannot be NULL)
 * @param cloud_ctx cloud context (cannot be NULL)
 */
void dps_cloud_observer_on_provisioning_started(plgd_dps_context_t *ctx,
                                                oc_cloud_context_t *cloud_ctx)
  OC_NONNULL();

/**
 * @brief Wait for cloud to register and log in.
 *
 * @param ctx device provisioning context (cannot be NULL)
 */
void dps_cloud_observe_status(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Callback to handle cloud server change
 *
 * @param ctx cloud status observer (cannot be NULL)
 */
void dps_cloud_observer_on_server_change(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Delayed callback to repeatedly check current cloud status.
 *
 * @param user_data user provided context (expected device provisioning context,
 * cannot be NULL)
 * @return OC_EVENT_DONE on success, or on failure with forced reprovisioning
 * @return OC_EVENT_CONTINUE on failure with retry
 */
oc_event_callback_retval_t dps_cloud_observe_status_async(void *user_data)
  OC_NONNULL();

/** @brief Delayed callback to reprovision from the credentials step */
oc_event_callback_retval_t
dps_cloud_observer_reprovision_server_uuid_change_async(void *data);

/** Add cloud servers from an oc_rep_t */
void dps_cloud_add_servers(oc_cloud_context_t *cloud_ctx,
                           const oc_rep_t *servers) OC_NONNULL(1);

/** Count the number of cloud servers */
uint8_t dps_cloud_count_servers(const oc_cloud_context_t *cloud_ctx,
                                bool ignoreSelected) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* DPS_CLOUD_INTERNAL_H */
