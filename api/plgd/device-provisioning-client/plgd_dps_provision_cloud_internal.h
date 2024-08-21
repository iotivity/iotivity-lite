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

#ifndef PLGD_DPS_PROVISION_CLOUD_INTERNAL_H
#define PLGD_DPS_PROVISION_CLOUD_INTERNAL_H

#include "plgd/plgd_dps.h"

#include "oc_api.h"
#include "oc_config.h"
#include "oc_rep.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Configure cloud resource.
 *
 * @param ctx device context (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool dps_provisioning_set_cloud(plgd_dps_context_t *ctx) OC_NONNULL();

/** @brief Handle POST response from PLGD_DPS_CLOUD_URI. */
void dps_set_cloud_handler(oc_client_response_t *data) OC_NONNULL();

/** @brief Check if cloud configuration has been set. */
bool dps_has_cloud_configuration(size_t device) OC_NONNULL();

typedef struct cloud_conf_t
{
  const oc_string_t
    *access_token; /**< Access Token resolved with an auth code. */
  const oc_string_t *auth_provider; /**< Auth Provider ID*/
  const oc_string_t *ci_server;     /**< Selected Cloud Interface Server URL to
                                       which an Enrollee is going to register. */
  const oc_string_t
    *sid; /**< OCF Cloud Identity as defined in OCF CNC 2.0 Spec. */
  const oc_rep_t *ci_servers; /**< List of all Cloud Interface Server URLs. */
} cloud_conf_t;

/**
 * @brief Parse payload into cloud configuration.
 *
 * @param[in] payload payload to parse (cannot be NULL)
 * @param[out] cloud output cloud configuration (cannot be NULL)
 * @return true on success
 * @return false otherwise
 */
bool dps_register_cloud_fill_data(const oc_rep_t *payload, cloud_conf_t *cloud)
  OC_NONNULL();

/**
 * @brief Encode selected gateway.
 *
 * @param ctx device context (cannot be NULL)
 * @return true on success
 * @return false otherwise
 */
bool dps_provisioning_set_cloud_encode_selected_gateway(
  const plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Encode cloud configuration request payload.
 *
 * @param ctx device context (cannot be NULL)
 * @return true on success
 * @return false otherwise
 */
bool dps_provisioning_set_cloud_encode_payload(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/**
 * @brief Handle cloud configuration response.
 *
 * @param data response data (cannot be NULL)
 * @return plgd_dps_error_t
 */
plgd_dps_error_t dps_handle_set_cloud_response(oc_client_response_t *data)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_PROVISION_CLOUD_INTERNAL_H */
