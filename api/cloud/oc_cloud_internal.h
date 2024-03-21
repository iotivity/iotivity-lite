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

#ifndef OC_CLOUD_INTERNAL_H
#define OC_CLOUD_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_api.h"
#include "oc_cloud.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Value of 0 means that the check which removes links after their Time to Live
 * property expires should be skipped. Thus the Time to Live of such link
 * is unlimited. This is the default value for the Time to Live property.
 */
#define RD_PUBLISH_TTL_UNLIMITED 0

#define OC_CLOUD_ACTION_REGISTER_STR "register"
#define OC_CLOUD_ACTION_LOGIN_STR "login"
#define OC_CLOUD_ACTION_REFRESH_TOKEN_STR "refreshtoken"
#define OC_CLOUD_ACTION_UNKNOWN_STR "unknown"

typedef struct
{
  const oc_string_t
    *access_token; /**< Access Token resolved with an auth code. */
  const oc_string_t *auth_provider; /**< Auth Provider ID*/
  const oc_string_t *ci_server;     /**< Cloud Interface Server URL which an a
                                       enrollee is going to registered. */
  oc_uuid_t sid; /**< OCF Cloud Identity as defined in OCF CNC 2.0 Spec. */
  const oc_rep_t *ci_servers; /**< List of Cloud Interface Servers. */
} oc_cloud_conf_update_t;

/** Initialize cloud data for devices */
bool cloud_init_devices(size_t devices);

/** Deinitialize cloud data for devices */
void cloud_deinit_devices(size_t devices);

/** Set cloud endpoint from currently selected cloud server address */
bool oc_cloud_set_endpoint(oc_cloud_context_t *ctx) OC_NONNULL();

/** Close connection to currently selected cloud server address  */
void oc_cloud_close_endpoint(const oc_endpoint_t *ep) OC_NONNULL();

/** Close connection and set endpoint to initial state */
void oc_cloud_reset_endpoint(oc_cloud_context_t *ctx) OC_NONNULL();

/** Initialize cloud data for devices */
bool oc_cloud_init(void);

/** Deinitialize cloud data for devices */
void oc_cloud_shutdown(void);

/** Check if the status code is one of the connection error codes */
bool cloud_is_connection_error_code(oc_status_t code);

/** Check if the status code is the timeout error code */
bool cloud_is_timeout_error_code(oc_status_t code);

void cloud_manager_cb(oc_cloud_context_t *ctx);
void cloud_set_last_error(oc_cloud_context_t *ctx, oc_cloud_error_t error);
void cloud_set_cps(oc_cloud_context_t *ctx, oc_cps_t cps);
void cloud_set_cps_and_last_error(oc_cloud_context_t *ctx, oc_cps_t cps,
                                  oc_cloud_error_t error);
/// Check if cloud is in deregistering state
bool cloud_is_deregistering(const oc_cloud_context_t *ctx);

/**
 * @brief Reset context for device.
 *
 * @note For secure device it will trigger deregistration if a cloud
 * endpoint peer exists.
 *
 * @param device device index
 * @param force just reset the context without execution of deregistration
 * @param sync for synchronous (no attempted login) execution of deregistration
 * for security device
 * @param timeout timeout for asynchronous deregistration requests
 * @return 0 on success
 * @return -1 on failure
 */
int cloud_reset(size_t device, bool force, bool sync, uint16_t timeout);

/**
 * @brief Set cloud configuration.
 *
 * @param ctx cloud context (cannot be NULL)
 * @param data configuration update (cannot be NULL)
 *
 * @return true on success
 * @return false on failure
 */
bool cloud_set_cloudconf(oc_cloud_context_t *ctx,
                         const oc_cloud_conf_update_t *data) OC_NONNULL();

/** Update cloud based on update data */
void oc_cloud_update_by_resource(oc_cloud_context_t *ctx,
                                 const oc_cloud_conf_update_t *data)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_INTERNAL_H */
