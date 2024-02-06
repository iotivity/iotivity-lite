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

#ifndef OC_CLOUD_APIS_INTERNAL_H
#define OC_CLOUD_APIS_INTERNAL_H

#include "api/cloud/oc_cloud_context_internal.h"
#include "oc_cloud.h"
#include "oc_cloud_access.h"
#include "oc_endpoint.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  oc_cloud_context_t *ctx;
  oc_cloud_cb_t cb;
  void *data;
  uint16_t timeout;
} cloud_api_param_t;

/** @brief Allocate and initialize cloud API parameter */
cloud_api_param_t *oc_cloud_api_new_param(oc_cloud_context_t *ctx,
                                          oc_cloud_cb_t cb, void *data,
                                          uint16_t timeout) OC_NONNULL(1);

/** @brief Free cloud API parameter */
void oc_cloud_api_free_param(cloud_api_param_t *p) OC_NONNULL();

/**
 * @brief Set cloud access configuration
 *
 * @param ctx cloud context (cannot be NULL)
 * @param handler the response handler (cannot be NULL)
 * @param user_data the user data to be conveyed to the response handler
 * @param timeout the timeout for the request
 * @param[out] conf cloud access configuration to be set (cannot be NULL)
 *
 * @return true on success
 */
bool oc_cloud_set_access_conf(oc_cloud_context_t *ctx,
                              oc_response_handler_t handler, void *user_data,
                              uint16_t timeout, oc_cloud_access_conf_t *conf)
  OC_NONNULL(1, 2, 5);

/** Execute cloud sign up */
int oc_cloud_do_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                         uint16_t timeout) OC_NONNULL(1, 2);
/** Execute cloud sign in */
int oc_cloud_do_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                      uint16_t timeout) OC_NONNULL(1, 2);
/** Execute cloud sign out */
int oc_cloud_do_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data,
                       uint16_t timeout) OC_NONNULL(1, 2);
/** Execute refreshing of the cloud access token */
int oc_cloud_do_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb,
                              void *data, uint16_t timeout) OC_NONNULL(1, 2);

/**
 * @brief Send a ping over the cloud connected connection
 *
 * @param endpoint endpoint to be used (cannot be NULL)
 * @param timeout_seconds timeout for the ping
 * @param handler the response handler (cannot be NULL)
 * @param user_data the user data to be conveyed to the response handler
 * @return true on success
 */
bool cloud_send_ping(const oc_endpoint_t *endpoint, uint16_t timeout_seconds,
                     oc_response_handler_t handler, void *user_data)
  OC_NONNULL(1, 3);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_APIS_INTERNAL_H */
