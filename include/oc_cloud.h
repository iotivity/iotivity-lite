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
  OC_CLOUD_REGISTERED = 1,
  OC_CLOUD_LOGGED_IN = 2,
  OC_CLOUD_TOKEN_EXPIRY = 4,
  OC_CLOUD_REFRESHED_TOKEN = 8,
  OC_CLOUD_LOGGED_OUT = 16,
  OC_CLOUD_FAILURE = 32,
  OC_CLOUD_DEREGISTERED = 64
} oc_cloud_status_t;

typedef enum oc_cps_t {
  OC_CPS_UNINITIALIZED = 0,
  OC_CPS_READYTOREGISTER,
  OC_CPS_REGISTERING,
  OC_CPS_REGISTERED,
  OC_CPS_FAILED
} oc_cps_t;

typedef struct oc_cloud_store_t
{
  oc_string_t ci_server;
  oc_string_t auth_provider;
  oc_string_t uid;
  oc_string_t access_token;
  oc_string_t refresh_token;
  oc_string_t sid;
  uint8_t status;
  size_t device;
} oc_cloud_store_t;

typedef enum {
  CLOUD_OK = 0,
  CLOUD_ERROR_RESPONSE = 1,
  CLOUD_ERROR_CONNECT = 2,
  CLOUD_ERROR_REFRESH_ACCESS_TOKEN = 3,
} oc_cloud_error_t;

struct oc_cloud_context_t;

/**
  @brief A function pointer for handling the cloud status.
  @param status Current status of the cloud.
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
  uint16_t expires_in;

  oc_link_t *rd_publish_resources;
  oc_link_t *rd_published_resources;
  oc_link_t *rd_delete_resources;
  bool rd_delete_all;

  oc_cps_t cps;

  oc_resource_t *cloud_conf;

  bool cloud_manager;
} oc_cloud_context_t;

oc_cloud_context_t *oc_cloud_get_context(size_t device);

int oc_cloud_manager_start(oc_cloud_context_t *ctx, oc_cloud_cb_t cb,
                           void *data);
int oc_cloud_manager_stop(oc_cloud_context_t *ctx);

int oc_cloud_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
int oc_cloud_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
int oc_cloud_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
int oc_cloud_deregister(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data);
int oc_cloud_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb,
                           void *data);

int oc_cloud_get_token_expiry(oc_cloud_context_t *ctx);

int oc_cloud_add_resource(oc_resource_t *resource);
void oc_cloud_delete_resource(oc_resource_t *resource);
int oc_cloud_publish_resources(size_t device);

int oc_cloud_provision_conf_resource(oc_cloud_context_t *ctx,
                                     const char *server,
                                     const char *access_token,
                                     const char *server_id,
                                     const char *auth_provider);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_H */
