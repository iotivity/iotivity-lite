/****************************************************************************
 *
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

#ifndef CLOUD_INTERNAL_H
#define CLOUD_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "cloud.h"
#include "cloud_error.h"
#include "oc_api.h"

typedef struct cloud_store_s
{
  oc_string_t ci_server;
  oc_string_t auth_provider;
  oc_string_t uid;
  oc_string_t access_token;
  oc_string_t refresh_token;
  oc_string_t sid;

  uint8_t status;
  size_t device;
} cloud_store_t;

typedef struct cloud_context_s
{
  struct cloud_context_s *next;

  size_t device_index;

  cloud_cb_t callback;
  void *user_data;

  cloud_store_t store;

  oc_session_state_t cloud_ep_state;
  oc_endpoint_t *cloud_ep;
  uint8_t retry_count;
  uint8_t retry_refresh_token_count;
  cloud_error_t last_error;
  uint16_t expires_in;

  oc_link_t *rd_publish_resources;
  oc_link_t *rd_published_resources;
  oc_link_t *rd_delete_resources;
  bool rd_delete_all;

  oc_resource_t *cloud_conf;
} cloud_context_t;

typedef struct cloud_conf_update_s
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

#ifdef __cplusplus
extern "C" {
#endif

void cloud_store_dump_async(const cloud_store_t *store);
void cloud_store_load(cloud_store_t *store);
void cloud_store_dump(const cloud_store_t *store);
void cloud_store_deinit(cloud_store_t *store);

cloud_context_t *cloud_find_context(size_t device_index);
void cloud_manager_cb(cloud_context_t *ctx);
void cloud_set_string(oc_string_t *dst, const char *data, size_t len);
void cloud_set_last_error(cloud_context_t *ctx, cloud_error_t error);
void cloud_update_by_resource(cloud_context_t *ctx,
                              const cloud_conf_update_t *data);
void cloud_reconnect(cloud_context_t *ctx);

bool cloud_resource_init(cloud_context_t *ctx);

void cloud_rd_manager_status_changed(cloud_context_t *ctx);
void cloud_rd_deinit(cloud_context_t *ctx);

void cloud_manager_start(cloud_context_t *ctx);
void cloud_manager_stop(cloud_context_t *ctx);

bool cloud_access_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
                          const char *uid, const char *access_token,
                          size_t device_index, oc_response_handler_t handler,
                          void *user_data);
bool cloud_access_sign_in(oc_endpoint_t *endpoint, const char *uid,
                          const char *access_token, size_t device_index,
                          oc_response_handler_t handler, void *user_data);
bool cloud_access_sign_out(oc_endpoint_t *endpoint, const char *access_token,
                           size_t device_index, oc_response_handler_t handler,
                           void *user_data);
bool cloud_access_refresh_access_token(oc_endpoint_t *endpoint, const char *uid,
                                       const char *refresh_token,
                                       size_t device_index,
                                       oc_response_handler_t handler,
                                       void *user_data);

#ifdef __cplusplus
}
#endif

#endif // CLOUD_INTERNAL_H