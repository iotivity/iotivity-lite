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

#ifndef OC_CLOUD_STORE_INTERNAL_H
#define OC_CLOUD_STORE_INTERNAL_H

#include "oc_cloud.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_cloud_store_t
{
  oc_string_t ci_server;     ///< URL of the OCF Cloud.
  oc_string_t auth_provider; ///< The name of the Authorisation Provider through
                             // which access token was obtained.
  oc_string_t uid;           ///< Unique OCF Cloud User identifier
  oc_string_t access_token;  ///< Access token which is returned by an
                             ///< Authorisation Provider or OCF Cloud.
  oc_string_t refresh_token; ///< Refresh token used to refresh the access token
                             ///< before it expires.
  oc_string_t sid;           ///< The identity of the OCF Cloud
  int64_t expires_in; ///< The time in seconds for which the access token is
                      ///< valid.
  uint8_t status;
  oc_cps_t cps; ///< Cloud provisioning status of the device.
  size_t device;
} oc_cloud_store_t;

/**  @brief Encode cloud store to the global encoder. */
void cloud_store_encode(const oc_cloud_store_t *store) OC_NONNULL();

/** @brief Decode representation to store. */
bool cloud_store_decode(const oc_rep_t *rep, oc_cloud_store_t *store)
  OC_NONNULL(2);

/**
 * @brief Load store data from storage
 *
 * @param[out] store store to save data to (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool cloud_store_load(oc_cloud_store_t *store) OC_NONNULL();

/**
 * @brief Save store data to storage
 *
 * @param store store with data to save (cannot be NULL)
 * @return >=0 amount of bytes written to storage
 * @return <0 on failure
 */
long cloud_store_dump(const oc_cloud_store_t *store) OC_NONNULL();

/**
 * @brief Schedule delayed saving of store data to storage
 *
 * @param store with data to save (cannot be NULL)
 *
 * @warning You must ensure that the store pointer is still valid in the delayed
 * execution
 */
void cloud_store_dump_async(const oc_cloud_store_t *store) OC_NONNULL();

/**
 * @brief Set store data to default values
 *
 * @param store store
 */
void cloud_store_initialize(oc_cloud_store_t *store) OC_NONNULL();

/**
 * @brief Deallocate allocated data
 *
 * @param store store
 */
void cloud_store_deinitialize(oc_cloud_store_t *store) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_INTERNAL_H */
