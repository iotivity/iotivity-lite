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

#ifndef PLGD_DPS_STORE_INTERNAL_H
#define PLGD_DPS_STORE_INTERNAL_H

#include "plgd_dps_context_internal.h"
#include "plgd_dps_internal.h"

#include "oc_rep.h"
#include "util/oc_compiler.h"
#include "util/oc_endpoint_address_internal.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize store with empty values.
 *
 * @param store store to initialize
 */
void dps_store_init(
  plgd_dps_store_t *store,
  on_selected_endpoint_address_change_fn_t on_dps_endpoint_change,
  void *on_dps_endpoint_change_data) OC_NONNULL(1);

/**
 * @brief Rewrite store with empty values.
 *
 * @param store store to deinit
 */
void dps_store_deinit(plgd_dps_store_t *store) OC_NONNULL();

/**
 * @brief Load store from oc_storage.
 *
 * @param store store to load data in
 * @param device index of the device
 * @return 0	on success
 *         < 0 	on failure to load store
 */
OC_NO_DISCARD_RETURN
int dps_store_load(plgd_dps_store_t *store, size_t device) OC_NONNULL();

/**
 * @brief Encode store to root encoder.
 *
 * @param store store to encode
 */
bool dps_store_encode(const plgd_dps_store_t *store) OC_NONNULL();

/**
 * @brief Decode store from oc_rep_t.
 *
 * @param rep representation to decode
 * @param store store with decoded data
 */
void dps_store_decode(const oc_rep_t *rep, plgd_dps_store_t *store)
  OC_NONNULL();

/**
 * @brief Save store to oc_storage.
 *
 * @param store store to save
 * @param device index of the device
 * @return 0	on success
 *         < 0 	on failure to save store
 */
OC_NO_DISCARD_RETURN
int dps_store_dump(const plgd_dps_store_t *store, size_t device) OC_NONNULL();

/// @brief dump store in async handler
oc_event_callback_retval_t dps_store_dump_handler(void *data);

/// @brief Schedule asynchronous execution of dps_store_dump.
void dps_store_dump_async(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Set list of DPS endpoints.
bool dps_store_set_endpoints(plgd_dps_store_t *store,
                             const oc_string_t *selected_uri,
                             const oc_string_t *selected_name,
                             const oc_rep_t *endpoints) OC_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_STORE_INTERNAL_H */
