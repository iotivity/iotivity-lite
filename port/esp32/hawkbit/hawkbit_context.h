/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
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

#ifndef HAWKBIT_CONTEXT_H
#define HAWKBIT_CONTEXT_H

#include "hawkbit_action.h"
#include "hawkbit_download.h"
#include "hawkbit_update.h"
#include "oc_rep.h"
#include "oc_ri.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hawkbit_context_t hawkbit_context_t;

/** Get pointer to hawkbit data for given device */
hawkbit_context_t *hawkbit_get_context(size_t device);

/**
 * @brief Encode global hawkbit structure to root object
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @param resource hawkbit resource
 * @param iface encode interface
 * @param to_storage encoding to storage
 */
void hawkbit_encode(const hawkbit_context_t *ctx, oc_resource_t *resource,
                    oc_interface_mask_t iface, bool to_storage);

/**
 * @brief Decode representation into the hawkbit structure
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @param rep data to decode
 * @param from_storage encoding from storage
 *
 * @return true on success
 * @return false on failure
 */
bool hawkbit_decode(hawkbit_context_t *ctx, const oc_rep_t *rep,
                    bool from_storage);

/**
 * @brief Load hawkbit data from storage
 *
 * @param ctx hawkbit context (cannot be NULL)
 *
 * @return -1 on error
 * @return  >=0 on success, number of bytes loaded from storage
 */
long hawkbit_store_load(hawkbit_context_t *ctx);

/**
 * @brief Save hawkbit data to storage
 *
 * @param ctx hawkbit context (cannot be NULL)
 *
 * @return  <0 on error
 * @return >=0 on success, number of bytes written to storage
 */
long hawkbit_store_save(const hawkbit_context_t *ctx);

/** Set device version */
void hawkbit_set_version(hawkbit_context_t *ctx, const char *version,
                         size_t length);

/** Get device index */
size_t hawkbit_get_device(const hawkbit_context_t *ctx);

/** Get device version */
const char *hawkbit_get_version(const hawkbit_context_t *ctx);

/** Get package url from /oc/swu resource */
const char *hawkbit_get_package_url(const hawkbit_context_t *ctx);

/** Set polling interval */
void hawkbit_set_polling_interval(hawkbit_context_t *ctx,
                                  uint64_t pollingInterval);

typedef void (*hawkbit_on_polling_action_cb_t)(hawkbit_context_t *ctx,
                                               const hawkbit_action_t *action);

/** Get callback to be called when a new command is received by polling */
hawkbit_on_polling_action_cb_t hawkbit_get_polling_action_cb(
  const hawkbit_context_t *ctx);

/** Set download from parsed deployment */
void hawkbit_set_download(hawkbit_context_t *ctx,
                          hawkbit_deployment_t deployment);

/** Get download */
const hawkbit_download_t *hawkbit_get_download(const hawkbit_context_t *ctx);

/** Clear stored download */
void hawkbit_clear_download(hawkbit_context_t *ctx);

typedef void (*hawkbit_on_download_done_cb_t)(hawkbit_context_t *ctx,
                                              bool success);

/** Set callback to be called when donwload succeeds or fails with some error */
void hawkbit_set_on_download_done_cb(
  hawkbit_context_t *ctx, hawkbit_on_download_done_cb_t on_download_done_cb);

/** Get callback to be called when donwload succeeds or fails with some error */
hawkbit_on_download_done_cb_t hawkbit_get_on_download_done_cb(
  const hawkbit_context_t *ctx);

/** Set update */
void hawkbit_set_update(hawkbit_context_t *ctx, const char *deployment_id,
                        const char *version, const uint8_t *sha256,
                        size_t sha256_size, const uint8_t *partition_sha256,
                        size_t partition_sha256_size);

/** Get update */
const hawkbit_async_update_t *hawkbit_get_update(const hawkbit_context_t *ctx);

/** Clear stored update */
void hawkbit_clear_update(hawkbit_context_t *ctx);

/** All update steps should executed automatically without manually trigger */
void hawkbit_set_execute_all_steps(hawkbit_context_t *ctx,
                                   bool execute_all_steps);

/** Check if all update steps should executed automatically */
bool hawkbit_execute_all_steps(const hawkbit_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_CONTEXT_H */
