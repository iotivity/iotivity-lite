/******************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_CLOUD_ENDPOINT_INTERNAL_H
#define OC_CLOUD_ENDPOINT_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_cloud.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"
#include "util/oc_list.h"
#include "util/oc_secure_string_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OC_CLOUD_MAX_ENDPOINT_ADDRESSES
// max two endpoint addresses per device with static allocation
#define OC_CLOUD_MAX_ENDPOINT_ADDRESSES (2 * OC_MAX_NUM_DEVICES)
#endif /* OC_CLOUD_MAX_ENDPOINT_ADDRESSES */

struct oc_cloud_endpoint_t
{
  struct oc_cloud_endpoint_t *next;
  oc_string_t uri;
  oc_uuid_t id; ///< identity of the cloud server
};

typedef void (*on_selected_change_fn_t)(void *data);

typedef struct
{
  const oc_cloud_endpoint_t *selected; ///< currently selected server endpoint
  on_selected_change_fn_t
    on_selected_change; ///< callback invoked when the selected endpoint changes
  void *
    on_selected_change_data; ///< data passed to the on_selected_change callback
  OC_LIST_STRUCT(endpoints); ///< list of server endpoints
} oc_cloud_endpoints_t;

/** Initialize cloud server endpoints
 *
 * @param ce cloud endpoints (cannot be NULL)
 * @param on_selected_change callback invoked when the selected endpoint changes
 * @param on_selected_change_data data passed to the on_selected_change callback
 * @param default_uri URI of the default endpoint to add (if the URI is empty
 * the list will remain empty)
 * @param default_id identity of the default endpoint to add
 * @return true on success
 * @return false on failure
 */
bool oc_cloud_endpoints_init(oc_cloud_endpoints_t *ce,
                             on_selected_change_fn_t on_selected_change,
                             void *on_selected_change_data,
                             oc_string_view_t default_uri, oc_uuid_t default_id)
  OC_NONNULL(1);

/** Deinitialize cloud server endpoints */
void oc_cloud_endpoints_deinit(oc_cloud_endpoints_t *ce) OC_NONNULL();

/** Deinitialize and reinitialize cloud server endpoints */
bool oc_cloud_endpoints_reinit(oc_cloud_endpoints_t *ce,
                               oc_string_view_t default_uri,
                               oc_uuid_t default_id) OC_NONNULL(1);

/** Get the number of cloud server endpoints */
size_t oc_cloud_endpoints_size(const oc_cloud_endpoints_t *ce) OC_NONNULL();

/** Check if the list of cloud server endpoints is empty */
bool oc_cloud_endpoints_is_empty(const oc_cloud_endpoints_t *ce) OC_NONNULL();

/**
 * Allocate and add a cloud server endpoint to the list of endpoints
 *
 * @param ce cloud endpoints (cannot be NULL)
 * @param uri cloud endpoint URI to add
 * @param id cloud endpoint identity
 *
 * @return new endpoint item on success
 * @return NULL on failure
 * */
oc_cloud_endpoint_t *oc_cloud_endpoint_add(oc_cloud_endpoints_t *ce,
                                           oc_string_view_t uri, oc_uuid_t id)
  OC_NONNULL();

/**
 * @brief Remove a cloud server endpoint from the list of endpoints
 *
 * @param ce cloud endpoints (cannot be NULL)
 * @param ep cloud endpoint to remove (cannot be NULL)
 *
 * @return true if the endpoint was removed
 * @return false if the endpoint was not found
 */
bool oc_cloud_endpoint_remove(oc_cloud_endpoints_t *ce,
                              const oc_cloud_endpoint_t *ep) OC_NONNULL();

/**
 * @brief Remove a cloud server endpoint with given URI from the list of
 * endpoints
 *
 * @param ce cloud endpoints (cannot be NULL)
 * @param uri cloud endpoint URI to remove
 *
 * @return true if the endpoint was removed
 * @return false if the endpoint was not found
 */
bool oc_cloud_endpoint_remove_by_uri(oc_cloud_endpoints_t *ce,
                                     oc_string_view_t uri) OC_NONNULL();

/**
 * @brief Select a cloud server endpoint from the list of endpoints
 *
 * @param ce cloud endpoints (cannot be NULL)
 * @param selected cloud endpoint to select (cannot be NULL, must be in the list
 * of endpoints)
 *
 * @return true if the endpoint was selected
 * @return false if the endpoint was not found in the list of endpoints (the
 * previous selection remains)
 */
bool oc_cloud_endpoint_select(oc_cloud_endpoints_t *ce,
                              const oc_cloud_endpoint_t *selected) OC_NONNULL();

/** Select a cloud server endpoint by URI from the list of endpoints */
bool oc_cloud_endpoint_select_by_uri(oc_cloud_endpoints_t *ce,
                                     oc_string_view_t uri) OC_NONNULL();

/** Select the next cloud server endpoint from the list of endpoints */
void oc_cloud_endpoint_select_next(oc_cloud_endpoints_t *ce) OC_NONNULL();

/** Check if a cloud server endpoint matching the given URI is selected */
bool oc_cloud_endpoint_is_selected(const oc_cloud_endpoints_t *ce,
                                   oc_string_view_t uri) OC_NONNULL();

/** Get address of the currently selected cloud server endpoint */
const oc_string_t *oc_cloud_endpoint_selected_address(
  const oc_cloud_endpoints_t *ce) OC_NONNULL();

/** Get id of the currently selected cloud server endpoint */
const oc_uuid_t *oc_cloud_endpoint_selected_id(const oc_cloud_endpoints_t *ce)
  OC_NONNULL();

/** Iterate the list of cloud server endpoints. */
void oc_cloud_endpoints_iterate(const oc_cloud_endpoints_t *ce,
                                oc_cloud_endpoints_iterate_fn_t fn, void *data)
  OC_NONNULL(1, 2);

/** Clear the list of cloud server endpoints */
void oc_cloud_endpoints_clear(oc_cloud_endpoints_t *ce) OC_NONNULL();

/** Find an endpoint in the list of endpoints */
oc_cloud_endpoint_t *oc_cloud_endpoint_find(const oc_cloud_endpoints_t *ce,
                                            oc_string_view_t uri) OC_NONNULL();

/** Check if the list of endpoints contains an endpoint with the given URL */
bool oc_cloud_endpoint_contains(const oc_cloud_endpoints_t *ce,
                                oc_string_view_t uri) OC_NONNULL();

/**
 * Encode cloud server endpoints array to an encoder
 *
 * @param encoder encoder to write to (cannot be NULL)
 * @param ce cloud endpoints (cannot be NULL)
 * @param key key to use for encoding
 * @param skipIfSingleAndSelected if true, skip encoding if there a single
 * endpoint in the list and it is selected
 */
CborError oc_cloud_endpoints_encode(CborEncoder *encoder,
                                    const oc_cloud_endpoints_t *ce,
                                    oc_string_view_t key,
                                    bool skipIfSingleAndSelected) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_ENDPOINT_INTERNAL_H */
