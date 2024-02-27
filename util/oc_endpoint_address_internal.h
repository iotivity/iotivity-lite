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

#ifndef OC_ENDPOINT_ADDRESS_INTERNAL_H
#define OC_ENDPOINT_ADDRESS_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST

#include "api/oc_helpers_internal.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"
#include "util/oc_endpoint_address.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID,
  OC_ENDPOINT_ADDRESS_METADATA_TYPE_NAME,
} oc_endpoint_address_metadata_type_t;

typedef union {
  oc_uuid_t uuid;   ///< identity associated with the URI
  oc_string_t name; ///< name associated with the URI
} oc_endpoint_address_metadata_id_t;

typedef struct
{
  oc_endpoint_address_metadata_id_t id;
  uint8_t id_type; ///< type of the identity
} oc_endpoint_address_metadata_t;

typedef union {
  oc_uuid_t uuid;
  oc_string_view_t name;
} oc_endpoint_address_metadata_id_view_t;

typedef struct
{
  oc_endpoint_address_metadata_id_view_t id;
  uint8_t id_type;
} oc_endpoint_address_metadata_view_t;

struct oc_endpoint_address_t
{
  struct oc_endpoint_address_t *next;
  oc_string_t uri;                         ///< URI
  oc_endpoint_address_metadata_t metadata; ///< metadata associated with the URI
};

typedef struct
{
  oc_string_view_t uri;
  oc_endpoint_address_metadata_view_t metadata;
} oc_endpoint_address_view_t;

/** Make a view for an endpoint address */
oc_endpoint_address_view_t oc_endpoint_address_view(
  const oc_endpoint_address_t *ea) OC_NONNULL();

/** Make a view of an endpoint address with a UUID in metadata */
oc_endpoint_address_view_t oc_endpoint_address_make_view_with_uuid(
  oc_string_view_t uri, oc_uuid_t id) OC_NONNULL();

/** Make a view of an endpoint address with a name in metadata */
oc_endpoint_address_view_t oc_endpoint_address_make_view_with_name(
  oc_string_view_t uri, oc_string_view_t name) OC_NONNULL();

/** Encode endpoint address to encoder */
CborError oc_endpoint_address_encode(
  CborEncoder *encoder, oc_string_view_t uri_key, oc_string_view_t uuid_key,
  oc_string_view_t name_key, oc_endpoint_address_view_t eav) OC_NONNULL();

typedef void (*on_selected_endpoint_address_change_fn_t)(void *data);

typedef struct
{
  oc_memb_t *pool; ///< memory pool for endpoint addresses
  const oc_endpoint_address_t
    *selected; ///< currently selected endpoint address
  on_selected_endpoint_address_change_fn_t
    on_selected_change; ///< callback invoked when the selected endpoint address
                        ///< changes
  void *
    on_selected_change_data; ///< data passed to the on_selected_change callback
  OC_LIST_STRUCT(addresses); ///< list of endpoint addresses
} oc_endpoint_addresses_t;

/** Initialize endpoint addresses
 *
 * @param eas endpoint addresses to initialize (cannot be NULL)
 * @param pool memory pool for endpoint addresses (cannot be NULL)
 * @param on_selected_change callback invoked when the selected endpoint address
 changes
 * @param on_selected_change_data data passed to the on_selected_change
 callback
 * @param default_ea default endpoint address to add (if the URI is empty the
 list will remain empty)
 * @return true on success
 * @return false on failure
 */
bool oc_endpoint_addresses_init(
  oc_endpoint_addresses_t *eas, oc_memb_t *pool,
  on_selected_endpoint_address_change_fn_t on_selected_change,
  void *on_selected_change_data, oc_endpoint_address_view_t default_ea)
  OC_NONNULL(1, 2);

/** Deinitialize endpoint addresses */
void oc_endpoint_addresses_deinit(oc_endpoint_addresses_t *eas) OC_NONNULL();

/** Deinitialize and reinitialize endpoint addresses */
bool oc_endpoint_addresses_reinit(oc_endpoint_addresses_t *eas,
                                  oc_endpoint_address_view_t default_ea)
  OC_NONNULL(1);

/** Get the number of endpoint adresses in the list */
size_t oc_endpoint_addresses_size(const oc_endpoint_addresses_t *eas)
  OC_NONNULL();

/** Check if the list of endpoint adresses is empty */
bool oc_endpoint_addresses_is_empty(const oc_endpoint_addresses_t *eas)
  OC_NONNULL();

/** Check if the list of endpoints contains an endpoint with the given URL */
bool oc_endpoint_addresses_contains(const oc_endpoint_addresses_t *eas,
                                    oc_string_view_t uri) OC_NONNULL();

/** Iterate the list of endpoint addresses. */
void oc_endpoint_addresses_iterate(const oc_endpoint_addresses_t *eas,
                                   oc_endpoint_addresses_iterate_fn_t fn,
                                   void *data) OC_NONNULL(1, 2);

/** Find an endpoint address in the list of endpoint addresses */
oc_endpoint_address_t *oc_endpoint_addresses_find(
  const oc_endpoint_addresses_t *eas, oc_string_view_t uri) OC_NONNULL();

/**
 * Allocate and add an address to the list of endpoint addresses
 *
 * @param eas endpoint addresses (cannot be NULL)
 * @param ea endpoint address to add
 *
 * @return new endpoint item on success
 * @return NULL on failure
 * */
oc_endpoint_address_t *oc_endpoint_addresses_add(oc_endpoint_addresses_t *eas,
                                                 oc_endpoint_address_view_t ea)
  OC_NONNULL();

/**
 * @brief Remove an address from the list of endpoint addresses
 *
 * @param eas endpoint addresses (cannot be NULL)
 * @param ea endpoint address to remove (cannot be NULL)
 *
 * @return true if the endpoint address was removed
 * @return false if the endpoint address was not found
 */
bool oc_endpoint_addresses_remove(oc_endpoint_addresses_t *eas,
                                  const oc_endpoint_address_t *ea) OC_NONNULL();

/**
 * @brief Remove an endpoint address with matching URI from the list of
 * endpoint addresses
 *
 * @param eas endpoint addresses (cannot be NULL)
 * @param uri URI to remove
 *
 * @return true if the endpoint address was removed
 * @return false if the endpoint address was not found
 */
bool oc_endpoint_addresses_remove_by_uri(oc_endpoint_addresses_t *eas,
                                         oc_string_view_t uri) OC_NONNULL();

/** Clear the list of endpoint addresses */
void oc_endpoint_addresses_clear(oc_endpoint_addresses_t *eas) OC_NONNULL();

/**
 * @brief Select an endpoint address from the list of endpoint addresses
 *
 * @param eas endpoint addresses (cannot be NULL)
 * @param selected endpoint address to select (cannot be NULL, must be in the
 * list of addresses)
 *
 * @return true if the endpoint address was selected
 * @return false if the address was not found in the list of endpoint address
 * (the previous selection remains)
 */
bool oc_endpoint_addresses_select(oc_endpoint_addresses_t *eas,
                                  const oc_endpoint_address_t *selected)
  OC_NONNULL();

/** Select an endpoint address by URI from the list of endpoint addresses */
bool oc_endpoint_addresses_select_by_uri(oc_endpoint_addresses_t *eas,
                                         oc_string_view_t uri) OC_NONNULL();

/** Select the next endpoint address from the list of endpoint addresses */
void oc_endpoint_addresses_select_next(oc_endpoint_addresses_t *eas)
  OC_NONNULL();

/** Check if an endpoint address matching the given URI is selected */
bool oc_endpoint_addresses_is_selected(const oc_endpoint_addresses_t *eas,
                                       oc_string_view_t uri) OC_NONNULL();

/** Get the currently selected endpoint address */
const oc_endpoint_address_t *oc_endpoint_addresses_selected(
  const oc_endpoint_addresses_t *eas) OC_NONNULL();

/** Get the URI of the currently selected endpoint address */
const oc_string_t *oc_endpoint_addresses_selected_uri(
  const oc_endpoint_addresses_t *eas) OC_NONNULL();

/** Get the UUID of the currently selected endpoint address */
const oc_uuid_t *oc_endpoint_addresses_selected_uuid(
  const oc_endpoint_addresses_t *eas) OC_NONNULL();

/** Get the name of the currently selected endpoint address */
const oc_string_t *oc_endpoint_addresses_selected_name(
  const oc_endpoint_addresses_t *eas) OC_NONNULL();

/**
 * Encode cloud server endpoints array to an encoder
 *
 * @param encoder encoder to write to (cannot be NULL)
 * @param eas endpoint addresses (cannot be NULL)
 * @param key key to use for encoding
 * @param skipIfSingleAndSelected if true, skip encoding if there a single
 * endpoint address in the list and it is selected
 */
CborError oc_endpoint_addresses_encode(CborEncoder *encoder,
                                       const oc_endpoint_addresses_t *eas,
                                       oc_string_view_t key,
                                       bool skipIfSingleAndSelected)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST */

#endif /* OC_ENDPOINT_ADDRESS_INTERNAL_H */
