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

#ifndef PLGD_DPS_CONTEXT_INTERNAL_H
#define PLGD_DPS_CONTEXT_INTERNAL_H

#include "plgd_dps_cloud_internal.h"
#include "plgd_dps_dhcp_internal.h"
#include "plgd_dps_pki_internal.h"
#include "plgd_dps_retry_internal.h"
#include "plgd/plgd_dps.h" // plgd_dps_context_t, plgd_dps_manager_callbacks_t

#include "oc_api.h"
#include "util/oc_compiler.h"
#include "util/oc_endpoint_address_internal.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  oc_endpoint_addresses_t endpoints; ///< list of OCF endpoints
  oc_string_t owner;
  bool has_been_provisioned_since_reset; ///< true if the device has been
                                         ///< provisioned after factory reset
} plgd_dps_store_t;

typedef struct
{
  oc_string_t data; ///< fingerprint of the DPS server certificate. (eg SHA256)
  mbedtls_md_type_t
    md_type; ///< Hash algorithm used to calculate the fingerprint.
} plgd_dps_certificate_fingerprint_t;

struct plgd_dps_context_t
{
  struct plgd_dps_context_t *next;

  oc_resource_t *conf; ///< configuration resource
  size_t device;
  plgd_dps_manager_callbacks_t callbacks;
  plgd_dps_store_t store;            ///< data stored in oc_storage
  oc_endpoint_t *endpoint;           ///< DPS service endpoint
  oc_session_state_t endpoint_state; ///< DPS service endpoint state
  plgd_dps_retry_t retry; ///< retry configuration and current counter
  plgd_dps_error_t last_error;
  plgd_dps_certificate_fingerprint_t
    certificate_fingerprint; ///< fingerprint of the DPS server certificate or
                             ///< intermediate certificate.
  uint32_t status; ///< provisioning status - bitmask of provisioning steps
  dps_pki_configuration_t pki; ///< pki configuration
  plgd_cloud_status_observer_t
    cloud_observer;     ///< observer for changes of cloud status
  plgd_dps_dhcp_t dhcp; ///< DHCP configuration
  uint8_t
    transient_retry_count; ///< count of consecutive transient failures of the
                           ///< current provisioning step, if a limit is reached
                           ///< then full reprovisioning of the device is forced
  bool manager_started;    ///< provisioning manager has been started
  bool force_reprovision;  ///< force full reprovision on (re)start - refresh
                           ///< creds, acls, cloud from DPS service
  bool skip_verify; ///< insecure skip verify controls whether a dps client
                    ///< verifies the device provision service's certificate
                    ///< chain against trust anchor in the device.
  bool closing_insecure_peer; ///< a TLS peer with disabled time verification
                              ///< was opened and scheduled to close, we must
                              ///< wait for the scheduled asynchronous close to
                              ///< finish before continuing
};

/// @brief Allocate context
plgd_dps_context_t *dps_context_alloc(void);

/// @brief Deallocate context
void dps_context_free(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Add to global lists of contexts
void dps_context_list_add(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Remove from global lists of contexts
void dps_context_list_remove(const plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Check if the global lists of contexts is empty
bool dps_context_list_is_empty(void);

/**
 * @brief Callback invoked for each iterated DPS context.
 *
 * @param ctx context to iterate
 * @param data custom user data provided to the iteration function
 * @return true to continue iteration
 * @return false to stop iteration
 */
typedef bool (*dps_contexts_iterate_fn_t)(plgd_dps_context_t *ctx, void *data)
  OC_NONNULL(1);

/** Iterate the list of DPS contexts. */
void dps_contexts_iterate(dps_contexts_iterate_fn_t fn, void *data)
  OC_NONNULL(1);

/// @brief Initialize device context.
void dps_context_init(plgd_dps_context_t *ctx, size_t device) OC_NONNULL();

/// @brief Deinitialize device context.
void dps_context_deinit(plgd_dps_context_t *ctx) OC_NONNULL();

/// @brief Clear device context.
void dps_context_reset(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Sets flag to indicate that the device has been provisioned after DPS
 * reset.
 * @param ctx dps context (cannot be NULL)
 * @param dump dump the value to persistent storage
 * @return true if the value has changed
 * @return false otherwise
 */
bool dps_set_has_been_provisioned_since_reset(plgd_dps_context_t *ctx,
                                              bool dump) OC_NONNULL();

/// @brief Set last error and notify observers if it has changed.
bool dps_set_last_error(plgd_dps_context_t *ctx, plgd_dps_error_t error)
  OC_NONNULL();

/// @brief Set provisioning status flags, last error and notify observers if it
/// has changed.
bool dps_set_ps_and_last_error(plgd_dps_context_t *ctx, uint32_t add_flags,
                               uint32_t remove_flags, plgd_dps_error_t error)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_CONTEXT_INTERNAL_H */
