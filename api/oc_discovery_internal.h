/****************************************************************************
 *
 * Copyright 2022 Jozef Kralik, All Rights Reserved.
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

#ifndef OC_DISCOVERY_INTERNAL_H
#define OC_DISCOVERY_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_client_state.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "util/oc_features.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_RES_URI "/oic/res"
#define OCF_RES_RT "oic.wk.res"

#define OCF_RES_PROP_SDUUID "sduuid"
#define OCF_RES_PROP_SDNAME "sdname"

#define OCF_RES_QUERY_SDUUID "sduuid"

/** The bitmask property should indicate only (discoverable, observable and
 * pushable) flags, see OCF Core Specification 7.8.2.5.3
 */
#ifdef OC_HAS_FEATURE_PUSH
#define OCF_RES_POLICY_PROPERTIES                                              \
  (OC_DISCOVERABLE | OC_OBSERVABLE | OC_PUSHABLE)
#else
#define OCF_RES_POLICY_PROPERTIES (OC_DISCOVERABLE | OC_OBSERVABLE)
#endif /* OC_HAS_FEATURE_PUSH */

/**
 * @brief Create /oic/res resource
 *
 * @param device the device to which the resource belongs
 */
void oc_create_discovery_resource(size_t device);

/** @brief Check if the URI matches the discovery resource URI (with or without
 *  the leading slash)
 */
bool oc_is_discovery_resource_uri(oc_string_view_t uri);

/**
 * @brief handle the discovery payload (e.g. parse the oic/res response and do
 * the callbacks)
 *
 * @param payload the recieved discovery response
 * @param len length of the payload
 * @param handler handler of the discovery
 * @param endpoint endpoint
 * @param user_data the user data to be supplied to the handler
 * @return oc_discovery_flags_t the discovery flags (e.g. more to come)
 */
oc_discovery_flags_t oc_discovery_process_payload(const uint8_t *payload,
                                                  size_t len,
                                                  oc_client_handler_t handler,
                                                  const oc_endpoint_t *endpoint,
                                                  void *user_data);

/**
 * @brief Determine whether to filter out endpoint from the resource.
 *
 * @param ep endpoint to check
 * @param resource the resource
 * @param request_origin the peer endpoint of request
 * @param device_index device index
 * @param owned_for_SVRs if the resource is secure vertical resource and is
 * owned.
 * @return true if endpoint should be filtered out, false otherwise
 */
bool oc_filter_out_ep_for_resource(const oc_endpoint_t *ep,
                                   const oc_resource_t *resource,
                                   const oc_endpoint_t *request_origin,
                                   size_t device_index, bool owned_for_SVRs);

#ifdef OC_RES_BATCH_SUPPORT

/**
 * @brief Check if resource should be included in the batch response.
 *
 * @param resource resource to check
 * @param endpoint endpoint (to check access to the resource)
 * @param skipDiscoveryResource true if the resource is /oic/res resource should
 * be skipped
 */
bool oc_discovery_resource_is_in_batch_response(const oc_resource_t *resource,
                                                const oc_endpoint_t *endpoint,
                                                bool skipDiscoveryResource)
  OC_NONNULL();

#ifdef OC_HAS_FEATURE_ETAG

/**
 * @brief Get the batch etag for /oic/res resource.
 *
 * For oic.if.b interface, the etag is highest etag of all discoverable and
 * accessible resources.
 *
 * @param endpoint endpoint accessing the resources (use in secure builds to
 * check ACL access)
 * @param device device index of the resources
 */
uint64_t oc_discovery_get_batch_etag(const oc_endpoint_t *endpoint,
                                     size_t device) OC_NONNULL();

#endif /* OC_HAS_FEATURE_ETAG */

#endif /* OC_RES_BATCH_SUPPORT */

#ifdef OC_WKCORE

#define OC_WELLKNOWNCORE_URI "/.well-known/core"
#define OC_WELLKNOWNCORE_RT "wk"

void oc_create_wkcore_resource(size_t device);

#endif /* OC_WKCORE */

#ifdef __cplusplus
}
#endif

#endif /* OC_DISCOVERY_INTERNAL_H */
