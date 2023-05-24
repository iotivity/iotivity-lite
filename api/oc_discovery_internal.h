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

#include "oc_client_state.h"
#include "oc_endpoint.h"
#include "oc_ri.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief handle the discovery payload (e.g. parse the oic/res response and do
 * the callbacks)
 *
 * @param payload the recieved discovery response
 * @param len lenght of the payload
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

#ifdef __cplusplus
}
#endif

#endif /* OC_DISCOVERY_INTERNAL_H */
