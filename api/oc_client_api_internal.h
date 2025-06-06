/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 ***************************************************************************/

#ifndef OC_CLIENT_API_INTERNAL_H
#define OC_CLIENT_API_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "messaging/coap/coap_internal.h"
#include "oc_client_state.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Callback function to customize the coap request */
typedef void (*coap_configure_request_fn_t)(coap_packet_t *, const void *);

/** @brief Prepare and dispatch an OC_GET or an OC_DELETE request */
oc_client_cb_t *oc_do_request(
  oc_method_t method, const char *uri, const oc_endpoint_t *endpoint,
  const char *query, uint16_t timeout_seconds, oc_response_handler_t handler,
  oc_qos_t qos, void *user_data, coap_configure_request_fn_t configure_request,
  const void *configure_request_data) OC_NONNULL(2, 3, 6);

/** @brief Initialize CoAP request packet */
void oc_request_init_packet(coap_packet_t *packet, bool is_tcp,
                            coap_message_type_t type, oc_method_t method,
                            uint16_t mid) OC_NONNULL();

/** @brief Set common CoAP request packet options */
void oc_request_set_packet_options(coap_packet_t *packet,
                                   oc_content_format_t accept,
                                   oc_string_view_t uri, int32_t observe_seq,
                                   oc_string_view_t query) OC_NONNULL(1);

/** @brief Prepare an OC_POST or an OC_PUT request */
bool oc_init_async_request(oc_method_t method, const char *uri,
                           const oc_endpoint_t *endpoint, const char *query,
                           oc_response_handler_t handler, oc_qos_t qos,
                           void *user_data,
                           coap_configure_request_fn_t configure_request,
                           const void *configure_request_data) OC_NONNULL(2, 3);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLIENT_API_INTERNAL_H */
