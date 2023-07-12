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

#include "messaging/coap/coap.h"
#include "oc_client_state.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Callback function to customize the coap request */
typedef void (*coap_configure_request_fn_t)(coap_packet_t *, void *);

/** @brief Prepare and dispatch OC_GET or OC_DELETE request */
oc_client_cb_t *oc_do_request(oc_method_t method, const char *uri,
                              const oc_endpoint_t *endpoint, const char *query,
                              uint16_t timeout_seconds,
                              oc_response_handler_t handler, oc_qos_t qos,
                              void *user_data,
                              coap_configure_request_fn_t configure_request,
                              void *configure_request_data);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLIENT_API_INTERNAL_H */
