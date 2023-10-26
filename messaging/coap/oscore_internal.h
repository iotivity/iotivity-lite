/****************************************************************************
 *
 * Copyright (c) 2020 Intel Corporation
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

#ifndef COAP_OSCORE_INTERNAL_H
#define COAP_OSCORE_INTERNAL_H

#include "coap_internal.h"
#include "constants.h"
#include "oscore_constants.h"
#include "port/oc_connectivity.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

void oscore_send_error(const coap_packet_t *packet, uint8_t code,
                       const oc_endpoint_t *endpoint);
int oscore_read_piv(const uint8_t *piv, uint8_t piv_len, uint64_t *ssn);
int oscore_store_piv(uint64_t ssn, uint8_t *piv, uint8_t *piv_len);
uint32_t oscore_get_outer_code(const coap_packet_t *packet);
int oscore_is_oscore_message(const oc_message_t *msg);
int coap_parse_oscore_option(coap_packet_t *packet,
                             const uint8_t *current_option,
                             size_t option_length);
size_t coap_serialize_oscore_option(unsigned int *current_number,
                                    const coap_packet_t *packet,
                                    uint8_t *buffer);
int coap_get_header_oscore(coap_packet_t *packet, uint8_t **piv,
                           uint8_t *piv_len, uint8_t **kid, uint8_t *kid_len,
                           uint8_t **kid_ctx, uint8_t *kid_ctx_len);
int coap_set_header_oscore(coap_packet_t *packet, const uint8_t *piv,
                           uint8_t piv_len, const uint8_t *kid, uint8_t kid_len,
                           const uint8_t *kid_ctx, uint8_t kid_ctx_len);
coap_status_t oscore_parse_inner_message(uint8_t *data, size_t data_len,
                                         coap_packet_t *packet);
coap_status_t oscore_parse_outer_message(oc_message_t *msg,
                                         coap_packet_t *packet);
size_t oscore_serialize_message(coap_packet_t *packet, uint8_t *buffer,
                                size_t buffer_size) OC_NONNULL();
size_t oscore_serialize_plaintext(coap_packet_t *packet, uint8_t *buffer,
                                  size_t buffer_size) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* COAP_OSCORE_INTERNAL_H */
