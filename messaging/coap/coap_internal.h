/****************************************************************************
 *
 * Copyright (c) 2016-2020 Intel Corporation
 *               2023 plgd.dev s.r.o.
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
/*
 *
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

#ifndef COAP_INTERNAL_H
#define COAP_INTERNAL_H

#include "conf.h"
#include "constants.h"
#include "oc_buffer.h"
#include "oc_config.h"
#include "oc_ri.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "util/oc_compiler.h"

#ifdef OC_OSCORE
#include "oscore_constants.h"
#endif /* OC_OSCORE */

#include <stdbool.h>
#include <stddef.h> /* size_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* bitmap for set options */
enum { OPTION_MAP_SIZE = sizeof(uint8_t) * 8 };

#define SET_OPTION(packet, opt)                                                \
  ((packet)->options[(opt) / OPTION_MAP_SIZE] |= 1 << ((opt) % OPTION_MAP_SIZE))
#define UNSET_OPTION(packet, opt)                                              \
  ((packet)->options[(opt) / OPTION_MAP_SIZE] &=                               \
   ~(1 << ((opt) % OPTION_MAP_SIZE)))
#define IS_OPTION(packet, opt)                                                 \
  ((packet)->options[(opt) / OPTION_MAP_SIZE] &                                \
   (1 << ((opt) % OPTION_MAP_SIZE)))

/* enum value for coap transport type  */
typedef enum {
  COAP_TRANSPORT_UDP,
  COAP_TRANSPORT_TCP,
} coap_transport_type_t;

/* parsed message struct */
typedef struct
{
  uint8_t *buffer; /* pointer to CoAP header / incoming packet buffer /
                      memory to serialize packet */
  coap_transport_type_t transport_type;
  uint8_t version;
  coap_message_type_t type;
  uint8_t code;
  uint16_t mid;

  uint8_t token_len;
  uint8_t token[COAP_TOKEN_LEN];

  uint8_t options[COAP_OPTION_SIZE1 / OPTION_MAP_SIZE +
                  1]; /* bitmap to check if option is set */

  uint16_t content_format; /* parse options once and store; allows setting
                              options in random order  */
  uint32_t max_age;
  uint8_t etag_len;
  uint8_t etag[COAP_ETAG_LEN];
  size_t proxy_uri_len;
  const char *proxy_uri;
#if 0
  size_t proxy_scheme_len;
  const char *proxy_scheme;
#endif
  size_t uri_host_len;
  const char *uri_host;
#if 0
  size_t location_path_len;
  const char *location_path;
#endif
  uint16_t uri_port;
#if 0
  size_t location_query_len;
  const char *location_query;
#endif
  size_t uri_path_len;
  const char *uri_path;
  int32_t observe;
  uint16_t accept;
#if 0
  uint8_t if_match_len;
  uint8_t if_match[COAP_ETAG_LEN];
#endif

  uint32_t block2_num;
  uint8_t block2_more;
  uint16_t block2_size;
  uint32_t block2_offset;
  uint32_t block1_num;
  uint8_t block1_more;
  uint16_t block1_size;
  uint32_t block1_offset;
  uint32_t size2;
  uint32_t size1;
  size_t uri_query_len;
  const char *uri_query;
#if 0
  uint8_t if_none_match;
#endif

#ifdef OC_TCP
  /* CoAP over TCP Signal option values */
  uint32_t max_msg_size;
  uint8_t blockwise_transfer;
  uint8_t custody;
  const char *alt_addr;
  size_t alt_addr_len;
  uint32_t hold_off;
  uint16_t bad_csm_opt;
#endif /* OC_TCP */

#ifdef OC_OSCORE
  /* OSCORE Option value */
  uint8_t oscore_flags;
  uint8_t piv[OSCORE_PIV_LEN];
  uint8_t piv_len;
  uint8_t kid_ctx[OSCORE_IDCTX_LEN];
  uint8_t kid_ctx_len;
  uint8_t kid[OSCORE_CTXID_LEN];
  uint8_t kid_len;
#endif /* OC_OSCORE */

  uint32_t payload_len;
  uint8_t *payload;
} coap_packet_t;

typedef enum {
  OC_COAP_OPTION_OBSERVE_NOT_SET = -1,
  OC_COAP_OPTION_OBSERVE_REGISTER = 0,
  OC_COAP_OPTION_OBSERVE_UNREGISTER = 1,
  // observe values [2, 2^24-1] are used for the sequence number
  OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE = 2,
  OC_COAP_OPTION_OBSERVE_MAX_VALUE = ((1 << 24) - 1),
} oc_coap_option_observe_t;

/// @brief Get global COAP status code
coap_status_t coap_global_status_code(void);

/// @brief Set global COAP status code
void coap_set_global_status_code(coap_status_t code);

void coap_init_connection(void);
uint16_t coap_get_mid(void);

void coap_udp_init_message(coap_packet_t *packet, coap_message_type_t type,
                           uint8_t code, uint16_t mid) OC_NONNULL();

size_t coap_serialize_message(coap_packet_t *packet, uint8_t *buffer,
                              size_t buffer_size);

size_t coap_oscore_serialize_message(coap_packet_t *packet, uint8_t *buffer,
                                     size_t buffer_size, bool inner, bool outer,
                                     bool oscore);

void coap_send_message(oc_message_t *message) OC_NONNULL();

/**
 * @brief Parse CoAP message options
 *
 * @param packet pointer to coap_packet_t struct
 * @param data raw message data
 * @param data_len length of raw message data
 * @param current_option offset of current option in raw message data
 * @param inner oscore inner option
 * @param outer oscore outer option
 * @param oscore oscore used
 * @param validate if true, it doesn't modify data, and validation stops on
 * first BAD_REQUEST
 * @return coap_status_t
 */
coap_status_t coap_oscore_parse_options(coap_packet_t *packet,
                                        const uint8_t *data, size_t data_len,
                                        uint8_t *current_option, bool inner,
                                        bool outer, bool oscore, bool validate)
  OC_NONNULL();

/**
 * @brief Parse UDP CoAP message
 *
 * @param request pointer to coap_packet_t struct
 * @param data raw message data
 * @param data_len length of raw message data
 * @param validate if true, it doesn't modify data
 * @return coap_status_t
 */
coap_status_t coap_udp_parse_message(coap_packet_t *request, uint8_t *data,
                                     size_t data_len, bool validate)
  OC_NONNULL();

/*---------------------------------------------------------------------------*/

int coap_set_status_code(coap_packet_t *packet, unsigned int code) OC_NONNULL();

int coap_set_token(coap_packet_t *packet, const uint8_t *token,
                   size_t token_len) OC_NONNULL();

uint32_t coap_get_payload(const coap_packet_t *packet, const uint8_t **payload)
  OC_NONNULL();
uint32_t coap_set_payload(coap_packet_t *packet, uint8_t *payload,
                          uint32_t length) OC_NONNULL();

size_t coap_set_option_header(unsigned int delta, size_t length,
                              uint8_t *buffer);

#ifdef OC_TCP
void coap_tcp_init_message(coap_packet_t *packet, uint8_t code) OC_NONNULL();

size_t coap_tcp_get_packet_size(const uint8_t *data) OC_NONNULL();

/**
 * @brief Parse TCP CoAP message
 *
 * @param packet pointer to coap_packet_t struct
 * @param data raw message data
 * @param data_len length of raw message data
 * @param validate if true, it doesn't modify data
 * @return coap_status_t
 */
coap_status_t coap_tcp_parse_message(coap_packet_t *packet, uint8_t *data,
                                     size_t data_len, bool validate)
  OC_NONNULL();

void coap_tcp_parse_message_length(const uint8_t *data, size_t *message_length,
                                   uint8_t *num_extended_length_bytes)
  OC_NONNULL();
#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* COAP_INTERNAL_H */
