/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef COAP_SIGNAL_H
#define COAP_SIGNAL_H

#include "oc_endpoint.h"
#include "messaging/coap/coap.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OC_TCP

/* CoAP signal codes */
typedef enum {
  CSM_7_01 = 225,
  PING_7_02 = 226,
  PONG_7_03 = 227,
  RELEASE_7_04 = 228,
  ABORT_7_05 = 229
} coap_signal_code_t;

/* CoAP signal option numbers */
typedef enum {
  COAP_SIGNAL_OPTION_MAX_MSG_SIZE = 2,       /* 0-4 B */
  COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER = 4, /* 0 B */
  COAP_SIGNAL_OPTION_CUSTODY = 2,            /* 0 B */
  COAP_SIGNAL_OPTION_ALT_ADDR = 2,           /* 1-255 B */
  COAP_SIGNAL_OPTION_HOLD_OFF = 4,           /* 0-3 B */
  COAP_SIGNAL_OPTION_BAD_CSM = 2,            /* 0-2 B */
} coap_signal_option_t;

int coap_send_csm_message(const oc_endpoint_t *endpoint,
                          uint32_t max_message_size,
                          uint8_t blockwise_transfer_option);
int coap_send_ping_message(const oc_endpoint_t *endpoint,
                           uint8_t custody_option, const uint8_t *token,
                           uint8_t token_len);
int coap_send_pong_message(const oc_endpoint_t *endpoint,
                           const coap_packet_t *packet);
int coap_send_release_message(const oc_endpoint_t *endpoint,
                              const char *alt_addr, size_t alt_addr_len,
                              uint32_t hold_off);
int coap_send_abort_message(const oc_endpoint_t *endpoint, uint16_t opt,
                            const char *diagnostic, size_t diagnostic_len);
bool coap_check_signal_message(const coap_packet_t *packet);
int handle_coap_signal_message(const coap_packet_t *packet,
                               const oc_endpoint_t *endpoint);

bool coap_signal_get_max_msg_size(const coap_packet_t *packet, uint32_t *size);
bool coap_signal_set_max_msg_size(coap_packet_t *packet, uint32_t size);
bool coap_signal_get_blockwise_transfer(const coap_packet_t *packet,
                                        uint8_t *blockwise_transfer);
bool coap_signal_set_blockwise_transfer(coap_packet_t *packet,
                                        uint8_t blockwise_transfer);
bool coap_signal_get_custody(const coap_packet_t *packet, uint8_t *custody);
bool coap_signal_set_custody(coap_packet_t *packet, uint8_t custody);
size_t coap_signal_get_alt_addr(const coap_packet_t *packet, const char **addr);
size_t coap_signal_set_alt_addr(coap_packet_t *packet, const char *addr,
                                size_t addr_len);
bool coap_signal_get_hold_off(const coap_packet_t *packet,
                              uint32_t *time_seconds);
bool coap_signal_set_hold_off(coap_packet_t *packet, uint32_t time_seconds);
bool coap_signal_get_bad_csm(const coap_packet_t *packet, uint16_t *opt);
bool coap_signal_set_bad_csm(coap_packet_t *packet, uint16_t opt);

#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* COAP_SIGNAL_H */
