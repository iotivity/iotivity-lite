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

#ifndef COAP_SIGNAL_INTERNAL_H
#define COAP_SIGNAL_INTERNAL_H

#include "oc_endpoint.h"
#include "messaging/coap/coap_internal.h"
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OC_TCP

/* CoAP signal codes (RFC8323) */
typedef enum {
  CSM_7_01 = 225,     ///< Capabilities and Settings Message
  PING_7_02 = 226,    ///< Ping Message
  PONG_7_03 = 227,    ///< Pong Message
  RELEASE_7_04 = 228, ///< Release Message
  ABORT_7_05 = 229    ///< Abort Message
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

/** @brief Check if response code is one of the signal codes */
bool coap_check_signal_message(uint8_t code);

typedef enum {
  COAP_SIGNAL_DONE = 0,
  COAP_SIGNAL_CONTINUE = 1,
} coap_signal_result_t;

/** @brief Process signal message packet */
coap_signal_result_t coap_signal_handle_message(const coap_packet_t *packet,
                                                const oc_endpoint_t *endpoint)
  OC_NONNULL();

/** @brief Send PING message */
bool coap_send_ping_message(const oc_endpoint_t *endpoint,
                            uint8_t custody_option, const uint8_t *token,
                            uint8_t token_len) OC_NONNULL(1);

/** @brief Send PONG message */
bool coap_send_pong_message(const oc_endpoint_t *endpoint,
                            const coap_packet_t *packet) OC_NONNULL();

/** @brief Send CSM message */
bool coap_send_csm_message(const oc_endpoint_t *endpoint,
                           uint32_t max_message_size,
                           uint8_t blockwise_transfer_option) OC_NONNULL();

/** @brief Send RELEASE message */
bool coap_send_release_message(const oc_endpoint_t *endpoint,
                               const char *alt_addr, size_t alt_addr_len,
                               uint32_t hold_off) OC_NONNULL(1);

/** @brief Send ABORT message */
bool coap_send_abort_message(const oc_endpoint_t *endpoint, uint16_t opt,
                             const char *diagnostic, size_t diagnostic_len)
  OC_NONNULL(1);

/** @brief Get the COAP_SIGNAL_OPTION_MAX_MSG_SIZE option */
bool coap_signal_get_max_msg_size(const coap_packet_t *packet, uint32_t *size)
  OC_NONNULL();

/** @brief Set the COAP_SIGNAL_OPTION_MAX_MSG_SIZE option */
bool coap_signal_set_max_msg_size(coap_packet_t *packet, uint32_t size)
  OC_NONNULL();

/** @brief Get the COAP_SIGNAL_OPTION_MAX_MSG_SIZE option */
bool coap_signal_get_blockwise_transfer(const coap_packet_t *packet,
                                        uint8_t *blockwise_transfer)
  OC_NONNULL();

/** @brief Set the COAP_SIGNAL_OPTION_MAX_MSG_SIZE option */
bool coap_signal_set_blockwise_transfer(coap_packet_t *packet,
                                        uint8_t blockwise_transfer)
  OC_NONNULL();

/** @brief Get the COAP_SIGNAL_OPTION_CUSTODY option */
bool coap_signal_get_custody(const coap_packet_t *packet, uint8_t *custody)
  OC_NONNULL();

/** @brief Set the COAP_SIGNAL_OPTION_CUSTODY option */
bool coap_signal_set_custody(coap_packet_t *packet, uint8_t custody)
  OC_NONNULL();

/** @brief Get the COAP_SIGNAL_OPTION_ALT_ADDR option */
size_t coap_signal_get_alt_addr(const coap_packet_t *packet, const char **addr)
  OC_NONNULL();

/** @brief Set the COAP_SIGNAL_OPTION_ALT_ADDR option */
size_t coap_signal_set_alt_addr(coap_packet_t *packet, const char *addr,
                                size_t addr_len) OC_NONNULL(1);

/** @brief Get the COAP_SIGNAL_OPTION_HOLD_OFF option */
bool coap_signal_get_hold_off(const coap_packet_t *packet,
                              uint32_t *time_seconds) OC_NONNULL();

/** @brief Set the COAP_SIGNAL_OPTION_HOLD_OFF option */
bool coap_signal_set_hold_off(coap_packet_t *packet, uint32_t time_seconds)
  OC_NONNULL();

/** @brief Get the COAP_SIGNAL_OPTION_BAD_CSM option */
bool coap_signal_get_bad_csm(const coap_packet_t *packet, uint16_t *opt)
  OC_NONNULL();

/** @brief Set the COAP_SIGNAL_OPTION_BAD_CSM option */
bool coap_signal_set_bad_csm(coap_packet_t *packet, uint16_t opt) OC_NONNULL();

#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* COAP_SIGNAL_INTERNAL_H */
