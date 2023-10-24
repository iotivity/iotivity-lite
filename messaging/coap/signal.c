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

#include "api/oc_helpers_internal.h"
#include "api/oc_message_internal.h"
#include "log_internal.h"
#include "signal_internal.h"
#include "coap_internal.h"
#include "transactions_internal.h"
#include <string.h>

#ifdef OC_TCP

bool
coap_check_signal_message(uint8_t code)
{
  return code == CSM_7_01 || code == PING_7_02 || code == PONG_7_03 ||
         code == RELEASE_7_04 || code == ABORT_7_05;
}

static bool
coap_send_signal_message(const oc_endpoint_t *endpoint, coap_packet_t *packet)
{
  oc_message_t *message = oc_message_allocate_outgoing();
  if (message == NULL) {
    COAP_ERR("message alloc failed.");
    return false;
  }
  memcpy(&message->endpoint, endpoint, sizeof(oc_endpoint_t));

  message->length =
    coap_serialize_message(packet, message->data, oc_message_buffer_size());
  oc_send_message(message);
  return true;
}

bool
coap_send_ping_message(const oc_endpoint_t *endpoint, uint8_t custody_option,
                       const uint8_t *token, uint8_t token_len)
{
  if (token_len == 0 || (endpoint->flags & TCP) == 0) {
    COAP_ERR("coap_send_ping_message failed for invalid arguments (token_len: "
             "%s, tcp: %s)",
             token_len > 0 ? "ok" : "invalid",
             (endpoint->flags & TCP) != 0 ? "ok" : "invalid");
    return false;
  }

  coap_packet_t ping_pkt;
  coap_tcp_init_message(&ping_pkt, PING_7_02);

  coap_set_token(&ping_pkt, token, token_len);

  if (custody_option != 0 &&
      !coap_signal_set_custody(&ping_pkt, custody_option)) {
    COAP_ERR("coap_signal_set_custody failed");
    return false;
  }

  coap_transaction_t *t = coap_new_transaction(0, token, token_len, endpoint);
  if (t == NULL) {
    return false;
  }
  t->message->length = coap_serialize_message(&ping_pkt, t->message->data,
                                              oc_message_buffer_size());

  COAP_DBG("send ping signal message.");
  coap_send_transaction(t);
  return true;
}

bool
coap_send_pong_message(const oc_endpoint_t *endpoint,
                       const coap_packet_t *packet)
{
  coap_packet_t pong_pkt;
  coap_tcp_init_message(&pong_pkt, PONG_7_03);

  coap_set_token(&pong_pkt, packet->token, packet->token_len);

  if (packet->custody != 0 &&
      !coap_signal_set_custody(&pong_pkt, packet->custody)) {
    COAP_ERR("coap_signal_set_custody failed");
    return false;
  }

  COAP_DBG("send pong signal message.");
  return coap_send_signal_message(endpoint, &pong_pkt);
}

static void
coap_make_token(coap_packet_t *packet)
{
  packet->token_len = sizeof(packet->token);
  oc_random_buffer(packet->token, packet->token_len);
}

bool
coap_send_csm_message(const oc_endpoint_t *endpoint, uint32_t max_message_size,
                      uint8_t blockwise_transfer_option)
{
  (void)blockwise_transfer_option;

  coap_packet_t csm_pkt;
  coap_tcp_init_message(&csm_pkt, CSM_7_01);

  coap_make_token(&csm_pkt);

#ifdef OC_BLOCK_WISE
  if (blockwise_transfer_option > 0) {
    if (!coap_signal_set_blockwise_transfer(&csm_pkt,
                                            blockwise_transfer_option)) {
      COAP_ERR("coap_signal_set_blockwise_transfer failed");
      return false;
    }
    // Add this line below to remain until we start supporting BERT
    max_message_size = 1152;
  }
#endif /* OC_BLOCK_WISE */

  if (!coap_signal_set_max_msg_size(&csm_pkt, max_message_size)) {
    COAP_ERR("coap_signal_set_max_msg_size failed");
    return false;
  }

  COAP_DBG("send csm signal message.");
  return coap_send_signal_message(endpoint, &csm_pkt);
}

bool
coap_send_release_message(const oc_endpoint_t *endpoint, const char *alt_addr,
                          size_t alt_addr_len, uint32_t hold_off)
{
  coap_packet_t release_pkt;
  coap_tcp_init_message(&release_pkt, RELEASE_7_04);

  coap_make_token(&release_pkt);

  if (alt_addr_len > 0 &&
      !coap_signal_set_alt_addr(&release_pkt, alt_addr, alt_addr_len)) {
    COAP_ERR("coap_signal_set_alt_addr failed");
    return false;
  }

  if (hold_off > 0 && !coap_signal_set_hold_off(&release_pkt, hold_off)) {
    COAP_ERR("coap_signal_set_hold_off failed");
    return false;
  }

  COAP_DBG("send release signal message.");
  return coap_send_signal_message(endpoint, &release_pkt);
}

bool
coap_send_abort_message(const oc_endpoint_t *endpoint, uint16_t opt,
                        const char *diagnostic, size_t diagnostic_len)
{
  coap_packet_t abort_pkt;
  coap_tcp_init_message(&abort_pkt, ABORT_7_05);

  coap_make_token(&abort_pkt);

  if (opt != 0 && !coap_signal_set_bad_csm(&abort_pkt, opt)) {
    COAP_ERR("coap_signal_set_bad_csm failed");
    return false;
  }

  if (diagnostic_len > 0 && !coap_set_payload(&abort_pkt, (uint8_t *)diagnostic,
                                              (uint32_t)diagnostic_len)) {
    COAP_ERR("coap_set_payload failed");
    return false;
  }

  COAP_DBG("send abort signal message.");
  return coap_send_signal_message(endpoint, &abort_pkt);
}

coap_signal_result_t
coap_signal_handle_message(const coap_packet_t *packet,
                           const oc_endpoint_t *endpoint)
{
  COAP_DBG("Coap signal message received.(code: %d)", packet->code);
  if (packet->code == CSM_7_01) {
    tcp_csm_state_t state = oc_tcp_get_csm_state(endpoint);
    if (state == CSM_DONE) {
      // TODO: max-message-size, blockwise_transfer handling
      return COAP_SIGNAL_DONE;
    }
    if (state == CSM_NONE) {
      coap_send_csm_message(endpoint, (uint32_t)OC_PDU_SIZE, 0);
    }
    oc_tcp_update_csm_state(endpoint, CSM_DONE);
    return COAP_SIGNAL_DONE;
  }
  if (packet->code == PING_7_02) {
    coap_send_pong_message(endpoint, packet);
    return COAP_SIGNAL_DONE;
  }
  if (packet->code == PONG_7_03) {
    COAP_DBG("Find client cb using token :");
    COAP_DBG("  [%02X%02X%02X%02X%02X%02X%02X%02X]", packet->token[0],
             packet->token[1], packet->token[2], packet->token[3],
             packet->token[4], packet->token[5], packet->token[6],
             packet->token[7]);
    return COAP_SIGNAL_CONTINUE;
  }

  if (packet->code == RELEASE_7_04) {
    // alternative address
    // hold off
    oc_connectivity_end_session(endpoint);
    return COAP_SIGNAL_DONE;
  }

  if (packet->code == ABORT_7_05) {
    COAP_WRN("Peer aborted! [code: %d(diagnostic: %*.s)]", packet->bad_csm_opt,
             (int)packet->payload_len, (char *)packet->payload);
  }
  return COAP_SIGNAL_DONE;
}

bool
coap_signal_get_max_msg_size(const coap_packet_t *packet, uint32_t *size)
{
  if (packet->code != CSM_7_01 ||
      !IS_OPTION(packet, COAP_SIGNAL_OPTION_MAX_MSG_SIZE)) {
    return false;
  }
  *size = packet->max_msg_size;
  return true;
}

bool
coap_signal_set_max_msg_size(coap_packet_t *packet, uint32_t size)
{
  if (packet->code != CSM_7_01) {
    return false;
  }
  packet->max_msg_size = size;
  SET_OPTION(packet, COAP_SIGNAL_OPTION_MAX_MSG_SIZE);
  return true;
}

bool
coap_signal_get_blockwise_transfer(const coap_packet_t *packet,
                                   uint8_t *blockwise_transfer)
{
  if (packet->code != CSM_7_01 ||
      !IS_OPTION(packet, COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER)) {
    return false;
  }
  *blockwise_transfer = packet->blockwise_transfer;
  return true;
}

bool
coap_signal_set_blockwise_transfer(coap_packet_t *packet,
                                   uint8_t blockwise_transfer)
{
  if (packet->code != CSM_7_01 || blockwise_transfer > 1) {
    return false;
  }
  packet->blockwise_transfer = blockwise_transfer;
  SET_OPTION(packet, COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER);
  return true;
}

bool
coap_signal_get_custody(const coap_packet_t *packet, uint8_t *custody)
{
  if ((packet->code != PING_7_02 && packet->code != PONG_7_03) ||
      !IS_OPTION(packet, COAP_SIGNAL_OPTION_CUSTODY)) {
    return false;
  }
  *custody = packet->custody;
  return true;
}

bool
coap_signal_set_custody(coap_packet_t *packet, uint8_t custody)
{
  if ((packet->code != PING_7_02 && packet->code != PONG_7_03) ||
      (custody > 1)) {
    return false;
  }
  packet->custody = custody;
  SET_OPTION(packet, COAP_SIGNAL_OPTION_CUSTODY);
  return true;
}

size_t
coap_signal_get_alt_addr(const coap_packet_t *packet, const char **addr)
{
  if (packet->code != RELEASE_7_04 ||
      !IS_OPTION(packet, COAP_SIGNAL_OPTION_ALT_ADDR)) {
    return 0;
  }
  *addr = packet->alt_addr;
  return packet->alt_addr_len;
}

size_t
coap_signal_set_alt_addr(coap_packet_t *packet, const char *addr,
                         size_t addr_len)
{
  if (packet->code != RELEASE_7_04 || addr_len <= 0) {
    return 0;
  }
  packet->alt_addr = addr;
  packet->alt_addr_len = addr_len;
  SET_OPTION(packet, COAP_SIGNAL_OPTION_ALT_ADDR);
  return packet->alt_addr_len;
}

bool
coap_signal_get_hold_off(const coap_packet_t *packet, uint32_t *time_seconds)
{
  if (packet->code != RELEASE_7_04 ||
      !IS_OPTION(packet, COAP_SIGNAL_OPTION_HOLD_OFF)) {
    return false;
  }
  *time_seconds = packet->hold_off;
  return true;
}

bool
coap_signal_set_hold_off(coap_packet_t *packet, uint32_t time_seconds)
{
  if (packet->code != RELEASE_7_04) {
    return false;
  }
  packet->hold_off = time_seconds;
  SET_OPTION(packet, COAP_SIGNAL_OPTION_HOLD_OFF);
  return true;
}

bool
coap_signal_get_bad_csm(const coap_packet_t *packet, uint16_t *opt)
{
  if (packet->code != ABORT_7_05 ||
      !IS_OPTION(packet, COAP_SIGNAL_OPTION_BAD_CSM)) {
    return false;
  }
  *opt = packet->bad_csm_opt;
  return true;
}

bool
coap_signal_set_bad_csm(coap_packet_t *packet, uint16_t opt)
{
  if (packet->code != ABORT_7_05) {
    return false;
  }
  packet->bad_csm_opt = opt;
  SET_OPTION(packet, COAP_SIGNAL_OPTION_BAD_CSM);
  return true;
}
#endif /* OC_TCP */
