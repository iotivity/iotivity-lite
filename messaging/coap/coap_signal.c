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
#include "coap_log.h"
#include "coap_signal.h"
#include "coap.h"
#include "transactions.h"
#include <string.h>

#ifdef OC_TCP
static void
coap_make_token(coap_packet_t *packet)
{
  packet->token_len = sizeof(packet->token);
  oc_random_buffer(packet->token, packet->token_len);
}

static int
coap_send_signal_message(const oc_endpoint_t *endpoint, coap_packet_t *packet)
{
  oc_message_t *message = oc_message_allocate_outgoing();
  if (!message) {
    COAP_ERR("message alloc failed.");
    return 0;
  }

  memcpy(&message->endpoint, endpoint, sizeof(oc_endpoint_t));

  message->length =
    coap_serialize_message(packet, message->data, oc_message_buffer_size());
  oc_send_message(message);

  return 1;
}

int
coap_send_csm_message(const oc_endpoint_t *endpoint, uint32_t max_message_size,
                      uint8_t blockwise_transfer_option)
{
  (void)blockwise_transfer_option;
  if (!endpoint)
    return 0;

  coap_packet_t csm_pkt[1];
  coap_tcp_init_message(csm_pkt, CSM_7_01);

  coap_make_token(csm_pkt);

#ifdef OC_BLOCK_WISE
  if (blockwise_transfer_option) {
    if (!coap_signal_set_blockwise_transfer(csm_pkt,
                                            blockwise_transfer_option)) {
      COAP_ERR("coap_signal_set_blockwise_transfer failed");
      return 0;
    }
    // Add this line below to remain until we start supporting BERT
    max_message_size = 1152;
  }
#endif /* OC_BLOCK_WISE */

  if (!coap_signal_set_max_msg_size(csm_pkt, max_message_size)) {
    COAP_ERR("coap_signal_set_max_msg_size failed");
    return 0;
  }

  COAP_DBG("send csm signal message.");
  return coap_send_signal_message(endpoint, csm_pkt);
}

int
coap_send_ping_message(const oc_endpoint_t *endpoint, uint8_t custody_option,
                       const uint8_t *token, uint8_t token_len)
{
  if (!endpoint || !token || token_len == 0 || !(endpoint->flags & TCP)) {
    COAP_ERR(
      "coap_send_ping_message failed for invalid arguments (endpoint: %s,"
      " token: %s, token_len: %s, tcp: %s)",
      endpoint ? "ok" : "invalid", token ? "ok" : "invalid",
      token_len > 0 ? "ok" : "invalid",
      endpoint && (endpoint->flags & TCP) ? "ok" : "invalid");
    return 0;
  }

  coap_packet_t ping_pkt[1];
  coap_tcp_init_message(ping_pkt, PING_7_02);

  coap_set_token(ping_pkt, token, token_len);

  if (custody_option) {
    if (!coap_signal_set_custody(ping_pkt, custody_option)) {
      COAP_ERR("coap_signal_set_custody failed");
      return 0;
    }
  }

  coap_transaction_t *t = coap_new_transaction(0, token, token_len, endpoint);
  if (!t) {
    return 0;
  }
  t->message->length = coap_serialize_message(ping_pkt, t->message->data,
                                              oc_message_buffer_size());

  COAP_DBG("send ping signal message.");
  coap_send_transaction(t);

  return 1;
}

int
coap_send_pong_message(const oc_endpoint_t *endpoint,
                       const coap_packet_t *packet)
{
  if (!endpoint || !packet)
    return 0;

  coap_packet_t pong_pkt;
  coap_tcp_init_message(&pong_pkt, PONG_7_03);

  coap_set_token(&pong_pkt, packet->token, packet->token_len);

  if (packet->custody) {
    if (!coap_signal_set_custody(&pong_pkt, packet->custody)) {
      COAP_ERR("coap_signal_set_custody failed");
      return 0;
    }
  }

  COAP_DBG("send pong signal message.");
  return coap_send_signal_message(endpoint, &pong_pkt);
}

int
coap_send_release_message(const oc_endpoint_t *endpoint, const char *alt_addr,
                          size_t alt_addr_len, uint32_t hold_off)
{
  if (!endpoint)
    return 0;

  coap_packet_t release_pkt[1];
  coap_tcp_init_message(release_pkt, RELEASE_7_04);

  coap_make_token(release_pkt);

  if (alt_addr && alt_addr_len > 0) {
    if (!coap_signal_set_alt_addr(release_pkt, alt_addr, alt_addr_len)) {
      COAP_ERR("coap_signal_set_alt_addr failed");
      return 0;
    }
  }

  if (hold_off > 0) {
    if (!coap_signal_set_hold_off(release_pkt, hold_off)) {
      COAP_ERR("coap_signal_set_hold_off failed");
      return 0;
    }
  }

  COAP_DBG("send release signal message.");
  return coap_send_signal_message(endpoint, release_pkt);
}

int
coap_send_abort_message(const oc_endpoint_t *endpoint, uint16_t opt,
                        const char *diagnostic, size_t diagnostic_len)
{
  if (!endpoint)
    return 0;

  coap_packet_t abort_pkt[1];
  coap_tcp_init_message(abort_pkt, ABORT_7_05);

  coap_make_token(abort_pkt);

  if (opt != 0) {
    if (!coap_signal_set_bad_csm(abort_pkt, opt)) {
      COAP_ERR("coap_signal_set_bad_csm failed");
      return 0;
    }
  }

  if (diagnostic && diagnostic_len > 0) {
    if (!coap_set_payload(abort_pkt, (uint8_t *)diagnostic, diagnostic_len)) {
      COAP_ERR("coap_set_payload failed");
      return 0;
    }
  }

  COAP_DBG("send abort signal message.");
  return coap_send_signal_message(endpoint, abort_pkt);
}

bool
coap_check_signal_message(const coap_packet_t *packet)
{
  if (!packet) {
    return false;
  }

  return packet->code == CSM_7_01 || packet->code == PING_7_02 ||
         packet->code == PONG_7_03 || packet->code == RELEASE_7_04 ||
         packet->code == ABORT_7_05;
}

int
handle_coap_signal_message(const coap_packet_t *packet,
                           const oc_endpoint_t *endpoint)
{
  COAP_DBG("Coap signal message received.(code: %d)", packet->code);
  if (packet->code == CSM_7_01) {
    tcp_csm_state_t state = oc_tcp_get_csm_state(endpoint);
    if (state == CSM_DONE) {
      // TODO: max-message-size, blockwise_transfer handling
      return COAP_NO_ERROR;
    } else if (state == CSM_NONE) {
      coap_send_csm_message(endpoint, OC_PDU_SIZE, 0);
    }
    oc_tcp_update_csm_state(endpoint, CSM_DONE);
  } else if (packet->code == PING_7_02) {
    coap_send_pong_message(endpoint, packet);
  } else if (packet->code == PONG_7_03) {
    COAP_DBG("Find client cb using token :");
    COAP_DBG("  [%02X%02X%02X%02X%02X%02X%02X%02X]", packet->token[0],
             packet->token[1], packet->token[2], packet->token[3],
             packet->token[4], packet->token[5], packet->token[6],
             packet->token[7]);
  } else if (packet->code == RELEASE_7_04) {
    // alternative address
    // hold off
    oc_connectivity_end_session(endpoint);
  } else if (packet->code == ABORT_7_05) {
    COAP_WRN("Peer aborted! [code: %d(diagnostic: %*.s)]", packet->bad_csm_opt,
             (int)packet->payload_len, (char *)packet->payload);
  }

  return COAP_NO_ERROR;
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
  if (packet->code != CSM_7_01 ||
      (blockwise_transfer != 0 && blockwise_transfer != 1)) {
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
      (custody != 0 && custody != 1)) {
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
  if (packet->code != RELEASE_7_04 || !addr || addr_len <= 0) {
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
