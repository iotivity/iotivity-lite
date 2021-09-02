/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "coap_signal.h"
#include "coap.h"
#include "transactions.h"
#include <string.h>

#ifdef OC_TCP
static void
coap_make_token(coap_packet_t *packet)
{
  packet->token_len = COAP_TOKEN_LEN;
  int i = 0;
  uint32_t r;
  while (i < packet->token_len) {
    r = oc_random_value();
    memcpy(packet->token + i, &r, sizeof(r));
    i += sizeof(r);
  }
}

static int
coap_send_signal_message(oc_endpoint_t *endpoint, coap_packet_t *packet)
{
  oc_message_t *message = oc_internal_allocate_outgoing_message();
  if (!message) {
    OC_ERR("message alloc failed.");
    return 0;
  }

  memcpy(&message->endpoint, endpoint, sizeof(oc_endpoint_t));

  message->length = coap_serialize_message(packet, message->data);
  oc_send_message(message);

  return 1;
}

int
coap_send_csm_message(oc_endpoint_t *endpoint, uint32_t max_message_size,
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
      OC_ERR("coap_signal_set_blockwise_transfer failed");
      return 0;
    }
    // Add this line below to remain until we start supporting BERT
    max_message_size = 1152;
  }
#endif /* OC_BLOCK_WISE */

  if (!coap_signal_set_max_msg_size(csm_pkt, max_message_size)) {
    OC_ERR("coap_signal_set_max_msg_size failed");
    return 0;
  }

  OC_DBG("send csm signal message.");
  return coap_send_signal_message(endpoint, csm_pkt);
}

int
coap_send_ping_message(oc_endpoint_t *endpoint, uint8_t custody_option,
                       uint8_t *token, uint8_t token_len)
{
  if (!endpoint || !token || token_len == 0)
    return 0;

  coap_packet_t ping_pkt[1];
  coap_tcp_init_message(ping_pkt, PING_7_02);

  coap_set_token(ping_pkt, token, token_len);

  if (custody_option) {
    if (!coap_signal_set_custody(ping_pkt, custody_option)) {
      OC_ERR("coap_signal_set_custody failed");
      return 0;
    }
  }

  coap_transaction_t *t = coap_new_transaction(0, token, token_len, endpoint);
  if (!t) {
    return 0;
  }
  t->message->length = coap_serialize_message(ping_pkt, t->message->data);

  OC_DBG("send ping signal message.");
  coap_send_transaction(t);

  return 1;
}

int
coap_send_pong_message(oc_endpoint_t *endpoint, void *packet)
{
  if (!endpoint || !packet)
    return 0;

  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  coap_packet_t pong_pkt[1];
  coap_tcp_init_message(pong_pkt, PONG_7_03);

  coap_set_token(pong_pkt, coap_pkt->token, coap_pkt->token_len);

  if (coap_pkt->custody) {
    if (!coap_signal_set_custody(pong_pkt, coap_pkt->custody)) {
      OC_ERR("coap_signal_set_custody failed");
      return 0;
    }
  }

  OC_DBG("send pong signal message.");
  return coap_send_signal_message(endpoint, pong_pkt);
}

int
coap_send_release_message(oc_endpoint_t *endpoint, const char *alt_addr,
                          size_t alt_addr_len, uint32_t hold_off)
{
  if (!endpoint)
    return 0;

  coap_packet_t release_pkt[1];
  coap_tcp_init_message(release_pkt, RELEASE_7_04);

  coap_make_token(release_pkt);

  if (alt_addr && alt_addr_len > 0) {
    if (!coap_signal_set_alt_addr(release_pkt, alt_addr, alt_addr_len)) {
      OC_ERR("coap_signal_set_alt_addr failed");
      return 0;
    }
  }

  if (hold_off > 0) {
    if (!coap_signal_set_hold_off(release_pkt, hold_off)) {
      OC_ERR("coap_signal_set_hold_off failed");
      return 0;
    }
  }

  OC_DBG("send release signal message.");
  return coap_send_signal_message(endpoint, release_pkt);
}

int
coap_send_abort_message(oc_endpoint_t *endpoint, uint16_t opt,
                        const char *diagnostic, size_t diagnostic_len)
{
  if (!endpoint)
    return 0;

  coap_packet_t abort_pkt[1];
  coap_tcp_init_message(abort_pkt, ABORT_7_05);

  coap_make_token(abort_pkt);

  if (opt != 0) {
    if (!coap_signal_set_bad_csm(abort_pkt, opt)) {
      OC_ERR("coap_signal_set_bad_csm failed");
      return 0;
    }
  }

  if (diagnostic && diagnostic_len > 0) {
    if (!coap_set_payload(abort_pkt, (uint8_t *)diagnostic, diagnostic_len)) {
      OC_ERR("coap_set_payload failed");
      return 0;
    }
  }

  OC_DBG("send abort signal message.");
  return coap_send_signal_message(endpoint, abort_pkt);
}

int
coap_check_signal_message(void *packet)
{
  if (!packet)
    return 0;

  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  if (coap_pkt->code == CSM_7_01 || coap_pkt->code == PING_7_02 ||
      coap_pkt->code == PONG_7_03 || coap_pkt->code == RELEASE_7_04 ||
      coap_pkt->code == ABORT_7_05)
    return 1;

  return 0;
}

int
handle_coap_signal_message(void *packet, oc_endpoint_t *endpoint)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  OC_DBG("Coap signal message received.(code: %d)", coap_pkt->code);
  if (coap_pkt->code == CSM_7_01) {
    tcp_csm_state_t state = oc_tcp_get_csm_state(endpoint);
    if (state == CSM_DONE) {
      // TODO: max-message-size, blockwise_transfer handling
      return COAP_NO_ERROR;
    } else if (state == CSM_NONE) {
      coap_send_csm_message(endpoint, OC_PDU_SIZE, 0);
    }
    oc_tcp_update_csm_state(endpoint, CSM_DONE);
  } else if (coap_pkt->code == PING_7_02) {
    coap_send_pong_message(endpoint, packet);
  } else if (coap_pkt->code == PONG_7_03) {
    OC_DBG("Find client cb using token :");
    OC_DBG("  [%02X%02X%02X%02X%02X%02X%02X%02X]", coap_pkt->token[0],
           coap_pkt->token[1], coap_pkt->token[2], coap_pkt->token[3],
           coap_pkt->token[4], coap_pkt->token[5], coap_pkt->token[6],
           coap_pkt->token[7]);
  } else if (coap_pkt->code == RELEASE_7_04) {
    // alternative address
    // hold off
    oc_connectivity_end_session(endpoint);
  } else if (coap_pkt->code == ABORT_7_05) {
    OC_WRN("Peer aborted! [code: %d(diagnostic: %*.s)]", coap_pkt->bad_csm_opt,
           coap_pkt->payload_len, (char *)coap_pkt->payload);
  }

  return COAP_NO_ERROR;
}

int
coap_signal_get_max_msg_size(void *packet, uint32_t *size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != CSM_7_01 ||
      !IS_OPTION(coap_pkt, COAP_SIGNAL_OPTION_MAX_MSG_SIZE)) {
    return 0;
  }
  *size = coap_pkt->max_msg_size;
  return 1;
}

int
coap_signal_set_max_msg_size(void *packet, uint32_t size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != CSM_7_01) {
    return 0;
  }
  coap_pkt->max_msg_size = size;
  SET_OPTION(coap_pkt, COAP_SIGNAL_OPTION_MAX_MSG_SIZE);
  return 1;
}

int
coap_signal_get_blockwise_transfer(void *packet, uint8_t *blockwise_transfer)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != CSM_7_01 ||
      !IS_OPTION(coap_pkt, COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER)) {
    return 0;
  }
  *blockwise_transfer = coap_pkt->blockwise_transfer;
  return 1;
}

int
coap_signal_set_blockwise_transfer(void *packet, uint8_t blockwise_transfer)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != CSM_7_01 ||
      (blockwise_transfer != 0 && blockwise_transfer != 1)) {
    return 0;
  }
  coap_pkt->blockwise_transfer = blockwise_transfer;
  SET_OPTION(coap_pkt, COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER);
  return 1;
}

int
coap_signal_get_custody(void *packet, uint8_t *custody)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if ((coap_pkt->code != PING_7_02 && coap_pkt->code != PONG_7_03) ||
      !IS_OPTION(coap_pkt, COAP_SIGNAL_OPTION_CUSTODY)) {
    return 0;
  }
  *custody = coap_pkt->custody;
  return 1;
}

int
coap_signal_set_custody(void *packet, uint8_t custody)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if ((coap_pkt->code != PING_7_02 && coap_pkt->code != PONG_7_03) ||
      (custody != 0 && custody != 1)) {
    return 0;
  }
  coap_pkt->custody = custody;
  SET_OPTION(coap_pkt, COAP_SIGNAL_OPTION_CUSTODY);
  return 1;
}

size_t
coap_signal_get_alt_addr(void *packet, const char **addr)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != RELEASE_7_04 ||
      !IS_OPTION(coap_pkt, COAP_SIGNAL_OPTION_ALT_ADDR)) {
    return 0;
  }
  *addr = coap_pkt->alt_addr;
  return coap_pkt->alt_addr_len;
}

size_t
coap_signal_set_alt_addr(void *packet, const char *addr, size_t addr_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != RELEASE_7_04 || !addr || addr_len <= 0) {
    return 0;
  }
  coap_pkt->alt_addr = addr;
  coap_pkt->alt_addr_len = addr_len;
  SET_OPTION(coap_pkt, COAP_SIGNAL_OPTION_ALT_ADDR);
  return coap_pkt->alt_addr_len;
}

int
coap_signal_get_hold_off(void *packet, uint32_t *time_seconds)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != RELEASE_7_04 ||
      !IS_OPTION(coap_pkt, COAP_SIGNAL_OPTION_HOLD_OFF)) {
    return 0;
  }
  *time_seconds = coap_pkt->hold_off;
  return 1;
}

int
coap_signal_set_hold_off(void *packet, uint32_t time_seconds)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != RELEASE_7_04) {
    return 0;
  }
  coap_pkt->hold_off = time_seconds;
  SET_OPTION(coap_pkt, COAP_SIGNAL_OPTION_HOLD_OFF);
  return 1;
}

int
coap_signal_get_bad_csm(void *packet, uint16_t *opt)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != ABORT_7_05 ||
      !IS_OPTION(coap_pkt, COAP_SIGNAL_OPTION_BAD_CSM)) {
    return 0;
  }
  *opt = coap_pkt->bad_csm_opt;
  return 1;
}

int
coap_signal_set_bad_csm(void *packet, uint16_t opt)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->code != ABORT_7_05) {
    return 0;
  }
  coap_pkt->bad_csm_opt = opt;
  SET_OPTION(coap_pkt, COAP_SIGNAL_OPTION_BAD_CSM);
  return 1;
}
#endif /* OC_TCP */
