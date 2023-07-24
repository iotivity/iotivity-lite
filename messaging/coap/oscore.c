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

#ifdef OC_SECURITY
#ifdef OC_OSCORE

#include "api/oc_message_internal.h"
#include "oscore.h"
#include "coap.h"
#include "coap_log.h"
#include "coap_options.h"
#include "coap_signal.h"
#include "oc_ri.h"
#include <stdint.h>

void
oscore_send_error(const coap_packet_t *packet, uint8_t code,
                  const oc_endpoint_t *endpoint)
{
  if (endpoint->flags & MULTICAST) {
    return;
  }

  uint16_t mid = packet->mid;
  coap_message_type_t type = COAP_TYPE_NON;
  if (packet->type == COAP_TYPE_CON) {
    type = COAP_TYPE_ACK;
  } else {
    mid = coap_get_mid();
  }

  coap_packet_t msg;
  coap_udp_init_message(&msg, type, code, mid);
  msg.transport_type = packet->transport_type;
  oc_message_t *message = oc_message_allocate_outgoing();
  if (message == NULL) {
    return;
  }
  memcpy(&message->endpoint, endpoint, sizeof(*endpoint));
  memset(&message->endpoint.di, 0, sizeof(oc_uuid_t));
  if (packet->token_len > 0) {
    coap_set_token(&msg, packet->token, packet->token_len);
  }
  coap_options_set_max_age(&msg, 0);
  size_t len =
    coap_serialize_message(&msg, message->data, oc_message_buffer_size());
  if (len == 0) {
    oc_message_unref(message);
    return;
  }

  message->length = len;
  coap_send_message(message);
  COAP_DBG("*** send OSCORE error (%u) ***", code);
}

int
oscore_read_piv(const uint8_t *piv, uint8_t piv_len, uint64_t *ssn)
{
  *ssn = 0;

  uint8_t j = sizeof(uint64_t) - piv_len;
  for (uint8_t i = 0; i < piv_len; i++, j++) {
    memcpy((char *)ssn + j, &piv[i], 1);
  }

  int _botest = 1;
  if (*(char *)&_botest == 1) {
    /* If byte order is Little-endian, convert to Big-endian */
    *ssn = (*ssn & 0x00ff00ff00ff00ff) << 8 | (*ssn & 0xff00ff00ff00ff00) >> 8;
    *ssn =
      (*ssn & 0x0000ffff0000ffff) << 16 | (*ssn & 0xffff0000ffff0000) >> 16;
    *ssn =
      (*ssn & 0x00000000ffffffff) << 32 | (*ssn & 0xffffffff00000000) >> 32;
  }

  return 0;
}

int
oscore_store_piv(uint64_t ssn, uint8_t *piv, uint8_t *piv_len)
{
  int _botest = 1;

  memset(piv, 0, OSCORE_PIV_LEN);

  if (ssn == 0) {
    piv[0] = 0;
    *piv_len = 1;
    return 0;
  }

  if (*(char *)&_botest == 1) {
    /* If byte order is Little-endian, convert to Big-endian */
    ssn = (ssn & 0x00ff00ff00ff00ff) << 8 | (ssn & 0xff00ff00ff00ff00) >> 8;
    ssn = (ssn & 0x0000ffff0000ffff) << 16 | (ssn & 0xffff0000ffff0000) >> 16;
    ssn = (ssn & 0x00000000ffffffff) << 32 | (ssn & 0xffffffff00000000) >> 32;
  }

  *piv_len = 0;
  const char *p = (const char *)&ssn + 8 - OSCORE_PIV_LEN;
  const char *end = p + OSCORE_PIV_LEN;
  while (p != end && *p == 0) {
    p++;
  }
  while (p != end) {
    piv[(*piv_len)++] = *p;
    p++;
  }

  return 0;
}

uint32_t
oscore_get_outer_code(const coap_packet_t *packet)
{
  bool observe = false;
  if (IS_OPTION(packet, COAP_OPTION_OBSERVE)) {
    observe = true;
  }

  if ((packet->code >= OC_GET && packet->code <= OC_DELETE)
#ifdef OC_TCP
      || (packet->code == PING_7_02 || packet->code == ABORT_7_05 ||
          packet->code == CSM_7_01)
#endif /* OC_TCP */
  ) {
    /* Requests */
    if (observe) {
      return OC_FETCH;
    } else {
      return OC_POST;
    }
  } else {
    /* Responses */
    if (observe) {
      return oc_status_code(OC_STATUS_OK);
    }
  }

  return oc_status_code(OC_STATUS_CHANGED);
}

int
coap_get_header_oscore(coap_packet_t *packet, uint8_t **piv, uint8_t *piv_len,
                       uint8_t **kid, uint8_t *kid_len, uint8_t **kid_ctx,
                       uint8_t *kid_ctx_len)
{
  if (!IS_OPTION(packet, COAP_OPTION_OSCORE)) {
    return 0;
  }

  /* Partial IV */
  if (piv) {
    *piv = packet->piv;
    *piv_len = packet->piv_len;
  }

  /* kid */
  if (kid) {
    *kid = packet->kid;
    *kid_len = packet->kid_len;
  }

  /* kid context */
  if (kid_ctx) {
    *kid_ctx = packet->kid_ctx;
    *kid_ctx_len = packet->kid_ctx_len;
  }

  return 1;
}

int
coap_set_header_oscore(coap_packet_t *packet, const uint8_t *piv,
                       uint8_t piv_len, const uint8_t *kid, uint8_t kid_len,
                       const uint8_t *kid_ctx, uint8_t kid_ctx_len)
{
  packet->oscore_flags = piv_len;

  /* Partial IV */
  if (piv_len > 0) {
    memcpy(packet->piv, piv, piv_len);
    packet->piv_len = piv_len;
  }

  /* kid */
  if (packet->code <= OC_FETCH) {
    packet->oscore_flags |= 1 << OSCORE_FLAGS_BIT_KID_POSITION;
  }
  if (kid_len > 0) {
    memcpy(packet->kid, kid, kid_len);
    packet->kid_len = kid_len;
  }

  /* kid context */
  if (kid_ctx_len > 0) {
    memcpy(packet->kid_ctx, kid_ctx, kid_ctx_len);
    packet->kid_ctx_len = kid_ctx_len;
    packet->oscore_flags |= 1 << OSCORE_FLAGS_BIT_KID_CTX_POSITION;
  }

  SET_OPTION(packet, COAP_OPTION_OSCORE);

  return 1;
}

int
coap_parse_oscore_option(coap_packet_t *packet, const uint8_t *current_option,
                         size_t option_length)
{
  /*
    OSCORE Option structure From RFC 8613:

    0 1 2 3 4 5 6 7 <------------- n bytes -------------->
    +-+-+-+-+-+-+-+-+--------------------------------------
    |0 0 0|h|k|  n  |       Partial IV (if any) ...
    +-+-+-+-+-+-+-+-+--------------------------------------

    <- 1 byte -> <----- s bytes ------>
    +------------+----------------------+------------------+
    | s (if any) | kid context (if any) | kid (if any) ... |
    +------------+----------------------+------------------+
  */

  COAP_DBG("OSCORE option");
  if (option_length == 0) {
    COAP_DBG("\t---empty value");
    return 0;
  }
  /* Flags  |0 0 0|h|k|  n  | */
  uint8_t oscore_flags = *current_option;
  current_option++;
  option_length--;
  COAP_DBG("\tflags: %02x", oscore_flags);

  /* Partial IV length (n bytes) */
  uint8_t piv[OSCORE_PIV_LEN];
  uint8_t piv_len = (oscore_flags & OSCORE_FLAGS_PIVLEN_BITMASK);
  if (piv_len > 0) {
    /* Partial IV */
    memcpy(piv, current_option, piv_len);
    current_option += piv_len;
    option_length -= piv_len;

    COAP_DBG("\tPartial IV:");
    COAP_LOGbytes(piv, piv_len);
  }

  /* kid context (if any) */
  /* Check if 'h' flag bit is set */
  uint8_t kid_ctx[OSCORE_IDCTX_LEN];
  uint8_t kid_ctx_len = 0;
  if ((oscore_flags & OSCORE_FLAGS_KIDCTX_BITMASK) != 0) {
    kid_ctx_len = *current_option;
    current_option++;
    option_length--;

    /* Store kid context */
    if (kid_ctx_len > OSCORE_IDCTX_LEN) {
      COAP_ERR("oscore: invalid kid context length(%d)", kid_ctx_len);
      return -1;
    }
    memcpy(kid_ctx, current_option, kid_ctx_len);
    current_option += kid_ctx_len;
    option_length -= kid_ctx_len;

    COAP_DBG("\tkid context:");
    COAP_LOGbytes(kid_ctx, kid_ctx_len);
  }

  /* kid (if any) */
  /* Check if 'k' flag bit is set */
  uint8_t kid[OSCORE_CTXID_LEN];
  uint8_t kid_len = 0;
  if ((oscore_flags & OSCORE_FLAGS_KID_BITMASK) != 0) {
    if (option_length > OSCORE_CTXID_LEN) {
      COAP_ERR("oscore: invalid option length for kid(%zu)", option_length);
      return -1;
    }
    /* Remaining bytes in option: kid */
    kid_len = (uint8_t)option_length;
    memcpy(kid, current_option, option_length);

    COAP_DBG("\tkid:");
    COAP_LOGbytes(kid, kid_len);
  }

  packet->oscore_flags = oscore_flags;
  packet->piv_len = piv_len;
  if (piv_len > 0) {
    memcpy(packet->piv, piv, piv_len);
  }
  packet->kid_ctx_len = kid_ctx_len;
  if (kid_ctx_len > 0) {
    memcpy(packet->kid_ctx, kid_ctx, kid_ctx_len);
  }
  packet->kid_len = kid_len;
  if (kid_len > 0) {
    memcpy(packet->kid, kid, kid_len);
  }

  return 0;
}

size_t
coap_serialize_oscore_option(unsigned int *current_number,
                             const coap_packet_t *packet, uint8_t *buffer)
{
  /* Calculate OSCORE option value length */
  size_t option_length =
    packet->piv_len + packet->kid_len + packet->kid_ctx_len;
  if (packet->kid_ctx_len > 0) {
    ++option_length;
  }
  if (packet->oscore_flags > 0) {
    ++option_length;
  }

  /* Serialize OSCORE option header */
  size_t header_length = coap_set_option_header(
    COAP_OPTION_OSCORE - *current_number, option_length, buffer);

  if (buffer) {
    buffer += header_length;

    COAP_DBG("OSCORE option");
    COAP_DBG("\tflags: %02x", packet->oscore_flags);
    if (packet->oscore_flags != 0) {
      /* Serialize OSCORE option flags */
      *buffer = packet->oscore_flags;
      ++buffer;

      /* Serialize Partial IV */
      if (packet->piv_len > 0) {
        memcpy(buffer, packet->piv, packet->piv_len);
        buffer += packet->piv_len;

        COAP_DBG("\tPartial IV:");
        COAP_LOGbytes(packet->piv, packet->piv_len);
      }

      /* Serialize kid context */
      if (packet->kid_ctx_len > 0) {
        /* kid context length */
        *buffer = packet->kid_ctx_len;
        ++buffer;

        memcpy(buffer, packet->kid_ctx, packet->kid_ctx_len);
        buffer += packet->kid_ctx_len;

        COAP_DBG("\tkid context:");
        COAP_LOGbytes(packet->kid_ctx, packet->kid_ctx_len);
      }

      /* Remaining bytes, if any, represent the kid */
      if (packet->kid_len > 0) {
        memcpy(buffer, packet->kid, packet->kid_len);

        COAP_DBG("\tkid:");
        COAP_LOGbytes(packet->kid, packet->kid_len);
      }
    }
  }

  *current_number = COAP_OPTION_OSCORE;

  return option_length + header_length;
}

size_t
oscore_serialize_plaintext(coap_packet_t *packet, uint8_t *buffer,
                           size_t buffer_size)
{
  return coap_oscore_serialize_message(packet, buffer, buffer_size, true, false,
                                       true);
}

size_t
oscore_serialize_message(coap_packet_t *packet, uint8_t *buffer,
                         size_t buffer_size)
{
  return coap_oscore_serialize_message(packet, buffer, buffer_size, false, true,
                                       true);
}

coap_status_t
oscore_parse_inner_message(uint8_t *data, size_t data_len,
                           coap_packet_t *packet)
{
  /* initialize packet */
  memset(packet, 0, sizeof(coap_packet_t));
  /* pointer to packet bytes */
  packet->buffer = data;

  /* Code */
  packet->code = data[0];
  COAP_DBG("Inner CoAP code: %d", packet->code);

  uint8_t *current_option = &data[1];

  /* Parse inner options */
  coap_status_t ret = coap_oscore_parse_options(
    packet, data, data_len, current_option, true, false, true, false);
  if (COAP_NO_ERROR != ret) {
    COAP_DBG("coap_oscore_parse_options failed! %d", ret);
    return ret;
  }

  return COAP_NO_ERROR;
}

int
oscore_is_oscore_message(const oc_message_t *msg)
{
  const uint8_t *current_option = NULL;

  /* Determine exact location of the CoAP options in the packet buffer */
#ifdef OC_TCP
  if (msg->endpoint.flags & TCP) {
    /* Calculate CoAP_TCP header length */
    size_t message_length = 0;
    uint8_t num_extended_length_bytes = 0;
    coap_tcp_parse_message_length(msg->data, &message_length,
                                  &num_extended_length_bytes);

    current_option =
      msg->data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;
  } else
#endif /* OC_TCP */
  {
    current_option = msg->data + COAP_HEADER_LEN;
  }

  size_t token_len = (COAP_HEADER_TOKEN_LEN_MASK & msg->data[0]) >>
                     COAP_HEADER_TOKEN_LEN_POSITION;

  current_option += token_len;

  /* Parse outer options */
  unsigned int option_number = 0;
  unsigned int option_delta = 0;
  size_t option_length = 0;

  while (current_option < msg->data + msg->length) {
    if ((current_option[0] & 0xF0) == 0xF0) {
      break;
    }

    option_delta = current_option[0] >> 4;
    option_length = current_option[0] & 0x0F;
    ++current_option;

    if (option_delta == 13) {
      option_delta += current_option[0];
      ++current_option;
    } else if (option_delta == 14) {
      option_delta += 255;
      option_delta += current_option[0] << 8;
      ++current_option;
      option_delta += current_option[0];
      ++current_option;
    }

    if (option_length == 13) {
      option_length += current_option[0];
      ++current_option;
    } else if (option_length == 14) {
      option_length += 255;
      option_length += current_option[0] << 8;
      ++current_option;
      option_length += current_option[0];
      ++current_option;
    }

    option_number += option_delta;

    switch (option_number) {
    case COAP_OPTION_OSCORE:
      /* Found the OSCORE option, return success */
      return 0;
    default:
      break;
    }

    current_option += option_length;
  }

  return -1;
}

coap_status_t
oscore_parse_outer_message(oc_message_t *msg, coap_packet_t *packet)
{
  /* initialize packet */
  memset(packet, 0, sizeof(coap_packet_t));
  /* pointer to packet bytes */
  packet->buffer = msg->data;
  uint8_t *current_option = NULL;

#ifdef OC_TCP
  if (msg->endpoint.flags & TCP) {
    packet->transport_type = COAP_TRANSPORT_TCP;
    /* parse header fields */
    size_t message_length = 0;
    uint8_t num_extended_length_bytes = 0;
    coap_tcp_parse_message_length(msg->data, &message_length,
                                  &num_extended_length_bytes);

    packet->type = COAP_TYPE_NON;
    packet->mid = 0;
    packet->code = packet->buffer[1 + num_extended_length_bytes];

    current_option =
      msg->data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;

  } else
#endif /* OC_TCP */
  {
    packet->transport_type = COAP_TRANSPORT_UDP;
    /* parse header fields */
    packet->version = (COAP_HEADER_VERSION_MASK & packet->buffer[0]) >>
                      COAP_HEADER_VERSION_POSITION;
    if (packet->version != 1) {
      COAP_WRN("CoAP version must be 1");
      return BAD_REQUEST_4_00;
    }
    packet->type =
      (COAP_HEADER_TYPE_MASK & packet->buffer[0]) >> COAP_HEADER_TYPE_POSITION;
    packet->mid = (uint16_t)(packet->buffer[2] << 8 | packet->buffer[3]);
    packet->code = packet->buffer[1];

    current_option = msg->data + COAP_HEADER_LEN;
  }

  /* Token */
  packet->token_len = (COAP_HEADER_TOKEN_LEN_MASK & packet->buffer[0]) >>
                      COAP_HEADER_TOKEN_LEN_POSITION;

  if (packet->token_len > COAP_TOKEN_LEN) {
    COAP_DBG("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  COAP_DBG("Outer CoAP code: %d", packet->code);

  memcpy(packet->token, current_option, packet->token_len);
  COAP_DBG("Token (len %u)", packet->token_len);
  COAP_LOGbytes(packet->token, packet->token_len);

  current_option += packet->token_len;

  /* Parse outer options */
  coap_status_t ret = coap_oscore_parse_options(
    packet, msg->data, msg->length, current_option, false, true, true, false);
  if (COAP_NO_ERROR != ret) {
    COAP_DBG("coap_oscore_parse_options failed! %d", ret);
    return ret;
  }

  return COAP_NO_ERROR;
}
#else  /* OC_OSCORE */
typedef int dummy_declaration;
#endif /* !OC_OSCORE */
#else  /* OC_SECURITY */
typedef int dummy_declaration;
#endif /* !OC_SECURITY */
