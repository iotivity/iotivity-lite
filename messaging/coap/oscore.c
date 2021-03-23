/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifdef OC_SECURITY
#ifdef OC_OSCORE

#include "oscore.h"
#include "coap.h"
#include "oc_ri.h"
#include "coap_signal.h"

void
oscore_send_error(void *packet, uint8_t code, oc_endpoint_t *endpoint)
{
  if (endpoint->flags & MULTICAST) {
    return;
  }

  coap_packet_t const *oscore_pkt = (coap_packet_t *)packet;

  uint16_t mid = oscore_pkt->mid;
  coap_message_type_t type = COAP_TYPE_NON;
  if (oscore_pkt->type == COAP_TYPE_CON) {
    type = COAP_TYPE_ACK;
  } else {
    mid = coap_get_mid();
  }

  coap_packet_t msg[1];
  coap_udp_init_message(msg, type, code, mid);
  msg->transport_type = oscore_pkt->transport_type;
  oc_message_t *message = oc_internal_allocate_outgoing_message();
  if (message) {
    memcpy(&message->endpoint, endpoint, sizeof(*endpoint));
    memset(&message->endpoint.di, 0, sizeof(oc_uuid_t));
    if (oscore_pkt->token_len > 0) {
      coap_set_token(msg, oscore_pkt->token, oscore_pkt->token_len);
    }
    coap_set_header_max_age(msg, 0);
    size_t len = coap_serialize_message(msg, message->data);
    if (len > 0) {
      message->length = len;
      coap_send_message(message);

      OC_DBG("*** send OSCORE error (%u) ***", code);
    }
  }
}

int
oscore_read_piv(uint8_t *piv, uint8_t piv_len, uint64_t *ssn)
{
  *ssn = 0;

  uint8_t i, j = sizeof(uint64_t) - piv_len;
  for (i = 0; i < piv_len; i++, j++) {
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
  char *p = (char *)&ssn + 8 - OSCORE_PIV_LEN;
  char *end = p + OSCORE_PIV_LEN;
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
oscore_get_outer_code(void *packet)
{
  coap_packet_t const *coap_pkt = (coap_packet_t *)packet;

  bool observe = false;
  if (IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)) {
    observe = true;
  }

  if ((coap_pkt->code >= OC_GET && coap_pkt->code <= OC_DELETE)
#ifdef OC_TCP
      || (coap_pkt->code == PING_7_02 || coap_pkt->code == ABORT_7_05 ||
          coap_pkt->code == CSM_7_01)
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
coap_get_header_oscore(void *packet, uint8_t **piv, uint8_t *piv_len,
                       uint8_t **kid, uint8_t *kid_len, uint8_t **kid_ctx,
                       uint8_t *kid_ctx_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_OSCORE)) {
    return 0;
  }

  /* Partial IV */
  if (piv) {
    *piv = coap_pkt->piv;
    *piv_len = coap_pkt->piv_len;
  }

  /* kid */
  if (kid) {
    *kid = coap_pkt->kid;
    *kid_len = coap_pkt->kid_len;
  }

  /* kid context */
  if (kid_ctx) {
    *kid_ctx = coap_pkt->kid_ctx;
    *kid_ctx_len = coap_pkt->kid_ctx_len;
  }

  return 1;
}

int
coap_set_header_oscore(void *packet, uint8_t *piv, uint8_t piv_len,
                       uint8_t *kid, uint8_t kid_len, uint8_t *kid_ctx,
                       uint8_t kid_ctx_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->oscore_flags = piv_len;

  /* Partial IV */
  if (piv_len > 0) {
    memcpy(coap_pkt->piv, piv, piv_len);
    coap_pkt->piv_len = piv_len;
  }

  /* kid */
  if (coap_pkt->code <= OC_FETCH) {
    coap_pkt->oscore_flags |= 1 << OSCORE_FLAGS_BIT_KID_POSITION;
  }
  if (kid_len > 0) {
    memcpy(coap_pkt->kid, kid, kid_len);
    coap_pkt->kid_len = kid_len;
  }

  /* kid context */
  if (kid_ctx_len > 0) {
    memcpy(coap_pkt->kid_ctx, kid_ctx, kid_ctx_len);
    coap_pkt->kid_ctx_len = kid_ctx_len;
    coap_pkt->oscore_flags |= 1 << OSCORE_FLAGS_BIT_KID_CTX_POSITION;
  }

  SET_OPTION(coap_pkt, COAP_OPTION_OSCORE);

  return 1;
}

int
coap_parse_oscore_option(void *packet, uint8_t *current_option,
                         size_t option_length)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

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

  OC_DBG("OSCORE option");
  if (option_length == 0) {
    OC_DBG("\t---empty value");
    return 0;
  }
  /* Flags  |0 0 0|h|k|  n  | */
  coap_pkt->oscore_flags = *current_option;
  current_option++;
  option_length--;
  OC_DBG("\tflags: %02x", coap_pkt->oscore_flags);

  /* Partial IV length (n bytes) */
  coap_pkt->piv_len = (coap_pkt->oscore_flags & OSCORE_FLAGS_PIVLEN_BITMASK);

  if (coap_pkt->piv_len > 0) {
    /* Partial IV */
    memcpy(coap_pkt->piv, current_option, coap_pkt->piv_len);
    current_option += coap_pkt->piv_len;
    option_length -= coap_pkt->piv_len;

    OC_DBG("\tPartial IV:");
    OC_LOGbytes(coap_pkt->piv, coap_pkt->piv_len);
  }

  /* kid context (if any) */
  /* Check if 'h' flag bit is set */
  if (coap_pkt->oscore_flags & OSCORE_FLAGS_KIDCTX_BITMASK) {
    coap_pkt->kid_ctx_len = *current_option;
    current_option++;
    option_length--;

    /* Store kid context */
    memcpy(coap_pkt->kid_ctx, current_option, coap_pkt->kid_ctx_len);
    current_option += coap_pkt->kid_ctx_len;
    option_length -= coap_pkt->kid_ctx_len;

    OC_DBG("\tkid context:");
    OC_LOGbytes(coap_pkt->kid_ctx, coap_pkt->kid_ctx_len);
  }

  /* kid (if any) */
  /* Check if 'k' flag bit is set */
  if (coap_pkt->oscore_flags & OSCORE_FLAGS_KID_BITMASK) {
    /* Remaining bytes in option: kid */
    coap_pkt->kid_len = option_length;
    memcpy(coap_pkt->kid, current_option, option_length);

    OC_DBG("\tkid:");
    OC_LOGbytes(coap_pkt->kid, coap_pkt->kid_len);
  }

  return 0;
}

size_t
coap_serialize_oscore_option(unsigned int *current_number, void *packet,
                             uint8_t *buffer)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  /* Calculate OSCORE option value length */
  size_t option_length =
    coap_pkt->piv_len + coap_pkt->kid_len + coap_pkt->kid_ctx_len;
  if (coap_pkt->kid_ctx_len > 0) {
    ++option_length;
  }
  if (coap_pkt->oscore_flags > 0) {
    ++option_length;
  }

  /* Serialize OSCORE option header */
  size_t header_length = coap_set_option_header(
    COAP_OPTION_OSCORE - *current_number, option_length, buffer);

  if (buffer) {
    buffer += header_length;

    OC_DBG("OSCORE option");
    OC_DBG("\tflags: %02x", coap_pkt->oscore_flags);
    if (coap_pkt->oscore_flags != 0) {
      /* Serialize OSCORE option flags */
      *buffer = coap_pkt->oscore_flags;
      ++buffer;

      /* Serialize Partial IV */
      if (coap_pkt->piv_len > 0) {
        memcpy(buffer, coap_pkt->piv, coap_pkt->piv_len);
        buffer += coap_pkt->piv_len;

        OC_DBG("\tPartial IV:");
        OC_LOGbytes(coap_pkt->piv, coap_pkt->piv_len);
      }

      /* Serialize kid context */
      if (coap_pkt->kid_ctx_len > 0) {
        /* kid context length */
        *buffer = (uint8_t)coap_pkt->kid_ctx_len;
        ++buffer;

        memcpy(buffer, coap_pkt->kid_ctx, coap_pkt->kid_ctx_len);
        buffer += coap_pkt->kid_ctx_len;

        OC_DBG("\tkid context:");
        OC_LOGbytes(coap_pkt->kid_ctx, coap_pkt->kid_ctx_len);
      }

      /* Remaining bytes, if any, represent the kid */
      if (coap_pkt->kid_len > 0) {
        memcpy(buffer, coap_pkt->kid, coap_pkt->kid_len);
        buffer += coap_pkt->kid_len;

        OC_DBG("\tkid:");
        OC_LOGbytes(coap_pkt->kid, coap_pkt->kid_len);
      }
    }
  }

  *current_number = COAP_OPTION_OSCORE;

  return option_length + header_length;
}

size_t
oscore_serialize_plaintext(void *packet, uint8_t *buffer)
{
  return coap_oscore_serialize_message(packet, buffer, true, false, true);
}

size_t
oscore_serialize_message(void *packet, uint8_t *buffer)
{
  return coap_oscore_serialize_message(packet, buffer, false, true, true);
}

coap_status_t
oscore_parse_inner_message(uint8_t *data, size_t data_len, void *packet)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  /* initialize packet */
  memset(coap_pkt, 0, sizeof(coap_packet_t));
  /* pointer to packet bytes */
  coap_pkt->buffer = data;

  /* Code */
  coap_pkt->code = data[0];
  OC_DBG("Inner CoAP code: %d", coap_pkt->code);

  uint8_t *current_option = &data[1];

  /* Parse inner options */
  coap_status_t ret = coap_oscore_parse_options(
    packet, data, data_len, current_option, true, false, true);
  if (COAP_NO_ERROR != ret) {
    OC_DBG("coap_oscore_parse_options failed! %d", ret);
    return ret;
  }

  return COAP_NO_ERROR;
}

int
oscore_is_oscore_message(oc_message_t *msg)
{
  uint8_t *current_option = NULL;

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
oscore_parse_outer_message(oc_message_t *msg, void *packet)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  /* initialize packet */
  memset(coap_pkt, 0, sizeof(coap_packet_t));
  /* pointer to packet bytes */
  coap_pkt->buffer = msg->data;
  uint8_t *current_option = NULL;

#ifdef OC_TCP
  if (msg->endpoint.flags & TCP) {
    coap_pkt->transport_type = COAP_TRANSPORT_TCP;
    /* parse header fields */
    size_t message_length = 0;
    uint8_t num_extended_length_bytes = 0;
    coap_tcp_parse_message_length(msg->data, &message_length,
                                  &num_extended_length_bytes);

    coap_pkt->type = COAP_TYPE_NON;
    coap_pkt->mid = 0;
    coap_pkt->code = coap_pkt->buffer[1 + num_extended_length_bytes];

    current_option =
      msg->data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;

  } else
#endif /* OC_TCP */
  {
    coap_pkt->transport_type = COAP_TRANSPORT_UDP;
    /* parse header fields */
    coap_pkt->version = (COAP_HEADER_VERSION_MASK & coap_pkt->buffer[0]) >>
                        COAP_HEADER_VERSION_POSITION;
    if (coap_pkt->version != 1) {
      OC_WRN("CoAP version must be 1");
      return BAD_REQUEST_4_00;
    }
    coap_pkt->type = (COAP_HEADER_TYPE_MASK & coap_pkt->buffer[0]) >>
                     COAP_HEADER_TYPE_POSITION;
    coap_pkt->mid = coap_pkt->buffer[2] << 8 | coap_pkt->buffer[3];
    coap_pkt->code = coap_pkt->buffer[1];

    current_option = msg->data + COAP_HEADER_LEN;
  }

  /* Token */
  coap_pkt->token_len = (COAP_HEADER_TOKEN_LEN_MASK & coap_pkt->buffer[0]) >>
                        COAP_HEADER_TOKEN_LEN_POSITION;

  if (coap_pkt->token_len > COAP_TOKEN_LEN) {
    OC_DBG("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  OC_DBG("Outer CoAP code: %d", coap_pkt->code);

  memcpy(coap_pkt->token, current_option, coap_pkt->token_len);
  OC_DBG("Token (len %u)", coap_pkt->token_len);
  OC_LOGbytes(coap_pkt->token, coap_pkt->token_len);

  current_option += coap_pkt->token_len;

  /* Parse outer options */
  coap_status_t ret = coap_oscore_parse_options(
    packet, msg->data, msg->length, current_option, false, true, true);
  if (COAP_NO_ERROR != ret) {
    OC_DBG("coap_oscore_parse_options failed! %d", ret);
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
