/*
// Copyright (c) 2016 Intel Corporation
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

#include <stdio.h>
#include <string.h>

#include "coap.h"
#include "transactions.h"

#ifdef OC_TCP
#include "coap_signal.h"
#endif /* OC_TCP */

#ifdef OC_SECURITY
#include "security/oc_tls.h"
#include "security/oc_audit.h"
#endif

/*---------------------------------------------------------------------------*/
/*- Variables ---------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static uint16_t current_mid = 0;

coap_status_t coap_status_code = COAP_NO_ERROR;
/*---------------------------------------------------------------------------*/
/*- Local helper functions --------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static uint16_t
coap_log_2(uint16_t value)
{
  uint16_t result = 0;

  do {
    value = value >> 1;
    result++;
  } while (value);

  return (result - 1);
}
/*---------------------------------------------------------------------------*/
static uint32_t
coap_parse_int_option(uint8_t *bytes, size_t length)
{
  uint32_t var = 0;
  size_t i = 0;

  while (i < length) {
    var <<= 8;
    var |= bytes[i++];
  }
  return var;
}
/*---------------------------------------------------------------------------*/
static uint8_t
coap_option_nibble(size_t value)
{
  if (value < 13) {
    return (uint8_t)value;
  } else if (value <= 0xFF + 13) {
    return 13;
  } else {
    return 14;
  }
}
/*---------------------------------------------------------------------------*/
static size_t
coap_set_option_header(unsigned int delta, size_t length, uint8_t *buffer)
{
  size_t written = 0;

  if (buffer) {
    buffer[0] = coap_option_nibble(delta) << 4 | coap_option_nibble(length);
  }

  if (delta > 268) {
    ++written;
    if (buffer) {
      buffer[written] = ((delta - 269) >> 8) & 0xff;
    }
    ++written;
    if (buffer) {
      buffer[written] = (delta - 269) & 0xff;
    }
  } else if (delta > 12) {
    ++written;
    if (buffer) {
      buffer[written] = (uint8_t)(delta - 13);
    }
  }

  if (length > 268) {
    ++written;
    if (buffer) {
      buffer[written] = ((length - 269) >> 8) & 0xff;
    }
    ++written;
    if (buffer) {
      buffer[written] = (length - 269) & 0xff;
    }
  } else if (length > 12) {
    ++written;
    if (buffer) {
      buffer[written] = (uint8_t)(length - 13);
    }
  }

  if (buffer) {
    OC_DBG("WRITTEN %zu B opt header", 1 + written);
  }

  return ++written;
}
/*---------------------------------------------------------------------------*/
static size_t
coap_serialize_int_option(unsigned int number, unsigned int current_number,
                          uint8_t *buffer, uint32_t value)
{
  size_t i = 0;

  if (0xFF000000 & value) {
    ++i;
  }
  if (0xFFFF0000 & value) {
    ++i;
  }
  if (0xFFFFFF00 & value) {
    ++i;
  }
  if (0xFFFFFFFF & value) {
    ++i;
  }
  if (buffer) {
    OC_DBG("OPTION %u (delta %u, len %zu)", number, number - current_number, i);
  }

  i = coap_set_option_header(number - current_number, i, buffer);

  if (0xFF000000 & value) {
    if (buffer) {
      buffer[i] = (uint8_t)(value >> 24);
    }
    i++;
  }
  if (0xFFFF0000 & value) {
    if (buffer) {
      buffer[i] = (uint8_t)(value >> 16);
    }
    i++;
  }
  if (0xFFFFFF00 & value) {
    if (buffer) {
      buffer[i] = (uint8_t)(value >> 8);
    }
    i++;
  }
  if (0xFFFFFFFF & value) {
    if (buffer) {
      buffer[i] = (uint8_t)(value);
    }
    i++;
  }
  return i;
}
/*---------------------------------------------------------------------------*/
static size_t
coap_serialize_array_option(unsigned int number, unsigned int current_number,
                            uint8_t *buffer, uint8_t *array, size_t length,
                            char split_char)
{
  size_t i = 0;

  if (buffer) {
    OC_DBG("ARRAY type %u, len %zu, full [%.*s]", number, length, (int)length,
           array);
  }

  if (split_char != '\0') {
    size_t j;
    uint8_t *part_start = array;
    uint8_t *part_end = NULL;
    size_t temp_length;

    for (j = 0; j <= length + 1; ++j) {
      if (buffer) {
        OC_DBG("STEP %zu/%zu (%c)", j, length, array[j]);
      }

      if (array[j] == split_char || j == length) {
        part_end = array + j;
        temp_length = part_end - part_start;

        if (buffer) {
          i += coap_set_option_header(number - current_number, temp_length,
                                      &buffer[i]);
          memcpy(&buffer[i], part_start, temp_length);
        } else {
          i +=
            coap_set_option_header(number - current_number, temp_length, NULL);
        }

        i += temp_length;

        if (buffer) {
          OC_DBG("OPTION type %u, delta %u, len %zu, part [%.*s]", number,
                 number - current_number, i, (int)temp_length, part_start);
        }

        ++j; /* skip the splitter */
        current_number = number;
        part_start = array + j;
      }
    } /* for */
  } else {

    if (buffer) {
      i += coap_set_option_header(number - current_number, length, &buffer[i]);
      memcpy(&buffer[i], array, length);
    } else {
      i += coap_set_option_header(number - current_number, length, NULL);
    }

    i += length;

    if (buffer) {
      OC_DBG("OPTION type %u, delta %u, len %zu", number,
             number - current_number, length);
    }
  }

  return i;
}
/*---------------------------------------------------------------------------*/
static void
coap_merge_multi_option(char **dst, size_t *dst_len, uint8_t *option,
                        size_t option_len, char separator)
{
  /* merge multiple options */
  if (*dst_len > 0) {
    /* dst already contains an option: concatenate */
    (*dst)[*dst_len] = separator;
    *dst_len += 1;

    /* memmove handles 2-byte option headers */
    memmove((*dst) + (*dst_len), option, option_len);

    *dst_len += option_len;
  } else {
    /* dst is empty: set to option */
    *dst = (char *)option;
    *dst_len = option_len;
  }
}
/*---------------------------------------------------------------------------*/
#if 0
static int
coap_get_variable(const char *buffer, size_t length, const char *name,
                  const char **output)
{
  const char *start = NULL;
  const char *end = NULL;
  const char *value_end = NULL;
  size_t name_len = 0;

  /*initialize the output buffer first */
  *output = 0;

  name_len = strlen(name);
  end = buffer + length;

  for(start = buffer; start + name_len < end; ++start) {
    if((start == buffer || start[-1] == '&') && start[name_len] == '='
       && strncmp(name, start, name_len) == 0) {

      /* Point start to variable value */
      start += name_len + 1;

      /* Point end to the end of the value */
      value_end = (const char *)memchr(start, '&', end - start);
      if(value_end == NULL) {
        value_end = end;
      }
      *output = start;

      return value_end - start;
    }
  }
  return 0;
}
#endif
/*---------------------------------------------------------------------------*/
#ifdef OC_TCP
size_t
coap_serialize_signal_options(void *packet, uint8_t *option_array)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  uint8_t *option = option_array;
  unsigned int current_number = 0;
  size_t option_length = 0;

  switch (coap_pkt->code) {
  case CSM_7_01:
    COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_MAX_MSG_SIZE, max_msg_size,
                              "Max-Message-Size");
    if (coap_pkt->blockwise_transfer) {
      COAP_SERIALIZE_INT_OPTION(
        COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER,
        blockwise_transfer - coap_pkt->blockwise_transfer, "Bert");
    }
    break;
  case PING_7_02:
  case PONG_7_03:
    if (coap_pkt->custody) {
      COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_CUSTODY,
                                custody - coap_pkt->custody, "Custody");
    }
    break;
  case RELEASE_7_04:
    COAP_SERIALIZE_STRING_OPTION(COAP_SIGNAL_OPTION_ALT_ADDR, alt_addr, '\0',
                                 "Alternative-Address");
    COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_HOLD_OFF, hold_off,
                              "Hold-off");
    break;
  case ABORT_7_05:
    COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_BAD_CSM, bad_csm_opt,
                              "Bad-CSM-Option");
    break;
  default:
    OC_ERR("unknown signal message.[%u]", coap_pkt->code);
    return 0;
  }

  if (option) {
    OC_DBG("-Done serializing at %p----", option);
  }

  return option_length;
}
#endif /* OC_TCP */
/*---------------------------------------------------------------------------*/
/* It just caculates size of option when option_array is NULL */
static size_t
coap_serialize_options(void *packet, uint8_t *option_array)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  uint8_t *option = option_array;
  unsigned int current_number = 0;
  size_t option_length = 0;

  if (option) {
    OC_DBG("Serializing options at %p", option);
  } else {
    OC_DBG("Caculating size of options");
  }

#ifdef OC_TCP
  if (coap_check_signal_message(packet)) {
    return coap_serialize_signal_options(packet, option_array);
  }
#endif /* OC_TCP */

#if 0
  /* The options must be serialized in the order of their number */
  COAP_SERIALIZE_BYTE_OPTION(COAP_OPTION_IF_MATCH, if_match, "If-Match");
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_HOST, uri_host, '\0',
                               "Uri-Host");
#endif
  COAP_SERIALIZE_BYTE_OPTION(COAP_OPTION_ETAG, etag, "ETag");
#if 0
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_IF_NONE_MATCH,
      content_format - coap_pkt-> content_format /* hack to get a zero field */,
      "If-None-Match");
#endif
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_OBSERVE, observe, "Observe");
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_URI_PORT, uri_port, "Uri-Port");
#if 0
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_LOCATION_PATH, location_path,
                               '/', "Location-Path");
#endif
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_PATH, uri_path, '/', "Uri-Path");
  if (option) {
    OC_DBG("Serialize content format: %d", coap_pkt->content_format);
  }
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_CONTENT_FORMAT, content_format,
                            "Content-Format");
#if 0
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_MAX_AGE, max_age, "Max-Age");
#endif
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_QUERY, uri_query, '&',
                               "Uri-Query");
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_ACCEPT, accept, "Accept");
#if 0
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_LOCATION_QUERY, location_query,
                               '&', "Location-Query");
#endif
  COAP_SERIALIZE_BLOCK_OPTION(COAP_OPTION_BLOCK2, block2, "Block2");
  COAP_SERIALIZE_BLOCK_OPTION(COAP_OPTION_BLOCK1, block1, "Block1");
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_SIZE2, size2, "Size2");
#if 0
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_PROXY_URI, proxy_uri, '\0',
                               "Proxy-Uri");
  COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_PROXY_SCHEME, proxy_scheme,
                               '\0', "Proxy-Scheme");
#endif
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_SIZE1, size1, "Size1");

  if (IS_OPTION(coap_pkt, COAP_OPTION_ACCEPT)) {
    if (coap_pkt->accept == APPLICATION_VND_OCF_CBOR) {

      option_length +=
        coap_serialize_int_option(OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER,
                                  current_number, option, OCF_VER_1_0_0);
      if (option) {
        option = option_array + option_length;
      }
    }
#ifdef OC_SPEC_VER_OIC
    else if (coap_pkt->accept == APPLICATION_CBOR) {

      option_length +=
        coap_serialize_int_option(OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER,
                                  current_number, option, OIC_VER_1_1_0);
      if (option) {
        option = option_array + option_length;
      }
    }
#endif /* OC_SPEC_VER_OIC */

    current_number = OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER;
  }
  if (IS_OPTION(coap_pkt, COAP_OPTION_CONTENT_FORMAT)) {
    if (coap_pkt->content_format == APPLICATION_VND_OCF_CBOR) {

      option_length += coap_serialize_int_option(
        OCF_OPTION_CONTENT_FORMAT_VER, current_number, option, OCF_VER_1_0_0);
      if (option) {
        option = option_array + option_length;
      }
    }
#ifdef OC_SPEC_VER_OIC
    else if (coap_pkt->content_format == APPLICATION_CBOR) {

      option_length += coap_serialize_int_option(
        OCF_OPTION_CONTENT_FORMAT_VER, current_number, option, OIC_VER_1_1_0);
      if (option) {
        option = option_array + option_length;
      }
    }
#endif /* OC_SPEC_VER_OIC */
    current_number = OCF_OPTION_CONTENT_FORMAT_VER;
  }

  if (option) {
    OC_DBG("-Done serializing at %p----", option);
  }

  return option_length;
}
/*---------------------------------------------------------------------------*/
#ifdef OC_TCP
coap_status_t
coap_parse_signal_options(void *packet, unsigned int option_number,
                          uint8_t *current_option, size_t option_length)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  switch (coap_pkt->code) {
  case CSM_7_01:
    if (option_number == COAP_SIGNAL_OPTION_MAX_MSG_SIZE) {
      coap_pkt->max_msg_size =
        coap_parse_int_option(current_option, option_length);
      OC_DBG("  Max-Message-Size [%u]", coap_pkt->max_msg_size);
    } else if (option_number == COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER) {
      coap_pkt->blockwise_transfer = 1;
      OC_DBG("  Bert [%u]", coap_pkt->blockwise_transfer);
    }
    break;
  case PING_7_02:
  case PONG_7_03:
    if (option_number == COAP_SIGNAL_OPTION_CUSTODY) {
      coap_pkt->custody = 1;
      OC_DBG("  Custody [%u]", coap_pkt->custody);
    }
    break;
  case RELEASE_7_04:
    if (option_number == COAP_SIGNAL_OPTION_ALT_ADDR) {
      coap_pkt->alt_addr = (char *)current_option;
      coap_pkt->alt_addr_len = option_length;
      OC_DBG("  Alternative-Address [%.*s]", (int)coap_pkt->alt_addr_len,
             coap_pkt->alt_addr);
    } else if (option_number == COAP_SIGNAL_OPTION_HOLD_OFF) {
      coap_pkt->hold_off = coap_parse_int_option(current_option, option_length);
      OC_DBG("  Hold-Off [%u]", coap_pkt->hold_off);
    }
    break;
  case ABORT_7_05:
    if (option_number == COAP_SIGNAL_OPTION_BAD_CSM) {
      coap_pkt->bad_csm_opt =
        (uint16_t)coap_parse_int_option(current_option, option_length);
      OC_DBG("  Bad-CSM-Option [%u]", coap_pkt->bad_csm_opt);
    }
    break;
  default:
    OC_ERR("unknown signal message.[%u]", coap_pkt->code);
    return BAD_REQUEST_4_00;
  }

  return COAP_NO_ERROR;
}
#endif /* OC_TCP */
/*---------------------------------------------------------------------------*/
static coap_status_t
coap_parse_token_option(void *packet, uint8_t *data, uint32_t data_len,
                        uint8_t *current_option)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  memcpy(coap_pkt->token, current_option, coap_pkt->token_len);
  OC_DBG("Token (len %u)", coap_pkt->token_len);
  OC_LOGbytes(coap_pkt->token, coap_pkt->token_len);

  /* parse options */
  memset(coap_pkt->options, 0, sizeof(coap_pkt->options));
  current_option += coap_pkt->token_len;

  unsigned int option_number = 0;
  unsigned int option_delta = 0;
  size_t option_length = 0;

  while (current_option < data + data_len) {
    /* payload marker 0xFF, currently only checking for 0xF* because rest is
     * reserved */
    if ((current_option[0] & 0xF0) == 0xF0) {
      coap_pkt->payload = ++current_option;
      coap_pkt->payload_len = data_len - (uint32_t)(coap_pkt->payload - data);

      if (coap_pkt->transport_type == COAP_TRANSPORT_UDP &&
          coap_pkt->payload_len > (uint32_t)OC_BLOCK_SIZE) {
        coap_pkt->payload_len = (uint32_t)OC_BLOCK_SIZE;
        /* null-terminate payload */
      }
      coap_pkt->payload[coap_pkt->payload_len] = '\0';

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

    if (option_number <= COAP_OPTION_SIZE1) {
      OC_DBG("OPTION %u (delta %u, len %zu):", option_number, option_delta,
             option_length);
      SET_OPTION(coap_pkt, option_number);
    }
    if (current_option + option_length > data + data_len) {
      OC_WRN("Unsupported option");
      return BAD_OPTION_4_02;
    }

#ifdef OC_TCP
    if (coap_check_signal_message(packet)) {
      coap_parse_signal_options(packet, option_number, current_option,
                                option_length);
      current_option += option_length;
      continue;
    }
#endif /* OC_TCP */
    switch (option_number) {
    case COAP_OPTION_CONTENT_FORMAT:
      coap_pkt->content_format =
        (uint16_t)coap_parse_int_option(current_option, option_length);
      OC_DBG("  Content-Format [%u]", coap_pkt->content_format);
      if (coap_pkt->content_format != APPLICATION_VND_OCF_CBOR
#ifdef OC_SPEC_VER_OIC
          && coap_pkt->content_format != APPLICATION_CBOR
#endif /* OC_SPEC_VER_OIC */
          )
        return UNSUPPORTED_MEDIA_TYPE_4_15;
      break;
    case COAP_OPTION_MAX_AGE:
      coap_pkt->max_age = coap_parse_int_option(current_option, option_length);
      OC_DBG("  Max-Age [%lu]", (unsigned long)coap_pkt->max_age);
      break;
    case COAP_OPTION_ETAG:
      coap_pkt->etag_len = (uint8_t)MIN(COAP_ETAG_LEN, option_length);
      memcpy(coap_pkt->etag, current_option, coap_pkt->etag_len);
      OC_DBG("  ETag %u [0x%02X%02X%02X%02X%02X%02X%02X%02X]",
             coap_pkt->etag_len, coap_pkt->etag[0], coap_pkt->etag[1],
             coap_pkt->etag[2], coap_pkt->etag[3], coap_pkt->etag[4],
             coap_pkt->etag[5], coap_pkt->etag[6],
             coap_pkt->etag[7]); /*FIXME always prints 8 bytes */
      break;
    case COAP_OPTION_ACCEPT:
      coap_pkt->accept =
        (uint16_t)coap_parse_int_option(current_option, option_length);
      OC_DBG("  Accept [%u]", coap_pkt->accept);
      if (coap_pkt->accept != APPLICATION_VND_OCF_CBOR
#ifdef OC_SPEC_VER_OIC
          && coap_pkt->accept != APPLICATION_CBOR
#endif /* OC_SPEC_VER_OIC */
          )
        return NOT_ACCEPTABLE_4_06;
      break;
#if 0
    case COAP_OPTION_IF_MATCH:
      /* TODO support multiple ETags */
      coap_pkt->if_match_len = MIN(COAP_ETAG_LEN, option_length);
      memcpy(coap_pkt->if_match, current_option,
             coap_pkt->if_match_len);
      OC_DBG("If-Match %u", coap_pkt->if_match_len);
      OC_LOGbytes(coap_pkt->if_match, coap_pkt->if_match_len);
      break;
    case COAP_OPTION_IF_NONE_MATCH:
      coap_pkt->if_none_match = 1;
      OC_DBG("If-None-Match");
      break;

    case COAP_OPTION_PROXY_URI:
#if COAP_PROXY_OPTION_PROCESSING
      coap_pkt->proxy_uri = (char *)current_option;
      coap_pkt->proxy_uri_len = option_length;
#endif
      OC_DBG("Proxy-Uri NOT IMPLEMENTED [%.*s]", (int)coap_pkt->proxy_uri_len,
             coap_pkt->proxy_uri);
      return PROXYING_NOT_SUPPORTED_5_05;
      break;
    case COAP_OPTION_PROXY_SCHEME:
#if COAP_PROXY_OPTION_PROCESSING
      coap_pkt->proxy_scheme = (char *)current_option;
      coap_pkt->proxy_scheme_len = option_length;
#endif
      OC_DBG("Proxy-Scheme NOT IMPLEMENTED [%.*s]",
             (int)coap_pkt->proxy_scheme_len, coap_pkt->proxy_scheme);
      return PROXYING_NOT_SUPPORTED_5_05;
      break;

    case COAP_OPTION_URI_HOST:
      coap_pkt->uri_host = (char *)current_option;
      coap_pkt->uri_host_len = option_length;
      OC_DBG("Uri-Host [%.*s]", (int)coap_pkt->uri_host_len,
             coap_pkt->uri_host);
      break;
#endif
    case COAP_OPTION_URI_PORT:
      coap_pkt->uri_port =
        (uint16_t)coap_parse_int_option(current_option, option_length);
      OC_DBG("  Uri-Port [%u]", coap_pkt->uri_port);
      break;
    case COAP_OPTION_URI_PATH:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final
       * packet field should be const string -> cast to string */
      coap_merge_multi_option((char **)&(coap_pkt->uri_path),
                              &(coap_pkt->uri_path_len), current_option,
                              option_length, '/');
      OC_DBG("  Uri-Path [%.*s]", (int)coap_pkt->uri_path_len,
             coap_pkt->uri_path);
      break;
    case COAP_OPTION_URI_QUERY:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final
       * packet field should be const string -> cast to string */
      coap_merge_multi_option((char **)&(coap_pkt->uri_query),
                              &(coap_pkt->uri_query_len), current_option,
                              option_length, '&');
      OC_DBG("  Uri-Query [%.*s]", (int)coap_pkt->uri_query_len,
             coap_pkt->uri_query);
      break;
#if 0
    case COAP_OPTION_LOCATION_PATH:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
      coap_merge_multi_option(
          (char **)&(coap_pkt->location_path),
          &(coap_pkt->location_path_len),
          current_option, option_length,
          '/');
      OC_DBG("Location-Path [%.*s]", (int)coap_pkt->location_path_len,
    coap_pkt->location_path);
      break;
    case COAP_OPTION_LOCATION_QUERY:
      /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
      coap_merge_multi_option(
          (char **)&(coap_pkt->location_query),
          &(coap_pkt->location_query_len),
          current_option, option_length,
          '&');
      OC_DBG("Location-Query [%.*s]", (int)coap_pkt->location_query_len,
             coap_pkt->location_query);
      break;
#endif
    case COAP_OPTION_OBSERVE:
      coap_pkt->observe = coap_parse_int_option(current_option, option_length);
      OC_DBG("  Observe [%lu]", (unsigned long)coap_pkt->observe);
      break;
    case COAP_OPTION_BLOCK2:
      coap_pkt->block2_num =
        coap_parse_int_option(current_option, option_length);
      coap_pkt->block2_more = (coap_pkt->block2_num & 0x08) >> 3;
      coap_pkt->block2_size = 16 << (coap_pkt->block2_num & 0x07);
      coap_pkt->block2_offset = (coap_pkt->block2_num & ~0x0000000F)
                                << (coap_pkt->block2_num & 0x07);
      coap_pkt->block2_num >>= 4;
      OC_DBG("  Block2 [%lu%s (%u B/blk)]", (unsigned long)coap_pkt->block2_num,
             coap_pkt->block2_more ? "+" : "", coap_pkt->block2_size);
      break;
    case COAP_OPTION_BLOCK1:
      coap_pkt->block1_num =
        coap_parse_int_option(current_option, option_length);
      coap_pkt->block1_more = (coap_pkt->block1_num & 0x08) >> 3;
      coap_pkt->block1_size = 16 << (coap_pkt->block1_num & 0x07);
      coap_pkt->block1_offset = (coap_pkt->block1_num & ~0x0000000F)
                                << (coap_pkt->block1_num & 0x07);
      coap_pkt->block1_num >>= 4;
      OC_DBG("  Block1 [%lu%s (%u B/blk)]", (unsigned long)coap_pkt->block1_num,
             coap_pkt->block1_more ? "+" : "", coap_pkt->block1_size);
      break;
    case COAP_OPTION_SIZE2:
      coap_pkt->size2 = coap_parse_int_option(current_option, option_length);
      OC_DBG("  Size2 [%lu]", (unsigned long)coap_pkt->size2);
      break;
    case COAP_OPTION_SIZE1:
      coap_pkt->size1 = coap_parse_int_option(current_option, option_length);
      OC_DBG("  Size1 [%lu]", (unsigned long)coap_pkt->size1);
      break;
    case OCF_OPTION_CONTENT_FORMAT_VER:
    case OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER: {
      uint16_t version =
        (uint16_t)coap_parse_int_option(current_option, option_length);
      OC_DBG("  Content-format/accept-Version: [%u]", version);
      if (version < OCF_VER_1_0_0
#ifdef OC_SPEC_VER_OIC
          && version != OIC_VER_1_1_0
#endif /* OC_SPEC_VER_OIC */
          ) {
        OC_WRN("Unsupported version %d %u", option_number, version);
        return UNSUPPORTED_MEDIA_TYPE_4_15;
      }
    } break;
    default:
      OC_DBG("  unknown (%u)", option_number);
      /* check if critical (odd) */
      if (option_number & 1) {
        OC_WRN("Unsupported critical option");
        return BAD_OPTION_4_02;
      }
    }
    current_option += option_length;
  } /* for */
  OC_DBG("-Done parsing-------");

  return COAP_NO_ERROR;
}
/*---------------------------------------------------------------------------*/
#ifdef OC_TCP
static void
coap_tcp_set_header_fields(void *packet, uint8_t *num_extended_length_bytes,
                           uint8_t *len, size_t *extended_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->buffer[0] = 0x00;
  coap_pkt->buffer[0] |=
    COAP_TCP_HEADER_LEN_MASK & (*len) << COAP_TCP_HEADER_LEN_POSITION;
  coap_pkt->buffer[0] |= COAP_HEADER_TOKEN_LEN_MASK &
                         (coap_pkt->token_len)
                           << COAP_HEADER_TOKEN_LEN_POSITION;

  int i = 0;
  for (i = 1; i <= *num_extended_length_bytes; i++) {
    coap_pkt->buffer[i] =
      (uint8_t)((*extended_len) >> (8 * (*num_extended_length_bytes - i)));
  }
  coap_pkt->buffer[1 + *num_extended_length_bytes] = coap_pkt->code;
}
static void
coap_tcp_compute_message_length(void *packet, size_t option_length,
                                uint8_t *num_extended_length_bytes,
                                uint8_t *len, size_t *extended_len)
{

  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  *len = 0;
  *extended_len = 0;

  size_t total_length = option_length;
  if (coap_pkt->payload_len > 0) {
    total_length += COAP_PAYLOAD_MARKER_LEN + coap_pkt->payload_len;
  }

  if (total_length < COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN) {
    OC_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN(%d) ",
           COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN);
    *len = (uint8_t)total_length;
    goto exit;
  }

  *len = COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
  *num_extended_length_bytes = 1;

  if (total_length < COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN) {
    *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
    OC_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN(%d) ",
           COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN);
    goto exit;
  }

  *len += 1;
  *num_extended_length_bytes <<= 1;

  if (total_length < COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN) {
    *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN;
    OC_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN(%d) ",
           COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN);
    goto exit;
  }

  *len += 1;
  *num_extended_length_bytes <<= 1;
  *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN;

exit:
  OC_DBG("-Size of options : %zd Total length of CoAP_TCP message "
         "(Options+Payload) : %zd ",
         option_length, total_length);
  OC_DBG("-COAP_TCP header len field : %u Extended length : %zd ", *len,
         *extended_len);
}
/*---------------------------------------------------------------------------*/
static void
coap_tcp_parse_message_length(const uint8_t *data, size_t *message_length,
                              uint8_t *num_extended_length_bytes)
{
  uint8_t tcp_len =
    (COAP_TCP_HEADER_LEN_MASK & data[0]) >> COAP_TCP_HEADER_LEN_POSITION;

  *message_length = 0;
  if (tcp_len < COAP_TCP_EXTENDED_LENGTH_1) {
    *message_length = tcp_len;
  } else {
    uint8_t i = 1;
    *num_extended_length_bytes = 1 << (tcp_len - COAP_TCP_EXTENDED_LENGTH_1);
    for (i = 1; i <= *num_extended_length_bytes; i++) {
      *message_length |= ((uint32_t)(0x000000FF & data[i])
                          << (8 * (*num_extended_length_bytes - i)));
    }

    if (COAP_TCP_EXTENDED_LENGTH_1 == tcp_len) {
      *message_length += COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
    } else if (COAP_TCP_EXTENDED_LENGTH_2 == tcp_len) {
      *message_length += COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN;
    } else if (COAP_TCP_EXTENDED_LENGTH_3 == tcp_len) {
      *message_length += COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN;
    }
  }

  OC_DBG("message_length : %zd, num_extended_length_bytes : %u",
         *message_length, *num_extended_length_bytes);
}
#endif /* OC_TCP */
/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
void
coap_init_connection(void)
{
  /* initialize transaction ID */
  current_mid = (uint16_t)oc_random_value();
}
/*---------------------------------------------------------------------------*/
uint16_t
coap_get_mid(void)
{
  return ++current_mid;
}
/*---------------------------------------------------------------------------*/
void
coap_udp_init_message(void *packet, coap_message_type_t type, uint8_t code,
                      uint16_t mid)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  /* Important thing */
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  coap_pkt->transport_type = COAP_TRANSPORT_UDP;
  coap_pkt->type = type;
  coap_pkt->code = code;
  coap_pkt->mid = mid;
}
/*---------------------------------------------------------------------------*/
#ifdef OC_TCP
void
coap_tcp_init_message(void *packet, uint8_t code)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  /* Important thing */
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  coap_pkt->transport_type = COAP_TRANSPORT_TCP;
  coap_pkt->type = COAP_TYPE_NON;
  coap_pkt->code = code;
  coap_pkt->mid = 0;
}
#endif /* OC_TCP */
/*---------------------------------------------------------------------------*/
static void
coap_udp_set_header_fields(void *packet)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->buffer[0] = 0x00;
  coap_pkt->buffer[0] |= COAP_HEADER_VERSION_MASK &
                         (coap_pkt->version) << COAP_HEADER_VERSION_POSITION;
  coap_pkt->buffer[0] |=
    COAP_HEADER_TYPE_MASK & (coap_pkt->type) << COAP_HEADER_TYPE_POSITION;
  coap_pkt->buffer[0] |= COAP_HEADER_TOKEN_LEN_MASK &
                         (coap_pkt->token_len)
                           << COAP_HEADER_TOKEN_LEN_POSITION;
  coap_pkt->buffer[1] = coap_pkt->code;
  coap_pkt->buffer[2] = (uint8_t)((coap_pkt->mid) >> 8);
  coap_pkt->buffer[3] = (uint8_t)(coap_pkt->mid);
}
/*---------------------------------------------------------------------------*/
size_t
coap_serialize_message(void *packet, uint8_t *buffer)
{
  if (!packet || !buffer) {
    OC_ERR("packet: %p or buffer: %p is NULL", packet, buffer);
    return 0;
  }

  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  uint8_t *option;
  unsigned int current_number = 0;
  uint8_t token_location = 0;
  size_t option_length = 0, option_length_calculation = 0,
         header_length_calculation = 0;

  /* Initialize */
  coap_pkt->buffer = buffer;
  coap_pkt->version = 1;

  /* coap header option serialize first to know total length about options */
  option_length_calculation = coap_serialize_options(coap_pkt, NULL);
  header_length_calculation += option_length_calculation;

  /* accoridng to spec  COAP_PAYLOAD_MARKER_LEN should be included
     if payload  exists */
  if (coap_pkt->payload_len > 0) {
    header_length_calculation += COAP_PAYLOAD_MARKER_LEN;
  }
  header_length_calculation += coap_pkt->token_len;

#ifdef OC_TCP
  if (coap_pkt->transport_type == COAP_TRANSPORT_TCP) {
    uint8_t num_extended_length_bytes = 0, len = 0;
    size_t extended_len = 0;

    coap_tcp_compute_message_length(coap_pkt, option_length_calculation,
                                    &num_extended_length_bytes, &len,
                                    &extended_len);

    token_location = COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;
    header_length_calculation += token_location;

    /* an error occurred: caller must check for !=0 */
    if (header_length_calculation > COAP_MAX_HEADER_SIZE) {
      OC_ERR("Serialized header length %u exceeds COAP_MAX_HEADER_SIZE %u-TCP",
             (unsigned int)(header_length_calculation), COAP_MAX_HEADER_SIZE);
      goto exit;
    }
    /* set header fields */
    coap_tcp_set_header_fields(coap_pkt, &num_extended_length_bytes, &len,
                               &extended_len);
  } else
#endif /* OC_TCP */
  {
    /* set header fields */
    token_location = COAP_HEADER_LEN;
    header_length_calculation += token_location;

    if (header_length_calculation > COAP_MAX_HEADER_SIZE) {
      OC_ERR("Serialized header length %u exceeds COAP_MAX_HEADER_SIZE %u-UDP",
             (unsigned int)(header_length_calculation), COAP_MAX_HEADER_SIZE);
      goto exit;
    }

    OC_DBG("-Serializing MID %u to %p", coap_pkt->mid, coap_pkt->buffer);
    coap_udp_set_header_fields(coap_pkt);
  }

  /* empty packet, dont need to do more stuff */
  if (!coap_pkt->code) {
    OC_DBG("Done serializing empty message at %p-", coap_pkt->buffer);
    return token_location;
  }
  /* set Token */
  OC_DBG("Token (len %u)", coap_pkt->token_len);
  OC_LOGbytes(coap_pkt->token, coap_pkt->token_len);
  option = coap_pkt->buffer + token_location;
  for (current_number = 0; current_number < coap_pkt->token_len;
       ++current_number) {
    *option = coap_pkt->token[current_number];
    ++option;
  }

  option_length = coap_serialize_options(packet, option);
  option += option_length;

  /* Pack payload */
  if ((option - coap_pkt->buffer) <= COAP_MAX_HEADER_SIZE) {
    /* Payload marker */
    if (coap_pkt->payload_len > 0) {
      *option = 0xFF;
      ++option;
    }
    memmove(option, coap_pkt->payload, coap_pkt->payload_len);
  } else {
    /* an error occurred: caller must check for !=0 */
    OC_WRN("Serialized header length %u exceeds COAP_MAX_HEADER_SIZE %u",
           (unsigned int)(option - coap_pkt->buffer), COAP_MAX_HEADER_SIZE);
    goto exit;
  }

  OC_DBG("-Done %u B (header len %u, payload len %u)-",
         (unsigned int)(coap_pkt->payload_len + option - buffer),
         (unsigned int)(option - buffer), (unsigned int)coap_pkt->payload_len);

  OC_DBG("Dump");
  OC_LOGbytes(coap_pkt->buffer, (coap_pkt->payload_len + option - buffer));

  return (option - buffer) + coap_pkt->payload_len; /* packet length */

exit:
  coap_pkt->buffer = NULL;
  return 0;
}
/*---------------------------------------------------------------------------*/
void
coap_send_message(oc_message_t *message)
{
#ifdef OC_TCP
  if (message->endpoint.flags & TCP &&
      message->endpoint.version == OCF_VER_1_0_0) {
    tcp_csm_state_t state = oc_tcp_get_csm_state(&message->endpoint);
    if (state == CSM_NONE) {
      coap_send_csm_message(&message->endpoint, OC_PDU_SIZE, 0);
    }
  }
#endif /* OC_TCP */

  OC_DBG("-sending OCF message (%u)-", (unsigned int)message->length);

  oc_send_message(message);
}
/*---------------------------------------------------------------------------*/
coap_status_t
coap_udp_parse_message(void *packet, uint8_t *data, uint16_t data_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;
  /* initialize packet */
  memset(coap_pkt, 0, sizeof(coap_packet_t));
  /* pointer to packet bytes */
  coap_pkt->buffer = data;
  coap_pkt->transport_type = COAP_TRANSPORT_UDP;
  /* parse header fields */
  coap_pkt->version = (COAP_HEADER_VERSION_MASK & coap_pkt->buffer[0]) >>
                      COAP_HEADER_VERSION_POSITION;
  coap_pkt->type =
    (COAP_HEADER_TYPE_MASK & coap_pkt->buffer[0]) >> COAP_HEADER_TYPE_POSITION;
  coap_pkt->token_len = (COAP_HEADER_TOKEN_LEN_MASK & coap_pkt->buffer[0]) >>
                        COAP_HEADER_TOKEN_LEN_POSITION;
  coap_pkt->code = coap_pkt->buffer[1];
  coap_pkt->mid = coap_pkt->buffer[2] << 8 | coap_pkt->buffer[3];

  if (coap_pkt->version != 1) {
    OC_WRN("CoAP version must be 1");
    return BAD_REQUEST_4_00;
  }

  if (coap_pkt->token_len > COAP_TOKEN_LEN) {
    OC_WRN("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  uint8_t *current_option = data + COAP_HEADER_LEN;

  coap_status_t ret =
    coap_parse_token_option(packet, data, data_len, current_option);
  if (COAP_NO_ERROR != ret) {
    OC_DBG("coap_parse_token_option failed! %d", ret);
#ifdef OC_SECURITY
    oc_audit_log("COMM-1", "Could not parse token option", 0x40, 2, NULL, 0); // this is optional
#endif
    return ret;
  }

  return COAP_NO_ERROR;
}
/*---------------------------------------------------------------------------*/
#ifdef OC_TCP
size_t
coap_tcp_get_packet_size(const uint8_t *data)
{
  size_t total_length = 0;
  size_t message_length = 0;

  uint8_t num_extended_length_bytes = 0;
  coap_tcp_parse_message_length(data, &message_length,
                                &num_extended_length_bytes);
  uint8_t token_len =
    (COAP_HEADER_TOKEN_LEN_MASK & data[0]) >> COAP_HEADER_TOKEN_LEN_POSITION;

  total_length = COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes +
                 token_len + message_length;

  return total_length;
}
/*---------------------------------------------------------------------------*/
coap_status_t
coap_tcp_parse_message(void *packet, uint8_t *data, uint32_t data_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  /* initialize packet */
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  /* pointer to packet bytes */
  coap_pkt->buffer = data;
  coap_pkt->transport_type = COAP_TRANSPORT_TCP;
  /* parse header fields */
  size_t message_length = 0;
  uint8_t num_extended_length_bytes = 0;
  coap_tcp_parse_message_length(data, &message_length,
                                &num_extended_length_bytes);

  coap_pkt->type = COAP_TYPE_NON;
  coap_pkt->mid = 0;
  coap_pkt->token_len = (COAP_HEADER_TOKEN_LEN_MASK & coap_pkt->buffer[0]) >>
                        COAP_HEADER_TOKEN_LEN_POSITION;
  coap_pkt->code = coap_pkt->buffer[1 + num_extended_length_bytes];

  if (coap_pkt->token_len > COAP_TOKEN_LEN) {
    OC_DBG("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  uint8_t *current_option =
    data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;

  coap_status_t ret =
    coap_parse_token_option(packet, data, data_len, current_option);
  if (COAP_NO_ERROR != ret) {
    OC_DBG("coap_parse_token_option failed!");
    return ret;
  }

  return COAP_NO_ERROR;
}
#endif /* OC_TCP */
/*---------------------------------------------------------------------------*/
#if 0
int
coap_get_query_variable(void *packet, const char *name, const char **output)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if(IS_OPTION(coap_pkt, COAP_OPTION_URI_QUERY)) {
    return coap_get_variable(coap_pkt->uri_query, coap_pkt->uri_query_len,
                             name, output);
  }
  return 0;
}
int
coap_get_post_variable(void *packet, const char *name, const char **output)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if(coap_pkt->payload_len) {
    return coap_get_variable((const char *)coap_pkt->payload,
                             coap_pkt->payload_len, name, output);
  }
  return 0;
}
#endif
/*---------------------------------------------------------------------------*/
int
coap_set_status_code(void *packet, unsigned int code)
{
  if (code <= 0xFF) {
    ((coap_packet_t *)packet)->code = (uint8_t)code;
    return 1;
  } else {
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
int
coap_set_token(void *packet, const uint8_t *token, size_t token_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->token_len = (uint8_t)MIN(COAP_TOKEN_LEN, token_len);
  memcpy(coap_pkt->token, token, coap_pkt->token_len);

  return coap_pkt->token_len;
}
#ifdef OC_CLIENT
int
coap_get_header_content_format(void *packet, unsigned int *format)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_CONTENT_FORMAT)) {
    return 0;
  }
  *format = coap_pkt->content_format;
  return 1;
}
#endif
int
coap_set_header_content_format(void *packet, unsigned int format)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->content_format = (uint16_t)format;
  SET_OPTION(coap_pkt, COAP_OPTION_CONTENT_FORMAT);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_get_header_accept(void *packet, unsigned int *accept)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_ACCEPT)) {
    return 0;
  }
  *accept = coap_pkt->accept;
  return 1;
}
#ifdef OC_CLIENT
int
coap_set_header_accept(void *packet, unsigned int accept)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->accept = (uint16_t)accept;
  SET_OPTION(coap_pkt, COAP_OPTION_ACCEPT);
  return 1;
}
#endif
/*---------------------------------------------------------------------------*/
#if 0
int coap_get_header_max_age(void *packet, uint32_t *age)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  if(!IS_OPTION(coap_pkt, COAP_OPTION_MAX_AGE)) {
    *age = COAP_DEFAULT_MAX_AGE;
  } else {
    *age = coap_pkt->max_age;
  }
  return 1;
}
#endif
int
coap_set_header_max_age(void *packet, uint32_t age)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->max_age = age;
  SET_OPTION(coap_pkt, COAP_OPTION_MAX_AGE);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_get_header_etag(void *packet, const uint8_t **etag)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_ETAG)) {
    return 0;
  }
  *etag = coap_pkt->etag;
  return coap_pkt->etag_len;
}
int
coap_set_header_etag(void *packet, const uint8_t *etag, size_t etag_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->etag_len = (uint8_t)MIN(COAP_ETAG_LEN, etag_len);
  memcpy(coap_pkt->etag, etag, coap_pkt->etag_len);

  SET_OPTION(coap_pkt, COAP_OPTION_ETAG);
  return coap_pkt->etag_len;
}
/*---------------------------------------------------------------------------*/
#if 0
/*FIXME support multiple ETags */
int coap_get_header_if_match(void *packet, const uint8_t **etag)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  if(!IS_OPTION(coap_pkt, COAP_OPTION_IF_MATCH)) {
    return 0;
  }
  *etag = coap_pkt->if_match;
  return coap_pkt->if_match_len;
}
int coap_set_header_if_match(void *packet, const uint8_t *etag, size_t etag_len)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->if_match_len = MIN(COAP_ETAG_LEN, etag_len);
  memcpy(coap_pkt->if_match, etag, coap_pkt->if_match_len);

  SET_OPTION(coap_pkt, COAP_OPTION_IF_MATCH);
  return coap_pkt->if_match_len;
}
/*---------------------------------------------------------------------------*/
int coap_get_header_if_none_match(void *packet)
{
  return IS_OPTION((coap_packet_t *)packet,
                   COAP_OPTION_IF_NONE_MATCH) ? 1 : 0;
}
int coap_set_header_if_none_match(void *packet)
{
  SET_OPTION((coap_packet_t * )packet, COAP_OPTION_IF_NONE_MATCH);
  return 1;
}
/*---------------------------------------------------------------------------*/
int coap_get_header_proxy_uri(void *packet, const char **uri)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  if(!IS_OPTION(coap_pkt, COAP_OPTION_PROXY_URI)) {
    return 0;
  }
  *uri = coap_pkt->proxy_uri;
  return coap_pkt->proxy_uri_len;
}
int coap_set_header_proxy_uri(void *packet, const char *uri)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  /*TODO Provide alternative that sets Proxy-Scheme and Uri-* options and provide er-coap-conf define */

  coap_pkt->proxy_uri = uri;
  coap_pkt->proxy_uri_len = strlen(uri);

  SET_OPTION(coap_pkt, COAP_OPTION_PROXY_URI);
  return coap_pkt->proxy_uri_len;
}
/*---------------------------------------------------------------------------*/
int coap_get_header_uri_host(void *packet, const char **host)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  if(!IS_OPTION(coap_pkt, COAP_OPTION_URI_HOST)) {
    return 0;
  }
  *host = coap_pkt->uri_host;
  return coap_pkt->uri_host_len;
}
int coap_set_header_uri_host(void *packet, const char *host)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->uri_host = host;
  coap_pkt->uri_host_len = strlen(host);

  SET_OPTION(coap_pkt, COAP_OPTION_URI_HOST);
  return coap_pkt->uri_host_len;
}
#endif
/*---------------------------------------------------------------------------*/
size_t
coap_get_header_uri_path(void *packet, const char **path)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_URI_PATH)) {
    return 0;
  }
  *path = coap_pkt->uri_path;
  return coap_pkt->uri_path_len;
}
size_t
coap_set_header_uri_path(void *packet, const char *path, size_t path_len)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  while (path[0] == '/') {
    ++path;
    --path_len;
  }

  coap_pkt->uri_path = path;
  coap_pkt->uri_path_len = path_len;

  SET_OPTION(coap_pkt, COAP_OPTION_URI_PATH);
  return coap_pkt->uri_path_len;
}
/*---------------------------------------------------------------------------*/
size_t
coap_get_header_uri_query(void *packet, const char **query)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_URI_QUERY)) {
    return 0;
  }
  *query = coap_pkt->uri_query;
  return coap_pkt->uri_query_len;
}
#ifdef OC_CLIENT
size_t
coap_set_header_uri_query(void *packet, const char *query)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  while (query[0] == '?')
    ++query;

  coap_pkt->uri_query = query;
  coap_pkt->uri_query_len = strlen(query);

  SET_OPTION(coap_pkt, COAP_OPTION_URI_QUERY);
  return coap_pkt->uri_query_len;
}
#endif
/*---------------------------------------------------------------------------*/
#if 0
int coap_get_header_location_path(void *packet, const char **path)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  if(!IS_OPTION(coap_pkt, COAP_OPTION_LOCATION_PATH)) {
    return 0;
  }
  *path = coap_pkt->location_path;
  return coap_pkt->location_path_len;
}
int coap_set_header_location_path(void *packet, const char *path)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  char *query;

  while(path[0] == '/')
    ++path;

  if((query = strchr(path, '?'))) {
    coap_set_header_location_query(packet, query + 1);
    coap_pkt->location_path_len = query - path;
  } else {
    coap_pkt->location_path_len = strlen(path);
  }
  coap_pkt->location_path = path;

  if(coap_pkt->location_path_len > 0) {
    SET_OPTION(coap_pkt, COAP_OPTION_LOCATION_PATH);
  }
  return coap_pkt->location_path_len;
}
/*---------------------------------------------------------------------------*/
int coap_get_header_location_query(void *packet, const char **query)
{
  coap_packet_t * const coap_pkt = (coap_packet_t *)packet;

  if(!IS_OPTION(coap_pkt, COAP_OPTION_LOCATION_QUERY)) {
    return 0;
  }
  *query = coap_pkt->location_query;
  return coap_pkt->location_query_len;
}
#endif
size_t
coap_set_header_location_query(void *packet, const char *query)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  while (query[0] == '?')
    ++query;

  coap_pkt->location_query = query;
  coap_pkt->location_query_len = strlen(query);

  SET_OPTION(coap_pkt, COAP_OPTION_LOCATION_QUERY);
  return coap_pkt->location_query_len;
}
/*---------------------------------------------------------------------------*/
int
coap_get_header_observe(void *packet, uint32_t *observe)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)) {
    return 0;
  }
  *observe = coap_pkt->observe;
  return 1;
}
int
coap_set_header_observe(void *packet, uint32_t observe)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->observe = observe;
  SET_OPTION(coap_pkt, COAP_OPTION_OBSERVE);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_get_header_block2(void *packet, uint32_t *num, uint8_t *more,
                       uint16_t *size, uint32_t *offset)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_BLOCK2)) {
    return 0;
  }
  /* pointers may be NULL to get only specific block parameters */
  if (num != NULL) {
    *num = coap_pkt->block2_num;
  }
  if (more != NULL) {
    *more = coap_pkt->block2_more;
  }
  if (size != NULL) {
    *size = coap_pkt->block2_size;
  }
  if (offset != NULL) {
    *offset = coap_pkt->block2_offset;
  }
  return 1;
}
int
coap_set_header_block2(void *packet, uint32_t num, uint8_t more, uint16_t size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (size < 16) {
    return 0;
  }
  if (size > 2048) {
    return 0;
  }
  if (num > 0x0FFFFF) {
    return 0;
  }
  coap_pkt->block2_num = num;
  coap_pkt->block2_more = more ? 1 : 0;
  coap_pkt->block2_size = size;

  SET_OPTION(coap_pkt, COAP_OPTION_BLOCK2);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_get_header_block1(void *packet, uint32_t *num, uint8_t *more,
                       uint16_t *size, uint32_t *offset)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_BLOCK1)) {
    return 0;
  }
  /* pointers may be NULL to get only specific block parameters */
  if (num != NULL) {
    *num = coap_pkt->block1_num;
  }
  if (more != NULL) {
    *more = coap_pkt->block1_more;
  }
  if (size != NULL) {
    *size = coap_pkt->block1_size;
  }
  if (offset != NULL) {
    *offset = coap_pkt->block1_offset;
  }
  return 1;
}
int
coap_set_header_block1(void *packet, uint32_t num, uint8_t more, uint16_t size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (size < 16) {
    return 0;
  }
  if (size > 2048) {
    return 0;
  }
  if (num > 0x0FFFFF) {
    return 0;
  }
  coap_pkt->block1_num = num;
  coap_pkt->block1_more = more;
  coap_pkt->block1_size = size;

  SET_OPTION(coap_pkt, COAP_OPTION_BLOCK1);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_get_header_size2(void *packet, uint32_t *size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_SIZE2)) {
    return 0;
  }
  *size = coap_pkt->size2;
  return 1;
}
int
coap_set_header_size2(void *packet, uint32_t size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->size2 = size;
  SET_OPTION(coap_pkt, COAP_OPTION_SIZE2);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_get_header_size1(void *packet, uint32_t *size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_SIZE1)) {
    return 0;
  }
  *size = coap_pkt->size1;
  return 1;
}
int
coap_set_header_size1(void *packet, uint32_t size)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->size1 = size;
  SET_OPTION(coap_pkt, COAP_OPTION_SIZE1);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
coap_get_payload(void *packet, const uint8_t **payload)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  if (coap_pkt->payload) {
    *payload = coap_pkt->payload;
    return coap_pkt->payload_len;
  } else {
    *payload = NULL;
    return 0;
  }
}
int
coap_set_payload(void *packet, const void *payload, size_t length)
{
  coap_packet_t *const coap_pkt = (coap_packet_t *)packet;

  coap_pkt->payload = (uint8_t *)payload;
#ifdef OC_TCP
  if (coap_pkt->transport_type == COAP_TRANSPORT_TCP) {
    coap_pkt->payload_len = (uint32_t)length;
  } else
#endif /* OC_TCP */
  {
    coap_pkt->payload_len = (uint16_t)MIN((unsigned)OC_BLOCK_SIZE, length);
  }

  return coap_pkt->payload_len;
}
/*---------------------------------------------------------------------------*/
