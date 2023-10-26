/****************************************************************************
 *
 * Copyright (c) 2016-2020 Intel Corporation
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

#include "coap_internal.h"
#include "coap_internal.h"
#include "log_internal.h"
#include "options_internal.h"
#include "oc_ri.h"
#include "transactions_internal.h"
#include "port/oc_connectivity.h"
#include "util/oc_macros_internal.h"

#ifdef OC_OSCORE
#include "oscore_internal.h"
#endif /* OC_OSCORE */

#ifdef OC_TCP
#include "signal_internal.h"
#endif /* OC_TCP */

#ifdef OC_SECURITY
#include "security/oc_audit_internal.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

/* option format serialization */
#define COAP_SERIALIZE_INT_OPTION(packet, number, field, text)                 \
  do {                                                                         \
    if (IS_OPTION(packet, number)) {                                           \
      option_length += coap_serialize_int_option(number, current_number,       \
                                                 option, (packet)->field);     \
      if (option) {                                                            \
        COAP_DBG(text " [%u]", (unsigned int)(packet)->field);                 \
        option = option_array + option_length;                                 \
      }                                                                        \
      current_number = number;                                                 \
    }                                                                          \
  } while (0)

#define COAP_SERIALIZE_BYTE_OPTION(packet, number, field, text)                \
  do {                                                                         \
    if (IS_OPTION(packet, number)) {                                           \
      option_length += coap_serialize_array_option(                            \
        number, current_number, option, (packet)->field,                       \
        (packet)->field##_len, '\0');                                          \
      if (option) {                                                            \
        COAP_DBG(text " %u [0x%02X%02X%02X%02X%02X%02X%02X%02X]",              \
                 (unsigned int)(packet)->field##_len, (packet)->field[0],      \
                 (packet)->field[1], (packet)->field[2], (packet)->field[3],   \
                 (packet)->field[4], (packet)->field[5], (packet)->field[6],   \
                 (packet)->field[7]); /* FIXME always prints 8 bytes */        \
        option = option_array + option_length;                                 \
      }                                                                        \
      current_number = number;                                                 \
    }                                                                          \
  } while (0)

#define COAP_SERIALIZE_STRING_OPTION(packet, number, field, splitter, text)    \
  do {                                                                         \
    if (IS_OPTION(packet, number)) {                                           \
      option_length += coap_serialize_array_option(                            \
        number, current_number, option, (uint8_t *)(packet)->field,            \
        (packet)->field##_len, splitter);                                      \
      if (option) {                                                            \
        COAP_DBG(text " [%.*s]", (int)(packet)->field##_len, (packet)->field); \
        option = option_array + option_length;                                 \
      }                                                                        \
      current_number = number;                                                 \
    }                                                                          \
  } while (0)

#define COAP_SERIALIZE_BLOCK_OPTION(packet, number, field, text)               \
  do {                                                                         \
    if (IS_OPTION(packet, number)) {                                           \
      uint32_t block = coap_options_block_encode((packet)->field##_num,        \
                                                 (packet)->field##_more,       \
                                                 (packet)->field##_size);      \
      option_length +=                                                         \
        coap_serialize_int_option(number, current_number, option, block);      \
      if (option) {                                                            \
        COAP_DBG(text " [%lu%s (%u B/blk)]",                                   \
                 (unsigned long)(packet)->field##_num,                         \
                 (packet)->field##_more ? "+" : "", (packet)->field##_size);   \
        COAP_DBG(text " encoded: 0x%lX", (unsigned long)block);                \
        option = option_array + option_length;                                 \
      }                                                                        \
      current_number = number;                                                 \
    }                                                                          \
  } while (0)

/*---------------------------------------------------------------------------*/
/*- Variables ---------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static uint16_t g_current_mid = 0;

static coap_status_t g_coap_status_code = COAP_NO_ERROR;

/*---------------------------------------------------------------------------*/
/*- Local helper functions --------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static int64_t
coap_parse_int_option(const uint8_t *bytes, size_t length)
{
  if (length > 4) {
    return -1;
  }
  uint32_t var = 0;
  for (size_t i = 0; i < length; ++i) {
    var <<= 8;
    var |= bytes[i];
  }
  return var;
}

static uint8_t
coap_option_nibble(size_t value)
{
  if (value < 13) {
    return (uint8_t)value;
  }
  if (value <= 0xFF + 13) {
    return 13;
  }
  return 14;
}

size_t
coap_set_option_header(unsigned int delta, size_t length, uint8_t *buffer)
{
  size_t written = 0;

  if (buffer) {
    buffer[0] =
      (uint8_t)(coap_option_nibble(delta) << 4 | coap_option_nibble(length));
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
    COAP_DBG("WRITTEN %zu B opt header", 1 + written);
  }

  return ++written;
}

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
    COAP_DBG("OPTION %u (delta %u, len %zu)", number, number - current_number,
             i);
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

static size_t
coap_serialize_array_option(unsigned int number, unsigned int current_number,
                            uint8_t *buffer, const uint8_t *array,
                            size_t length, unsigned char split_char)
{

  if (buffer) {
    COAP_DBG("ARRAY type %u, len %zu, full [%.*s]", number, length, (int)length,
             array);
  }

  if (split_char == '\0') {
    size_t i = 0;
    if (buffer) {
      i += coap_set_option_header(number - current_number, length, &buffer[i]);
      memcpy(&buffer[i], array, length);
    } else {
      i += coap_set_option_header(number - current_number, length, NULL);
    }

    i += length;

    if (buffer) {
      COAP_DBG("OPTION type %u, delta %u, len %zu", number,
               number - current_number, length);
    }
    return i;
  }

  size_t i = 0;
  const uint8_t *part_start = array;
  const uint8_t *part_end = NULL;
  size_t temp_length;
  for (size_t j = 0; j <= length + 1; ++j) {
    if (buffer) {
      COAP_DBG("STEP %zu/%zu (%c)", j, length, array[j]);
    }

    if (array[j] == split_char || j == length) {
      part_end = array + j;
      temp_length = part_end - part_start;

      if (buffer) {
        i += coap_set_option_header(number - current_number, temp_length,
                                    &buffer[i]);
        memcpy(&buffer[i], part_start, temp_length);
      } else {
        i += coap_set_option_header(number - current_number, temp_length, NULL);
      }

      i += temp_length;

      if (buffer) {
        COAP_DBG("OPTION type %u, delta %u, len %zu, part [%.*s]", number,
                 number - current_number, i, (int)temp_length, part_start);
      }

      ++j; /* skip the splitter */
      if (buffer && j < length) {
        OC_DBG("STEP %zu/%zu (%c)", j, length, array[j]);
      }
      current_number = number;
      part_start = array + j;
    }
  }

  return i;
}

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

#ifdef OC_TCP
static size_t
coap_serialize_signal_options(const coap_packet_t *packet,
                              uint8_t *option_array)
{
  uint8_t *option = option_array;
  unsigned int current_number = 0;
  size_t option_length = 0;

  switch (packet->code) {
  case CSM_7_01:
    COAP_SERIALIZE_INT_OPTION(packet, COAP_SIGNAL_OPTION_MAX_MSG_SIZE,
                              max_msg_size, "Max-Message-Size");
    if (packet->blockwise_transfer) {
      COAP_SERIALIZE_INT_OPTION(packet, COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER,
                                blockwise_transfer - packet->blockwise_transfer,
                                "Bert");
    }
    break;
  case PING_7_02:
  case PONG_7_03:
    if (packet->custody) {
      COAP_SERIALIZE_INT_OPTION(packet, COAP_SIGNAL_OPTION_CUSTODY,
                                custody - packet->custody, "Custody");
    }
    break;
  case RELEASE_7_04:
    COAP_SERIALIZE_STRING_OPTION(packet, COAP_SIGNAL_OPTION_ALT_ADDR, alt_addr,
                                 '\0', "Alternative-Address");
    COAP_SERIALIZE_INT_OPTION(packet, COAP_SIGNAL_OPTION_HOLD_OFF, hold_off,
                              "Hold-off");
    break;
  case ABORT_7_05:
    COAP_SERIALIZE_INT_OPTION(packet, COAP_SIGNAL_OPTION_BAD_CSM, bad_csm_opt,
                              "Bad-CSM-Option");
    break;
  default:
    COAP_ERR("unknown signal message.[%u]", packet->code);
    return 0;
  }

  if (option) {
    COAP_DBG("-Done serializing at %p----", (void *)option);
  }

  return option_length;
}
#endif /* OC_TCP */

static size_t
coap_serialize_accept_option(uint16_t accept, unsigned int current_number,
                             uint8_t *buffer)
{
  if (accept == APPLICATION_VND_OCF_CBOR) {
    return coap_serialize_int_option(OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER,
                                     current_number, buffer, OCF_VER_1_0_0);
  }
#ifdef OC_SPEC_VER_OIC
  if (accept == APPLICATION_CBOR) {
    return coap_serialize_int_option(OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER,
                                     current_number, buffer, OIC_VER_1_1_0);
  }
#endif /* OC_SPEC_VER_OIC */
  return 0;
}

static size_t
coap_serialize_content_format_option(uint16_t content_format,
                                     unsigned int current_number,
                                     uint8_t *buffer)

{
  if (content_format == APPLICATION_VND_OCF_CBOR) {
    return coap_serialize_int_option(OCF_OPTION_CONTENT_FORMAT_VER,
                                     current_number, buffer, OCF_VER_1_0_0);
  }
#ifdef OC_SPEC_VER_OIC
  if (content_format == APPLICATION_CBOR) {
    return coap_serialize_int_option(OCF_OPTION_CONTENT_FORMAT_VER,
                                     current_number, buffer, OIC_VER_1_1_0);
  }
#endif /* OC_SPEC_VER_OIC */
  return 0;
}

/* It just caculates size of option when option_array is NULL */
static size_t
coap_serialize_options(const coap_packet_t *packet, uint8_t *option_array,
                       bool inner, bool outer, bool oscore)
{
  (void)oscore;
  uint8_t *option = option_array;
  unsigned int current_number = 0;
  size_t option_length = 0;

#if OC_DBG_IS_ENABLED
  if (option != NULL) {
    COAP_DBG("Serializing options at %p", (void *)option);
  } else {
    COAP_DBG("Calculating size of options");
  }
#endif /* OC_DBG_IS_ENABLED */

#ifdef OC_TCP
  if (coap_check_signal_message(packet->code)) {
    return coap_serialize_signal_options(packet, option_array);
  }
#endif /* OC_TCP */

#if 0
  /* The options must be serialized in the order of their number */
  COAP_SERIALIZE_BYTE_OPTION(packet, COAP_OPTION_IF_MATCH, if_match, "If-Match");
#endif
  if (outer) {
    COAP_SERIALIZE_STRING_OPTION(packet, COAP_OPTION_URI_HOST, uri_host, '\0',
                                 "Uri-Host");
  }
  if (inner) {
    COAP_SERIALIZE_BYTE_OPTION(packet, COAP_OPTION_ETAG, etag, "ETag");
  }
#if 0
  COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_IF_NONE_MATCH,
      content_format - packet-> content_format /* hack to get a zero field */,
      "If-None-Match");
#endif
  COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_OBSERVE, observe, "Observe");
  if (outer) {
    COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_URI_PORT, uri_port,
                              "Uri-Port");
  }
#if 0
  COAP_SERIALIZE_STRING_OPTION(packet, COAP_OPTION_LOCATION_PATH, location_path,
                               '/', "Location-Path");
#endif
#if defined(OC_OSCORE) && defined(OC_SECURITY)
  if (oscore && outer && IS_OPTION(packet, COAP_OPTION_OSCORE)) {
    option_length +=
      coap_serialize_oscore_option(&current_number, packet, option);
    if (option) {
      option = option_array + option_length;
    }
  }
#endif /* OC_OSCORE && OC_SECURITY */
  if (inner) {
    COAP_SERIALIZE_STRING_OPTION(packet, COAP_OPTION_URI_PATH, uri_path, '/',
                                 "Uri-Path");
    if (option) {
      COAP_DBG("Serialize content format: %d", packet->content_format);
    }
    COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_CONTENT_FORMAT,
                              content_format, "Content-Format");
  }
  if (outer) {
    COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_MAX_AGE, max_age, "Max-Age");
  }
  if (inner) {
    COAP_SERIALIZE_STRING_OPTION(packet, COAP_OPTION_URI_QUERY, uri_query, '&',
                                 "Uri-Query");
    COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_ACCEPT, accept, "Accept");
  }
#if 0
  COAP_SERIALIZE_STRING_OPTION(packet, COAP_OPTION_LOCATION_QUERY, location_query,
                               '&', "Location-Query");
#endif
  if (inner) {
    COAP_SERIALIZE_BLOCK_OPTION(packet, COAP_OPTION_BLOCK2, block2, "Block2");
    COAP_SERIALIZE_BLOCK_OPTION(packet, COAP_OPTION_BLOCK1, block1, "Block1");
    COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_SIZE2, size2, "Size2");
  }
  if (outer) {
    COAP_SERIALIZE_STRING_OPTION(packet, COAP_OPTION_PROXY_URI, proxy_uri, '\0',
                                 "Proxy-Uri");
  }
#if 0
  COAP_SERIALIZE_STRING_OPTION(packet, COAP_OPTION_PROXY_SCHEME, proxy_scheme,
                               '\0', "Proxy-Scheme");
#endif
  if (inner) {
    COAP_SERIALIZE_INT_OPTION(packet, COAP_OPTION_SIZE1, size1, "Size1");

    if (IS_OPTION(packet, COAP_OPTION_ACCEPT)) {
      option_length +=
        coap_serialize_accept_option(packet->accept, current_number, option);
      if (option) {
        option = option_array + option_length;
      }
      current_number = OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER;
    }

    if (IS_OPTION(packet, COAP_OPTION_CONTENT_FORMAT)) {
      option_length += coap_serialize_content_format_option(
        packet->content_format, current_number, option);
      if (option) {
        option = option_array + option_length;
      }
    }
  }

  if (option) {
    COAP_DBG("-Done serializing at %p----", (void *)option);
  }

  return option_length;
}

#ifdef OC_TCP
static coap_status_t
coap_parse_signal_options(coap_packet_t *packet, unsigned int option_number,
                          uint8_t *current_option, size_t option_length,
                          bool inner)
{
  if (!inner) {
    return BAD_OPTION_4_02;
  }
  switch (packet->code) {
  case CSM_7_01:
    if (option_number == COAP_SIGNAL_OPTION_MAX_MSG_SIZE) {
      int64_t max_msg_size =
        coap_parse_int_option(current_option, option_length);
      if (max_msg_size < 0) {
        return BAD_OPTION_4_02;
      }
      packet->max_msg_size = (uint32_t)max_msg_size;
      COAP_DBG("  Max-Message-Size [%" PRIu32 "]", packet->max_msg_size);
      break;
    }
    if (option_number == COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER) {
      packet->blockwise_transfer = 1;
      COAP_DBG("  Bert [%u]", packet->blockwise_transfer);
      break;
    }
    break;
  case PING_7_02:
  case PONG_7_03:
    if (option_number == COAP_SIGNAL_OPTION_CUSTODY) {
      packet->custody = 1;
      COAP_DBG("  Custody [%u]", packet->custody);
    }
    break;
  case RELEASE_7_04:
    if (option_number == COAP_SIGNAL_OPTION_ALT_ADDR) {
      packet->alt_addr = (char *)current_option;
      packet->alt_addr_len = option_length;
      COAP_DBG("  Alternative-Address [%.*s]", (int)packet->alt_addr_len,
               packet->alt_addr);
      break;
    }
    if (option_number == COAP_SIGNAL_OPTION_HOLD_OFF) {
      int64_t hold_off = coap_parse_int_option(current_option, option_length);
      if (hold_off < 0) {
        return BAD_OPTION_4_02;
      }
      packet->hold_off = (uint32_t)hold_off;
      COAP_DBG("  Hold-Off [%" PRIu32 "]", packet->hold_off);
      break;
    }
    break;
  case ABORT_7_05:
    if (option_number == COAP_SIGNAL_OPTION_BAD_CSM) {
      int64_t bad_csm = coap_parse_int_option(current_option, option_length);
      if (bad_csm < 0 || bad_csm > UINT16_MAX) {
        return BAD_OPTION_4_02;
      }
      packet->bad_csm_opt = (uint16_t)bad_csm;
      COAP_DBG("  Bad-CSM-Option [%u]", packet->bad_csm_opt);
    }
    break;
  default:
    COAP_ERR("unknown signal message.[%u]", packet->code);
    return BAD_REQUEST_4_00;
  }
  return COAP_NO_ERROR;
}
#endif /* OC_TCP */

static bool
coap_parse_is_valid_content_format_option(int64_t content_format)
{
  return content_format == APPLICATION_VND_OCF_CBOR
#ifdef OC_SPEC_VER_OIC
         || content_format == APPLICATION_CBOR
#endif /* OC_SPEC_VER_OIC */
#ifdef OC_JSON_ENCODER
         || content_format == APPLICATION_JSON ||
         content_format == APPLICATION_TD_JSON
#endif /* OC_JSON_ENCODER */
    ;
}

static bool
coap_parse_is_valid_accept_option(int64_t accept)
{
  return coap_parse_is_valid_content_format_option(accept)
#ifdef OC_WKCORE
         || accept == APPLICATION_LINK_FORMAT
#endif /* OC_SPEC_VER_OIC */
    ;
}

static coap_status_t
coap_oscore_parse_inner_option(coap_packet_t *packet,
                               unsigned int option_number, uint8_t *option,
                               size_t option_length, bool validate)
{
  switch (option_number) {
  case COAP_OPTION_CONTENT_FORMAT: {
    int64_t content_format = coap_parse_int_option(option, option_length);
    COAP_DBG("  Content-Format [%" PRId64 "]", content_format);
    if (!coap_parse_is_valid_content_format_option(content_format)) {
      return UNSUPPORTED_MEDIA_TYPE_4_15;
    }
    packet->content_format = (uint16_t)content_format;
    return COAP_NO_ERROR;
  }
  case COAP_OPTION_ETAG: {
    packet->etag_len = (uint8_t)MIN(COAP_ETAG_LEN, option_length);
    memcpy(packet->etag, option, packet->etag_len);
#if OC_DBG_IS_ENABLED
    char buf[32];
    size_t buf_size = OC_ARRAY_SIZE(buf);
    oc_conv_byte_array_to_hex_string(packet->etag, packet->etag_len, buf,
                                     &buf_size);
    COAP_DBG("  ETag %u [0x%s]", packet->etag_len, buf);
#endif /* OC_DBG_IS_ENABLED */
    return COAP_NO_ERROR;
  }
  case COAP_OPTION_ACCEPT: {
    int64_t accept = coap_parse_int_option(option, option_length);
    COAP_DBG("  Accept [%" PRId64 "]", accept);
    if (!coap_parse_is_valid_accept_option(accept)) {
      return NOT_ACCEPTABLE_4_06;
    }
    packet->accept = (uint16_t)accept;
    return COAP_NO_ERROR;
  }
  case COAP_OPTION_URI_PATH:
    if (validate) {
      return COAP_NO_ERROR;
    }
    /* coap_merge_multi_option() operates in-place on the IPBUF, but final
     * packet field should be const string -> cast to string */
    coap_merge_multi_option((char **)&(packet->uri_path),
                            &(packet->uri_path_len), option, option_length,
                            '/');
    COAP_DBG("  Uri-Path [%.*s]", (int)packet->uri_path_len, packet->uri_path);
    return COAP_NO_ERROR;
  case COAP_OPTION_URI_QUERY:
    if (validate) {
      return COAP_NO_ERROR;
    }
    /* coap_merge_multi_option() operates in-place on the IPBUF, but final
     * packet field should be const string -> cast to string */
    coap_merge_multi_option((char **)&(packet->uri_query),
                            &(packet->uri_query_len), option, option_length,
                            '&');
    COAP_DBG("  Uri-Query [%.*s]", (int)packet->uri_query_len,
             packet->uri_query);
    return COAP_NO_ERROR;
  case COAP_OPTION_BLOCK2: {
    int64_t block2 = coap_parse_int_option(option, option_length);
    if (block2 < 0) {
      return BAD_OPTION_4_02;
    }
    coap_options_block2_decode(packet, (uint32_t)block2);
    COAP_DBG("  Block2 [%lu%s (%u B/blk)]", (unsigned long)packet->block2_num,
             packet->block2_more ? "+" : "", packet->block2_size);
    return COAP_NO_ERROR;
  }
  case COAP_OPTION_BLOCK1: {
    int64_t block1 = coap_parse_int_option(option, option_length);
    if (block1 < 0) {
      return BAD_OPTION_4_02;
    }
    coap_options_block1_decode(packet, (uint32_t)block1);
    COAP_DBG("  Block1 [%lu%s (%u B/blk)]", (unsigned long)packet->block1_num,
             packet->block1_more ? "+" : "", packet->block1_size);
    return COAP_NO_ERROR;
  }
  case COAP_OPTION_SIZE2: {
    int64_t size2 = coap_parse_int_option(option, option_length);
    if (size2 < 0) {
      return BAD_OPTION_4_02;
    }
    packet->size2 = (uint32_t)size2;
    COAP_DBG("  Size2 [%lu]", (unsigned long)packet->size2);
    return COAP_NO_ERROR;
  }
  case COAP_OPTION_SIZE1: {
    int64_t size1 = coap_parse_int_option(option, option_length);
    if (size1 < 0) {
      return BAD_OPTION_4_02;
    }
    packet->size1 = (uint32_t)size1;
    COAP_DBG("  Size1 [%lu]", (unsigned long)packet->size1);
    return COAP_NO_ERROR;
  }
  case OCF_OPTION_CONTENT_FORMAT_VER:
  case OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER: {
    int64_t version = coap_parse_int_option(option, option_length);
    COAP_DBG("  Content-format/accept-Version: [%" PRId64 "]", version);
    if (version < OCF_VER_1_0_0
#ifdef OC_SPEC_VER_OIC
        && version != OIC_VER_1_1_0
#endif /* OC_SPEC_VER_OIC */
    ) {
      COAP_WRN("Unsupported version %d %" PRId64, option_number, version);
      return UNSUPPORTED_MEDIA_TYPE_4_15;
    }
    return COAP_NO_ERROR;
  }
#if 0
  case COAP_OPTION_IF_MATCH:
    /* TODO support multiple ETags */
    packet->if_match_len = MIN(COAP_ETAG_LEN, option_length);
    memcpy(packet->if_match, option, packet->if_match_len);
    COAP_DBG("If-Match %u", packet->if_match_len);
    COAP_LOGbytes(packet->if_match, packet->if_match_len);
    return COAP_NO_ERROR;
  case COAP_OPTION_IF_NONE_MATCH:
    packet->if_none_match = 1;
    COAP_DBG("If-None-Match");
    return COAP_NO_ERROR;
  case COAP_OPTION_LOCATION_PATH:
    if (validate) {
      return COAP_NO_ERROR;
    }
    /* coap_merge_multi_option() operates in-place on the IPBUF, but final
     * packet field should be const string -> cast to string */
    coap_merge_multi_option((char **)&(packet->location_path),
                            &(packet->location_path_len), option, option_length,
                            '/');
    COAP_DBG("Location-Path [%.*s]", (int)packet->location_path_len,
           packet->location_path);
    return COAP_NO_ERROR;
  case COAP_OPTION_LOCATION_QUERY:
    if (validate) {
      return COAP_NO_ERROR;
    }
    /* coap_merge_multi_option() operates in-place on the IPBUF, but final
     * packet field should be const string -> cast to string */
    coap_merge_multi_option((char **)&(packet->location_query),
                            &(packet->location_query_len), option,
                            option_length, '&');
    COAP_DBG("Location-Query [%.*s]", (int)packet->location_query_len,
           packet->location_query);
    return COAP_NO_ERROR;
#endif
  }

  return BAD_OPTION_4_02;
}

static coap_status_t
coap_oscore_parse_outer_option(coap_packet_t *packet,
                               unsigned int option_number, uint8_t *option,
                               size_t option_length, bool validate)
{
  switch (option_number) {
  case COAP_OPTION_PROXY_URI:
    if (validate) {
      return COAP_NO_ERROR;
    }
    packet->proxy_uri = (char *)option;
    packet->proxy_uri_len = option_length;
    COAP_DBG("Proxy-Uri [%.*s]", (int)packet->proxy_uri_len, packet->proxy_uri);
    return COAP_NO_ERROR;
  case COAP_OPTION_URI_HOST:
    packet->uri_host = (char *)option;
    packet->uri_host_len = option_length;
    COAP_DBG("Uri-Host [%.*s]", (int)packet->uri_host_len, packet->uri_host);
    return COAP_NO_ERROR;
  case COAP_OPTION_URI_PORT: {
    int64_t uri_port = coap_parse_int_option(option, option_length);
    if (uri_port < 0 || uri_port > UINT16_MAX) {
      return BAD_OPTION_4_02;
    }
    packet->uri_port = (uint16_t)uri_port;
    COAP_DBG("  Uri-Port [%u]", packet->uri_port);
    return COAP_NO_ERROR;
  }
#if 0
  case COAP_OPTION_PROXY_SCHEME:
    packet->proxy_scheme = (char *)current_option;
    packet->proxy_scheme_len = option_length;
    COAP_DBG("Proxy-Scheme NOT IMPLEMENTED [%.*s]", (int)packet->proxy_scheme_len,
           packet->proxy_scheme);
    return PROXYING_NOT_SUPPORTED_5_05;
#endif
  }

  return BAD_OPTION_4_02;
}

static coap_status_t
coap_oscore_parse_option(coap_packet_t *packet, uint8_t *current_option,
                         bool inner, bool outer, bool oscore, bool validate,
                         unsigned int option_number, size_t option_length)
{
  (void)oscore;

#ifdef OC_TCP
  if (coap_check_signal_message(packet->code)) {
    return coap_parse_signal_options(packet, option_number, current_option,
                                     option_length, inner);
  }
#endif /* OC_TCP */

  switch (option_number) {
  case COAP_OPTION_CONTENT_FORMAT:
  case COAP_OPTION_ETAG:
  case COAP_OPTION_ACCEPT:
  case COAP_OPTION_URI_PATH:
  case COAP_OPTION_URI_QUERY:
  case COAP_OPTION_BLOCK2:
  case COAP_OPTION_BLOCK1:
  case COAP_OPTION_SIZE2:
  case COAP_OPTION_SIZE1:
  case OCF_OPTION_CONTENT_FORMAT_VER:
  case OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER:
#if 0
  case COAP_OPTION_IF_MATCH:
  case COAP_OPTION_IF_NONE_MATCH:
  case COAP_OPTION_LOCATION_PATH:
  case COAP_OPTION_LOCATION_QUERY:
#endif
  {
    if (!inner) {
      return BAD_OPTION_4_02;
    }
    coap_status_t ret = coap_oscore_parse_inner_option(
      packet, option_number, current_option, option_length, validate);
    if (ret != COAP_NO_ERROR) {
      return ret;
    }
    break;
  }
#if defined(OC_OSCORE) && defined(OC_SECURITY)
  case COAP_OPTION_OSCORE:
    if (!outer || !oscore) {
      return BAD_OPTION_4_02;
    }
    if (coap_parse_oscore_option(packet, current_option, option_length) != 0) {
      return BAD_OPTION_4_02;
    }
    break;
#endif /* OC_OSCORE && OC_SECURITY */
  case COAP_OPTION_PROXY_URI:
  case COAP_OPTION_URI_HOST:
  case COAP_OPTION_URI_PORT:
#if 0
  case COAP_OPTION_PROXY_SCHEME:
#endif
  {
    if (!outer) {
      return BAD_OPTION_4_02;
    }
    coap_status_t ret = coap_oscore_parse_outer_option(
      packet, option_number, current_option, option_length, validate);
    if (ret != COAP_NO_ERROR) {
      return ret;
    }
    break;
  }
  case COAP_OPTION_MAX_AGE: {
    int64_t max_age = coap_parse_int_option(current_option, option_length);
    if (max_age < 0) {
      return BAD_OPTION_4_02;
    }
    packet->max_age = (uint32_t)max_age;
    COAP_DBG("  Max-Age [%lu]", (unsigned long)packet->max_age);
    break;
  }
  case COAP_OPTION_OBSERVE: {
    int64_t observe = coap_parse_int_option(current_option, option_length);
    if (observe < 0) {
      return BAD_OPTION_4_02;
    }
    packet->observe = (int32_t)observe;
    COAP_DBG("  Observe [%lu]", (unsigned long)packet->observe);
    break;
  }
  default:
    COAP_DBG("  unknown (%u)", option_number);
    /* check if critical (odd) */
    if ((option_number & 1) != 0) {
      COAP_WRN("Unsupported critical option");
      return BAD_OPTION_4_02;
    }
  }
  return COAP_NO_ERROR;
}

coap_status_t
coap_oscore_parse_options(coap_packet_t *packet, const uint8_t *data,
                          size_t data_len, uint8_t *current_option, bool inner,
                          bool outer, bool oscore, bool validate)
{
  if (data_len > UINT32_MAX) {
    COAP_WRN("message size(%zu) exceeds limit for coap message(%lu)", data_len,
             (long unsigned)UINT32_MAX);
    return BAD_REQUEST_4_00;
  }

  /* parse options */
  memset(packet->options, 0, sizeof(packet->options));

  unsigned int option_number = 0;
  unsigned int option_delta = 0;
  size_t option_length = 0;
  coap_status_t last_error = COAP_NO_ERROR;

  while (current_option < data + data_len) {
    /* payload marker 0xFF, currently only checking for 0xF* because rest is
     * reserved */
    if ((current_option[0] & 0xF0) == 0xF0) {
      ++current_option;
      packet->payload = current_option;
      packet->payload_len = (uint32_t)(data_len - (packet->payload - data));

      if (packet->transport_type == COAP_TRANSPORT_UDP &&
          packet->payload_len > (uint32_t)OC_MAX_APP_DATA_SIZE) {
        packet->payload_len = (uint32_t)OC_MAX_APP_DATA_SIZE;
        /* null-terminate payload */
      }
      if (!validate) {
        packet->payload[packet->payload_len] =
          '\0'; // TODO: this writes after the payload, if the message was
                // shrank so the allocation matches the message length this
                // causes a memory corruption
        COAP_DBG("Got payload:");
        COAP_LOGbytes(packet->payload, packet->payload_len);
      }
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
      COAP_DBG("OPTION %u (delta %u, len %zu):", option_number, option_delta,
               option_length);
      SET_OPTION(packet, option_number);
    }
    if (current_option + option_length > data + data_len) {
      COAP_WRN("Invalid option - option length exceeds packet length");
      return BAD_REQUEST_4_00;
    }
    coap_status_t s =
      coap_oscore_parse_option(packet, current_option, inner, outer, oscore,
                               validate, option_number, option_length);
    if (s != COAP_NO_ERROR) {
      if (!validate) {
        return s;
      }
      if (s == BAD_REQUEST_4_00) {
        return s;
      }
      if (last_error < s) {
        last_error = s;
      }
    }
    current_option += option_length;
  } /* for */
  COAP_DBG("-Done parsing-------");

  return last_error;
}
/*---------------------------------------------------------------------------*/
#ifdef OC_TCP
static void
coap_tcp_set_header_fields(coap_packet_t *packet,
                           uint8_t num_extended_length_bytes, uint8_t len,
                           size_t extended_len)
{
  packet->buffer[0] = 0x00;
  packet->buffer[0] |=
    COAP_TCP_HEADER_LEN_MASK & len << COAP_TCP_HEADER_LEN_POSITION;
  packet->buffer[0] |= COAP_HEADER_TOKEN_LEN_MASK &
                       (packet->token_len) << COAP_HEADER_TOKEN_LEN_POSITION;

  for (int i = 1; i <= num_extended_length_bytes; i++) {
    packet->buffer[i] =
      (uint8_t)(extended_len >> (8 * (num_extended_length_bytes - i)));
  }
  packet->buffer[1 + num_extended_length_bytes] = packet->code;
}

static void
coap_tcp_compute_message_length(const coap_packet_t *packet,
                                size_t option_length,
                                uint8_t *num_extended_length_bytes,
                                uint8_t *len, size_t *extended_len)
{
  *len = 0;
  *extended_len = 0;

  size_t total_length = option_length;
  if (packet->payload_len > 0) {
    total_length += COAP_PAYLOAD_MARKER_LEN + packet->payload_len;
  }

  if (total_length < COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN) {
    COAP_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN(%d) ",
             COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN);
    *len = (uint8_t)total_length;
    goto exit;
  }

  *len = COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
  *num_extended_length_bytes = 1;

  if (total_length < COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN) {
    *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
    COAP_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN(%d) ",
             COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN);
    goto exit;
  }

  *len += 1;
  *num_extended_length_bytes <<= 1;

  if (total_length < COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN) {
    *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN;
    COAP_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN(%d) ",
             COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN);
    goto exit;
  }

  *len += 1;
  *num_extended_length_bytes <<= 1;
  *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN;

exit:
  COAP_DBG("-Size of options : %zd Total length of CoAP_TCP message "
           "(Options+Payload) : %zd ",
           option_length, total_length);
  COAP_DBG("-COAP_TCP header len field : %u Extended length : %zd ", *len,
           *extended_len);
}
/*---------------------------------------------------------------------------*/
void
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
    *num_extended_length_bytes =
      (uint8_t)(1 << (tcp_len - COAP_TCP_EXTENDED_LENGTH_1));
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

  COAP_DBG("message_length : %zd, num_extended_length_bytes : %u",
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
  g_current_mid = (uint16_t)oc_random_value();
}

uint16_t
coap_get_mid(void)
{
  return ++g_current_mid;
}

void
coap_udp_init_message(coap_packet_t *packet, coap_message_type_t type,
                      uint8_t code, uint16_t mid)
{
  memset(packet, 0, sizeof(coap_packet_t));
  packet->transport_type = COAP_TRANSPORT_UDP;
  packet->type = type;
  packet->code = code;
  packet->mid = mid;
}

#ifdef OC_TCP
void
coap_tcp_init_message(coap_packet_t *packet, uint8_t code)
{
  memset(packet, 0, sizeof(coap_packet_t));
  packet->transport_type = COAP_TRANSPORT_TCP;
  packet->type = COAP_TYPE_NON;
  packet->code = code;
  packet->mid = 0;
}
#endif /* OC_TCP */

static void
coap_udp_set_header_fields(coap_packet_t *packet)
{
  packet->buffer[0] = 0x00;
  packet->buffer[0] |= COAP_HEADER_VERSION_MASK &
                       (packet->version) << COAP_HEADER_VERSION_POSITION;
  packet->buffer[0] |= COAP_HEADER_TYPE_MASK & (packet->type)
                                                 << COAP_HEADER_TYPE_POSITION;
  packet->buffer[0] |= COAP_HEADER_TOKEN_LEN_MASK &
                       (packet->token_len) << COAP_HEADER_TOKEN_LEN_POSITION;
  packet->buffer[1] = packet->code;
  packet->buffer[2] = (uint8_t)((packet->mid) >> 8);
  packet->buffer[3] = (uint8_t)(packet->mid);
}

bool
coap_check_header_size(size_t header_size, size_t buffer_size)
{
  if (header_size > (size_t)COAP_MAX_HEADER_SIZE) {
    COAP_ERR("Serialized header length %zu exceeds COAP_MAX_HEADER_SIZE %zu",
             header_size, (size_t)COAP_MAX_HEADER_SIZE);
    return false;
  }
  if (buffer_size > 0 && header_size > buffer_size) {
    COAP_ERR("Serialized header length %zu exceeds buffer size %zu",
             header_size, buffer_size);
    return false;
  }
  return true;
}

coap_calculate_header_size_result_t
coap_calculate_header_size(const coap_packet_t *packet, bool inner, bool outer,
                           bool oscore, size_t token_len)
{
  coap_calculate_header_size_result_t hdr = { 0 };
  /* coap header option serialize first to know total length about options */
  size_t option_length_calculation =
    coap_serialize_options(packet, NULL, inner, outer, oscore);
  hdr.size = option_length_calculation;

  if (!outer) {
    return hdr;
  }

  hdr.size += token_len;
  hdr.token_location = COAP_HEADER_LEN;

#ifdef OC_TCP
  if (packet->transport_type == COAP_TRANSPORT_TCP) {
    coap_tcp_compute_message_length(packet, option_length_calculation,
                                    &hdr.num_extended_length_bytes, &hdr.length,
                                    &hdr.extended_length);
    hdr.token_location =
      COAP_TCP_DEFAULT_HEADER_LEN + hdr.num_extended_length_bytes;
  }
#endif /* OC_TCP */

  hdr.size += hdr.token_location;
  COAP_DBG("Serialized header length %zu", hdr.size);
  return hdr;
}

size_t
coap_oscore_serialize_message(coap_packet_t *packet, uint8_t *buffer,
                              size_t buffer_size, bool inner, bool outer,
                              bool oscore)
{
  /* Initialize */
  packet->buffer = buffer;
  packet->version = 1;

  coap_calculate_header_size_result_t hdr =
    coap_calculate_header_size(packet, inner, outer, oscore, packet->token_len);
  if (!coap_check_header_size(hdr.size, buffer_size)) {
#ifdef OC_TCP
    COAP_ERR("cannot serialize %s packet",
             packet->transport_type == COAP_TRANSPORT_TCP ? "TCP" : "UDP");
#else  /* !OC_TCP */
    COAP_ERR("cannot serialize UDP packet");
#endif /* OC_TCP */
    return 0;
  }

  uint8_t *option;

  if (outer) {
#ifdef OC_TCP
    if (packet->transport_type == COAP_TRANSPORT_TCP) {
      /* set header fields */
      coap_tcp_set_header_fields(packet, hdr.num_extended_length_bytes,
                                 hdr.length, hdr.extended_length);
    } else
#endif /* OC_TCP */
    {
      COAP_DBG("-Serializing MID %u to %p", packet->mid,
               (void *)packet->buffer);
      coap_udp_set_header_fields(packet);
    }

    /* empty packet, dont need to do more stuff */
    if (!packet->code) {
      COAP_DBG("Done serializing empty message at %p-", (void *)packet->buffer);
      return hdr.token_location;
    }

    if (oscore) {
      COAP_DBG("Outer CoAP code: %d", packet->code);
    }

    /* set Token */
    COAP_DBG("Token (len %u)", packet->token_len);
    COAP_LOGbytes(packet->token, packet->token_len);
    option = packet->buffer + hdr.token_location;
    memcpy(option, packet->token, packet->token_len);
    option += packet->token_len;
  } else {
    COAP_DBG("Inner CoAP code: %d", packet->code);
    ++hdr.size;
    if (!coap_check_header_size(hdr.size, buffer_size)) {
      COAP_ERR("cannot serialize payload: cannot serialize inner packet");
      goto exit;
    }
    packet->buffer[0] = packet->code;
    option = packet->buffer + 1;
  }

  size_t written = coap_serialize_options(packet, option, inner, outer, oscore);
  option += written;
  buffer_size -= hdr.size;

  assert(hdr.size == (size_t)(option - packet->buffer));
  /* Payload marker */
  if (packet->payload_len > 0) {
    if (buffer_size < packet->payload_len + COAP_PAYLOAD_MARKER_LEN) {
      COAP_ERR("cannot serialize payload: no space left for payload(required: "
               "%" PRIu32 ", remaining: %zu)",
               packet->payload_len + COAP_PAYLOAD_MARKER_LEN, buffer_size);
      goto exit;
    }
    /* according to spec COAP_PAYLOAD_MARKER_LEN should be included if payload
     * exists */
    *option = COAP_PAYLOAD_MARKER;
    option += COAP_PAYLOAD_MARKER_LEN;
    memmove(option, packet->payload, packet->payload_len);
  }
  COAP_DBG("Serialized payload:");
  COAP_LOGbytes(option, packet->payload_len);

  COAP_DBG("-Done %zu B (header len %zu, payload len %u)-",
           (size_t)(packet->payload_len + option - buffer),
           (size_t)(option - buffer), (unsigned)packet->payload_len);

  COAP_DBG("Dump");
  COAP_LOGbytes(packet->buffer, (packet->payload_len + option - buffer));

  return (size_t)((option - buffer) + packet->payload_len);

exit:
  packet->buffer = NULL;
  return 0;
}

void
coap_send_message(oc_message_t *message)
{
#ifdef OC_TCP
  if (message->endpoint.flags & TCP &&
      message->endpoint.version == OCF_VER_1_0_0) {
    tcp_csm_state_t state = oc_tcp_get_csm_state(&message->endpoint);
    if (state == CSM_NONE) {
      coap_send_csm_message(&message->endpoint, (uint32_t)OC_PDU_SIZE, 0);
    }
  }
#endif /* OC_TCP */

  COAP_DBG("-sending OCF message (%u)-", (unsigned int)message->length);

  oc_send_message(message);
}

size_t
coap_serialize_message(coap_packet_t *packet, uint8_t *buffer,
                       size_t buffer_size)
{
  return coap_oscore_serialize_message(packet, buffer, buffer_size, true, true,
                                       false);
}

coap_status_t
coap_udp_parse_message(coap_packet_t *packet, uint8_t *data, size_t data_len,
                       bool validate)
{
  if (data_len > UINT16_MAX) {
    COAP_WRN("message size(%zu) exceeds limit for UDP message(%u)", data_len,
             (unsigned)UINT16_MAX);
    return BAD_REQUEST_4_00;
  }
  /* initialize packet */
  memset(packet, 0, sizeof(coap_packet_t));
  /* pointer to packet bytes */
  packet->buffer = data;
  packet->transport_type = COAP_TRANSPORT_UDP;
  /* parse header fields */
  packet->version = (COAP_HEADER_VERSION_MASK & packet->buffer[0]) >>
                    COAP_HEADER_VERSION_POSITION;
  packet->type =
    (COAP_HEADER_TYPE_MASK & packet->buffer[0]) >> COAP_HEADER_TYPE_POSITION;
  packet->token_len = (COAP_HEADER_TOKEN_LEN_MASK & packet->buffer[0]) >>
                      COAP_HEADER_TOKEN_LEN_POSITION;
  packet->code = packet->buffer[1];
  packet->mid = (uint16_t)(packet->buffer[2] << 8 | packet->buffer[3]);

  if (packet->version != 1) {
    COAP_WRN("CoAP version must be 1");
    return BAD_REQUEST_4_00;
  }

  if (packet->token_len > COAP_TOKEN_LEN) {
    COAP_WRN("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  uint8_t *current_option = data + COAP_HEADER_LEN;

  memcpy(packet->token, current_option, packet->token_len);
  COAP_DBG("Token (len %u)", packet->token_len);
  COAP_LOGbytes(packet->token, packet->token_len);

  current_option += packet->token_len;

  coap_status_t ret = coap_oscore_parse_options(
    packet, data, data_len, current_option, true, true, false, validate);
  if (COAP_NO_ERROR != ret) {
    COAP_DBG("coap_oscore_parse_options failed! %d", ret);
    return ret;
  }

  return COAP_NO_ERROR;
}

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

coap_status_t
coap_tcp_parse_message(coap_packet_t *packet, uint8_t *data, size_t data_len,
                       bool validate)
{
  if (data_len > UINT32_MAX) {
    COAP_WRN("message size(%zu) exceeds limit for TCP message(%lu)", data_len,
             (long unsigned)UINT32_MAX);
    return BAD_REQUEST_4_00;
  }

  /* initialize packet */
  memset(packet, 0, sizeof(coap_packet_t));

  /* pointer to packet bytes */
  packet->buffer = data;
  packet->transport_type = COAP_TRANSPORT_TCP;
  /* parse header fields */
  size_t message_length = 0;
  uint8_t num_extended_length_bytes = 0;
  coap_tcp_parse_message_length(data, &message_length,
                                &num_extended_length_bytes);

  packet->type = COAP_TYPE_NON;
  packet->mid = 0;
  packet->token_len = (COAP_HEADER_TOKEN_LEN_MASK & packet->buffer[0]) >>
                      COAP_HEADER_TOKEN_LEN_POSITION;
  packet->code = packet->buffer[1 + num_extended_length_bytes];

  if (packet->token_len > COAP_TOKEN_LEN) {
    COAP_DBG("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  uint8_t *current_option =
    data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;

  memcpy(packet->token, current_option, packet->token_len);
  COAP_DBG("Token (len %u)", packet->token_len);
  COAP_LOGbytes(packet->token, packet->token_len);

  current_option += packet->token_len;

  coap_status_t ret = coap_oscore_parse_options(
    packet, data, data_len, current_option, true, true, false, validate);
  if (COAP_NO_ERROR != ret) {
    COAP_DBG("coap_oscore_parse_options failed!");
    return ret;
  }

  return COAP_NO_ERROR;
}
#endif /* OC_TCP */

#if 0
int
coap_get_query_variable(coap_packet_t *packet, const char *name, const char **output)
{
  if(IS_OPTION(packet, COAP_OPTION_URI_QUERY)) {
    return coap_get_variable(packet->uri_query, packet->uri_query_len,
                             name, output);
  }
  return 0;
}
int
coap_get_post_variable(coap_packet_t *packet, const char *name, const char **output)
{
  if(packet->payload_len) {
    return coap_get_variable((const char *)packet->payload,
                             packet->payload_len, name, output);
  }
  return 0;
}
#endif

int
coap_set_status_code(coap_packet_t *packet, unsigned int code)
{
  if (code <= 0xFF) {
    packet->code = (uint8_t)code;
    return 1;
  }
  return 0;
}

int
coap_set_token(coap_packet_t *packet, const uint8_t *token, size_t token_len)
{
  packet->token_len = (uint8_t)MIN(COAP_TOKEN_LEN, token_len);
  if (packet->token_len > 0) {
    memcpy(packet->token, token, packet->token_len);
  }
  return packet->token_len;
}

uint32_t
coap_get_payload(const coap_packet_t *packet, const uint8_t **payload)
{
  if (packet->payload) {
    *payload = packet->payload;
    return packet->payload_len;
  }
  *payload = NULL;
  return 0;
}

uint32_t
coap_set_payload(coap_packet_t *packet, uint8_t *payload, uint32_t length)
{
  packet->payload = payload;
#ifdef OC_TCP
  if (packet->transport_type == COAP_TRANSPORT_TCP) {
    packet->payload_len = length;
  } else
#endif /* OC_TCP */
  {
    packet->payload_len = MIN((uint32_t)OC_BLOCK_SIZE, length);
  }

  return packet->payload_len;
}

coap_status_t
coap_global_status_code(void)
{
  return g_coap_status_code;
}

void
coap_set_global_status_code(coap_status_t code)
{
  g_coap_status_code = code;
}
