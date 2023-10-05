/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *               2016-2020 Intel Corporation
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

#include "coap_log.h"
#include "coap_options.h"
#include "messaging/coap/constants.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <inttypes.h>

bool
coap_options_get_content_format(const coap_packet_t *packet,
                                oc_content_format_t *format)
{
  if (!IS_OPTION(packet, COAP_OPTION_CONTENT_FORMAT)) {
    return false;
  }
  *format = packet->content_format;
  return true;
}

void
coap_options_set_content_format(coap_packet_t *packet,
                                oc_content_format_t format)
{
  assert(format <= UINT16_MAX);
  packet->content_format = (uint16_t)format;
  SET_OPTION(packet, COAP_OPTION_CONTENT_FORMAT);
}

bool
coap_options_get_accept(const coap_packet_t *packet,
                        oc_content_format_t *accept)
{
  if (!IS_OPTION(packet, COAP_OPTION_ACCEPT)) {
    return false;
  }
  *accept = packet->accept;
  return true;
}

void
coap_options_set_accept(coap_packet_t *packet, oc_content_format_t accept)
{
  assert(accept <= UINT16_MAX);
  packet->accept = (uint16_t)accept;
  SET_OPTION(packet, COAP_OPTION_ACCEPT);
}

bool
coap_options_get_max_age(const coap_packet_t *packet, uint32_t *age)
{
  if (!IS_OPTION(packet, COAP_OPTION_MAX_AGE)) {
    *age = COAP_DEFAULT_MAX_AGE;
    return false;
  }
  *age = packet->max_age;
  return true;
}

void
coap_options_set_max_age(coap_packet_t *packet, uint32_t age)
{
  packet->max_age = age;
  SET_OPTION(packet, COAP_OPTION_MAX_AGE);
}

uint8_t
coap_options_get_etag(const coap_packet_t *packet, const uint8_t **etag)
{
  if (!IS_OPTION(packet, COAP_OPTION_ETAG)) {
    return 0;
  }
  *etag = packet->etag;
  return packet->etag_len;
}

/* TODO: support multiple ETags */

int
coap_options_set_etag(coap_packet_t *packet, const uint8_t *etag,
                      uint8_t etag_len)
{
  assert(etag_len > 0);
  packet->etag_len = (uint8_t)MIN(COAP_ETAG_LEN, etag_len);
  memcpy(packet->etag, etag, packet->etag_len);
  SET_OPTION(packet, COAP_OPTION_ETAG);
  return packet->etag_len;
}

size_t
coap_options_get_proxy_uri(const coap_packet_t *packet, const char **uri)
{
  if (!IS_OPTION(packet, COAP_OPTION_PROXY_URI)) {
    return 0;
  }
  *uri = packet->proxy_uri;
  return packet->proxy_uri_len;
}

size_t
coap_options_set_proxy_uri(coap_packet_t *packet, const char *uri,
                           size_t uri_len)
{
  packet->proxy_uri = uri;
  packet->proxy_uri_len = uri_len;
  SET_OPTION(packet, COAP_OPTION_PROXY_URI);
  return packet->proxy_uri_len;
}

size_t
coap_options_get_uri_path(const coap_packet_t *packet, const char **path)
{
  if (!IS_OPTION(packet, COAP_OPTION_URI_PATH)) {
    return 0;
  }
  *path = packet->uri_path;
  return packet->uri_path_len;
}

size_t
coap_options_set_uri_path(coap_packet_t *packet, const char *path,
                          size_t path_len)
{
  while (path[0] == '/' && path_len > 0) {
    ++path;
    --path_len;
  }
  packet->uri_path = path;
  packet->uri_path_len = path_len;
  SET_OPTION(packet, COAP_OPTION_URI_PATH);
  return packet->uri_path_len;
}

size_t
coap_options_get_uri_query(const coap_packet_t *packet, const char **query)
{
  if (!IS_OPTION(packet, COAP_OPTION_URI_QUERY)) {
    return 0;
  }
  *query = packet->uri_query;
  return packet->uri_query_len;
}

#ifdef OC_CLIENT

size_t
coap_options_set_uri_query(coap_packet_t *packet, const char *query,
                           size_t query_len)
{
  while (query[0] == '?' && query_len > 0) {
    ++query;
    --query_len;
  }
  packet->uri_query = query;
  packet->uri_query_len = query_len;
  SET_OPTION(packet, COAP_OPTION_URI_QUERY);
  return packet->uri_query_len;
}

#endif /* OC_CLIENT */

bool
coap_options_get_size1(const coap_packet_t *packet, uint32_t *size)
{
  if (!IS_OPTION(packet, COAP_OPTION_SIZE1)) {
    return false;
  }
  *size = packet->size1;
  return true;
}

void
coap_options_set_size1(coap_packet_t *packet, uint32_t size)
{
  packet->size1 = size;
  SET_OPTION(packet, COAP_OPTION_SIZE1);
}

#if 0

int
coap_options_get_if_match(coap_packet_t *packet, const uint8_t **etag)
{
  if (!IS_OPTION(packet, COAP_OPTION_IF_MATCH)) {
    return 0;
  }
  *etag = packet->if_match;
  return packet->if_match_len;
}

int
coap_options_set_if_match(coap_packet_t *packet, const uint8_t *etag,
                         size_t etag_len)
{
  packet->if_match_len = MIN(COAP_ETAG_LEN, etag_len);
  memcpy(packet->if_match, etag, packet->if_match_len);
  SET_OPTION(packet, COAP_OPTION_IF_MATCH);
  return packet->if_match_len;
}

int
coap_options_get_if_none_match(coap_packet_t *packet)
{
  return IS_OPTION(packet, COAP_OPTION_IF_NONE_MATCH) ? 1 : 0;
}

int
coap_options_set_if_none_match(coap_packet_t *packet)
{
  SET_OPTION(packet, COAP_OPTION_IF_NONE_MATCH);
  return 1;
}

int
coap_options_get_uri_host(coap_packet_t *packet, const char **host)
{
  if (!IS_OPTION(packet, COAP_OPTION_URI_HOST)) {
    return 0;
  }
  *host = packet->uri_host;
  return packet->uri_host_len;
}

int
coap_options_set_uri_host(coap_packet_t *packet, const char *host)
{
  packet->uri_host = host;
  packet->uri_host_len = strlen(host);

  SET_OPTION(packet, COAP_OPTION_URI_HOST);
  return packet->uri_host_len;
}

int
coap_options_get_location_path(coap_packet_t *packet, const char **path)
{
  if (!IS_OPTION(packet, COAP_OPTION_LOCATION_PATH)) {
    return 0;
  }
  *path = packet->location_path;
  return packet->location_path_len;
}

int
coap_options_set_header_location_path(coap_packet_t *packet, const char *path)
{
  while (path[0] == '/') {
    ++path;
  }

  char *query;
  if ((query = strchr(path, '?'))) {
    coap_set_header_location_query(packet, query + 1);
    packet->location_path_len = query - path;
  } else {
    packet->location_path_len = strlen(path);
  }
  packet->location_path = path;

  if (packet->location_path_len > 0) {
    SET_OPTION(packet, COAP_OPTION_LOCATION_PATH);
  }
  return packet->location_path_len;
}

int
coap_options_get_location_query(coap_packet_t *packet, const char **query)
{
  if (!IS_OPTION(packet, COAP_OPTION_LOCATION_QUERY)) {
    return 0;
  }
  *query = packet->location_query;
  return packet->location_query_len;
}

size_t
coap_options_set_location_query(coap_packet_t *packet, const char *query)
{
  while (query[0] == '?')
    ++query;

  packet->location_query = query;
  packet->location_query_len = strlen(query);

  SET_OPTION(packet, COAP_OPTION_LOCATION_QUERY);
  return packet->location_query_len;
}

#endif

bool
coap_options_get_size2(const coap_packet_t *packet, uint32_t *size)
{
  if (!IS_OPTION(packet, COAP_OPTION_SIZE2)) {
    return false;
  }
  *size = packet->size2;
  return true;
}

void
coap_options_set_size2(coap_packet_t *packet, uint32_t size)
{
  packet->size2 = size;
  SET_OPTION(packet, COAP_OPTION_SIZE2);
}

bool
coap_options_get_block1(const coap_packet_t *packet, uint32_t *num,
                        uint8_t *more, uint16_t *size, uint32_t *offset)
{
  if (!IS_OPTION(packet, COAP_OPTION_BLOCK1)) {
    return false;
  }
  /* pointers may be NULL to get only specific block parameters */
  if (num != NULL) {
    *num = packet->block1_num;
  }
  if (more != NULL) {
    *more = packet->block1_more;
  }
  if (size != NULL) {
    *size = packet->block1_size;
  }
  if (offset != NULL) {
    *offset = packet->block1_offset;
  }
  return true;
}

bool
coap_options_set_block1(coap_packet_t *packet, uint32_t num, uint8_t more,
                        uint16_t size, uint32_t offset)
{
  if (num > 0x0FFFFF) {
    COAP_ERR("Block1 number(%" PRIu32 ") too large", num);
    return false;
  }
  if (size < 16 || size > 2048) {
    COAP_ERR("Block1 size(%" PRIu16 ") not supported", size);
    return false;
  }
  packet->block1_num = num;
  packet->block1_more = more;
  packet->block1_size = size;
  packet->block1_offset = offset;
  SET_OPTION(packet, COAP_OPTION_BLOCK1);
  return true;
}

bool
coap_options_get_block2(const coap_packet_t *packet, uint32_t *num,
                        uint8_t *more, uint16_t *size, uint32_t *offset)
{
  if (!IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
    return false;
  }
  /* pointers may be NULL to get only specific block parameters */
  if (num != NULL) {
    *num = packet->block2_num;
  }
  if (more != NULL) {
    *more = packet->block2_more;
  }
  if (size != NULL) {
    *size = packet->block2_size;
  }
  if (offset != NULL) {
    *offset = packet->block2_offset;
  }
  return true;
}

bool
coap_options_set_block2(coap_packet_t *packet, uint32_t num, uint8_t more,
                        uint16_t size, uint32_t offset)
{
  if (num > 0x0FFFFF) {
    COAP_ERR("Block2 number(%" PRIu32 ") too large", num);
    return false;
  }
  if (size < 16 || size > 2048) {
    COAP_ERR("Block2 size(%" PRIu16 ") not supported", size);
    return false;
  }
  packet->block2_num = num;
  packet->block2_more = more ? 1 : 0;
  packet->block2_size = size;
  packet->block2_offset = offset;
  SET_OPTION(packet, COAP_OPTION_BLOCK2);
  return true;
}

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

uint32_t
coap_options_block_encode(uint32_t num, uint8_t more, uint16_t size)
{
  uint32_t block = num << 4;
  if (more != 0) {
    block |= 0x8;
  }
  block |= 0xF & coap_log_2(size / 16);
  return block;
}

static void
coap_options_block_decode(uint32_t value, uint32_t *num, uint8_t *more,
                          uint16_t *size, uint32_t *offset)
{
  *num = (value >> 4) & 0xFFFFF;
  *more = (value & 0x08) >> 3;
  *size = (uint16_t)(16 << (value & 0x07));
  *offset = (value & ~0x0000000F) << (value & 0x07);
}

void
coap_options_block1_decode(coap_packet_t *packet, uint32_t value)
{
  coap_options_block_decode(value, &packet->block1_num, &packet->block1_more,
                            &packet->block1_size, &packet->block1_offset);
  SET_OPTION(packet, COAP_OPTION_BLOCK1);
}

void
coap_options_block2_decode(coap_packet_t *packet, uint32_t value)
{
  coap_options_block_decode(value, &packet->block2_num, &packet->block2_more,
                            &packet->block2_size, &packet->block2_offset);
  SET_OPTION(packet, COAP_OPTION_BLOCK2);
}

bool
coap_options_get_observe(const coap_packet_t *packet, int32_t *observe)
{
  if (!IS_OPTION(packet, COAP_OPTION_OBSERVE)) {
    return false;
  }
  *observe = packet->observe;
  return true;
}

void
coap_options_set_observe(coap_packet_t *packet, int32_t observe)
{
  packet->observe = observe;
  SET_OPTION(packet, COAP_OPTION_OBSERVE);
}
