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

#ifndef COAP_OPTIONS_H
#define COAP_OPTIONS_H

#include "messaging/coap/coap.h"
#include "oc_config.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*  CoAP options (RFC7252):
    +-----+---+---+---+---+----------------+--------+--------+----------+
    | No. | C | U | N | R | Name           | Format | Length | Default  |
    +-----+---+---+---+---+----------------+--------+--------+----------+
    |   1 | x |   |   | x | If-Match       | opaque | 0-8    | (none)   |
    |   3 | x | x | - |   | Uri-Host       | string | 1-255  | (see     |
    |     |   |   |   |   |                |        |        | below)   |
    |   4 |   |   |   | x | ETag           | opaque | 1-8    | (none)   |
    |   5 | x |   |   |   | If-None-Match  | empty  | 0      | (none)   |
    |   7 | x | x | - |   | Uri-Port       | uint   | 0-2    | (see     |
    |     |   |   |   |   |                |        |        | below)   |
    |   8 |   |   |   | x | Location-Path  | string | 0-255  | (none)   |
    |  11 | x | x | - | x | Uri-Path       | string | 0-255  | (none)   |
    |  12 |   |   |   |   | Content-Format | uint   | 0-2    | (none)   |
    |  14 |   | x | - |   | Max-Age        | uint   | 0-4    | 60       |
    |  15 | x | x | - | x | Uri-Query      | string | 0-255  | (none)   |
    |  17 | x |   |   |   | Accept         | uint   | 0-2    | (none)   |
    |  20 |   |   |   | x | Location-Query | string | 0-255  | (none)   |
    |  35 | x | x | - |   | Proxy-Uri      | string | 1-1034 | (none)   |
    |  39 | x | x | - |   | Proxy-Scheme   | string | 1-255  | (none)   |
    |  60 |   |   | x |   | Size1          | uint   | 0-4    | (none)   |
    +-----+---+---+---+---+----------------+--------+--------+----------+
*/

#define COAP_OPTION_QUERY_MAX_SIZE (255)

/**
 * @brief Get the Content-Format option value.
 *
 * @param packet packet to read (cannot be NULL)
 * @param[out] format output parameter for the Content-Format value (cannot be
 * NULL)
 *
 * @return true if the Content-Format option was found
 * @return false otherwise
 */
bool coap_options_get_content_format(const coap_packet_t *packet,
                                     oc_content_format_t *format) OC_NONNULL();

/**
 * @brief Set the Content-Format option value.
 *
 * The Content-Format Option indicates the representation format of the message
 * payload.
 */
void coap_options_set_content_format(coap_packet_t *packet,
                                     oc_content_format_t format) OC_NONNULL();

/**
 * @brief Get the Accept option value.
 *
 * @param packet packet to read (cannot be NULL)
 * @param[out] accept output parameter for the Accept value (cannot be NULL)
 */
bool coap_options_get_accept(const coap_packet_t *packet,
                             oc_content_format_t *accept) OC_NONNULL();

/**
 * @brief Set the Accept option value.
 *
 * The CoAP Accept option can be used to indicate which Content-Format is
 * acceptable to the client.
 */
void coap_options_set_accept(coap_packet_t *packet, oc_content_format_t accept)
  OC_NONNULL();

/**
 * @brief Get the Max-Age option value.
 *
 * @param packet packet to read (cannot be NULL)
 * @param[out] age output parameter for the Max-Age value (cannot be NULL)
 *
 * @return true if the Max-Age option was found
 * @return false otherwise (\p age is set to COAP_DEFAULT_MAX_AGE)
 */
bool coap_options_get_max_age(const coap_packet_t *packet, uint32_t *age)
  OC_NONNULL();

/**
 * @brief Set the Max-Age option value.
 *
 * The Max-Age Option indicates the maximum time a response may be cached before
 * it is considered not fresh.
 */
void coap_options_set_max_age(coap_packet_t *packet, uint32_t age) OC_NONNULL();

/**
 * @brief Get the ETag option value.
 *
 * @param packet packet to read
 * @param[out] etag pointer to the etag
 *
 * @return length of the ETag value stored in \p etag if option is set
 * @return 0 otherwise
 */
uint8_t coap_options_get_etag(const coap_packet_t *packet, const uint8_t **etag)
  OC_NONNULL();

/**
 * @brief Set the ETag option value.
 *
 * An entity-tag is intended for use as a resource-local identifier for
 * differentiating between representations of the same resource that vary over
 * time.
 *
 * @note If the value is longer than COAP_ETAG_LEN then it will be truncated.
 *
 * @param packet packet to update
 * @param etag ETag value (cannot be NULL)
 * @param etag_len length of the ETag value
 *
 * @return length of the ETag value stored in \p etag
 */
int coap_options_set_etag(coap_packet_t *packet, const uint8_t *etag,
                          uint8_t etag_len) OC_NONNULL();

/**
 * @brief Get the Proxy-Uri option value.
 *
 * @param packet packet to read
 * @param[out] uri pointer to the uri (in-place string might not be
 * 0-terminated)
 *
 * @return length of the Proxy-Uri value stored in \p uri if option is set
 * @return 0 otherwise
 */
size_t coap_options_get_proxy_uri(const coap_packet_t *packet, const char **uri)
  OC_NONNULL();

/**
 * @brief Set the Proxy-Uri option value.
 *
 * The Proxy-Uri Option is used to make a request to a forward proxy.
 */
size_t coap_options_set_proxy_uri(coap_packet_t *packet, const char *uri,
                                  size_t uri_len) OC_NONNULL();

/**
 * @brief Get the Uri-Host option value.
 *
 * @param packet packet to read
 * @param[out] path pointer to the host (in-place string might not be
 * 0-terminated)
 *
 * @return length of the Uri-Host value stored in \p host if option is set
 * @return 0 otherwise
 */
size_t coap_options_get_uri_path(const coap_packet_t *packet, const char **path)
  OC_NONNULL(); /* in-place string might not be 0-terminated. */

/**
 * @brief Set the Uri-Path option value.
 *
 * @note All leading '/' will be skipped.
 *
 * Each Uri-Path Option specifies one segment of the absolute path to the
 * resource.
 */
size_t coap_options_set_uri_path(coap_packet_t *packet, const char *path,
                                 size_t path_len) OC_NONNULL();

/**
 * @brief Get the Uri-Query option value.
 *
 * @param packet packet to read
 * @param[out] query pointer to the query (in-place string might not be
 * 0-terminated)
 *
 * @return length of the Uri-Query value stored in \p query if option is set
 * @return 0 otherwise
 */
size_t coap_options_get_uri_query(const coap_packet_t *packet,
                                  const char **query)
  OC_NONNULL(); /* in-place string might not be 0-terminated. */

#ifdef OC_CLIENT

/**
 * @brief Set the Uri-Query option value.
 *
 * @note All leading '?' will be skipped.
 *
 * Each Uri-Query Option specifies one argument parameterizing the resource.
 */
size_t coap_options_set_uri_query(coap_packet_t *packet, const char *query,
                                  size_t query_len) OC_NONNULL();

#endif /* OC_CLIENT */

/**
 * @brief Get the Size1 option value.
 *
 * @param packet packet to read
 * @param[out] size output parameter for the Size1 value
 *
 * @return true if the Size1 option was found
 * @return false otherwise
 */
bool coap_options_get_size1(const coap_packet_t *packet, uint32_t *size)
  OC_NONNULL();

/**
 * @brief Set the Size1 option value.
 *
 * The Size1 option provides size information about the resource representation
 * in a request.
 */
void coap_options_set_size1(coap_packet_t *packet, uint32_t size) OC_NONNULL();

/*  CoAP blockwise options (RFC7959):

    +-----+---+---+---+---+--------+--------+--------+---------+
    | No. | C | U | N | R | Name   | Format | Length | Default |
    +-----+---+---+---+---+--------+--------+--------+---------+
    |  23 | C | U | - | - | Block2 | uint   |    0-3 | (none)  |
    |     |   |   |   |   |        |        |        |         |
    |  27 | C | U | - | - | Block1 | uint   |    0-3 | (none)  |
    +-----+---+---+---+---+--------+--------+--------+---------+


    +-----+---+---+---+---+-------+--------+--------+---------+
    | No. | C | U | N | R | Name  | Format | Length | Default |
    +-----+---+---+---+---+-------+--------+--------+---------+
    |  60 |   |   | x |   | Size1 | uint   |    0-4 | (none)  |
    |     |   |   |   |   |       |        |        |         |
    |  28 |   |   | x |   | Size2 | uint   |    0-4 | (none)  |
    +-----+---+---+---+---+-------+--------+--------+---------+
*/

/**
 * @brief Get the Size2 option value.
 *
 * @param packet packet to read
 * @param[out] size output parameter for the Size2 value
 *
 * @return true if the Size2 option was found
 * @return false otherwise
 */
bool coap_options_get_size2(const coap_packet_t *packet, uint32_t *size)
  OC_NONNULL();

/** @brief Set the Size2 option value. */
void coap_options_set_size2(coap_packet_t *packet, uint32_t size) OC_NONNULL();

/**
 * @brief Get the Block1 option value.
 *
 * @param packet packet to read
 * @param[out] num output parameter for the block number
 * @param[out] more output parameter for the more flag
 * @param[out] size output parameter for the block size
 * @param[out] offset output parameter for the block offset
 *
 * @return true if the Block1 option was found
 * @return false otherwise
 */
bool coap_options_get_block1(const coap_packet_t *packet, uint32_t *num,
                             uint8_t *more, uint16_t *size, uint32_t *offset)
  OC_NONNULL(1);

/**
 * @brief Set the Block1 option value.
 *
 * @param packet packet to write
 * @param num block number (allowed values <0 .. (2^20-1)>)
 * @param more more flag
 * @param size block size (allowed sizes <16 .. 2048>)
 * @param offset block offset
 *
 * @return true if the values are valid and the option was set
 * @return false otherwise
 */
bool coap_options_set_block1(coap_packet_t *packet, uint32_t num, uint8_t more,
                             uint16_t size, uint32_t offset) OC_NONNULL();

/**
 * @brief Get the Block2 option value.
 *
 * @param packet packet to read
 * @param[out] num output parameter for the block number
 * @param[out] more output parameter for the more flag
 * @param[out] size output parameter for the block size
 * @param[out] offset output parameter for the block offset
 *
 * @return true if the Block2 option was found
 * @return false otherwise
 */
bool coap_options_get_block2(const coap_packet_t *packet, uint32_t *num,
                             uint8_t *more, uint16_t *size, uint32_t *offset)
  OC_NONNULL(1);

/**
 * @brief Set the Block2 option value.
 *
 * @param packet packet to write
 * @param num block number (allowed values <0 .. (2^20-1)>)
 * @param more more flag
 * @param size block size (allowed sizes <16 .. 2048>)
 * @param offset block offset
 *
 * @return true if the values are valid and the option was set
 * @return false otherwise
 */
bool coap_options_set_block2(coap_packet_t *packet, uint32_t num, uint8_t more,
                             uint16_t size, uint32_t offset) OC_NONNULL();

/**
 * @brief Encode Block1 or Block2 option value using 3-byte encoded value as
 * described by RFC7959.
 */
uint32_t coap_options_block_encode(uint32_t num, uint8_t more, uint16_t size)
  OC_NONNULL();

/**
 * @brief Decode Block1 option value using 3-byte encoded value as described by
 * RFC7959.
 *
 * @param packet packet to write
 * @param value 3-byte encoded value for the block1 option
 */
void coap_options_block1_decode(coap_packet_t *packet, uint32_t value)
  OC_NONNULL();

/**
 * @brief Decode Block2 option value using 3-byte encoded value as described by
 * RFC7959.
 *
 * @param packet packet to write
 * @param value 3-byte encoded value for the block2 option
 */
void coap_options_block2_decode(coap_packet_t *packet, uint32_t value)
  OC_NONNULL();

/*  CoAP observe option (RFC7641):
    +-----+---+---+---+---+---------+--------+--------+---------+
    | No. | C | U | N | R | Name    | Format | Length | Default |
    +-----+---+---+---+---+---------+--------+--------+---------+
    |   6 |   | x | - |   | Observe | uint   | 0-3 B  | (none)  |
    +-----+---+---+---+---+---------+--------+--------+---------+
*/

/**
 * @brief Get the Observe option value.
 *
 * @param packet packet to read
 * @param[out] observe output parameter for the Observe value
 *
 * @return true if the Observe option was found
 * @return false otherwise
 */
bool coap_options_get_observe(const coap_packet_t *packet, int32_t *observe)
  OC_NONNULL();

/** @brief Set the Observe option value. */
void coap_options_set_observe(coap_packet_t *packet, int32_t observe)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* COAP_OPTIONS_H */
