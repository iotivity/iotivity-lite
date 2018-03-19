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

#ifndef OC_BLOCKWISE_H
#define OC_BLOCKWISE_H

#include "messaging/coap/coap.h"
#include "messaging/coap/transactions.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "port/oc_connectivity.h"

typedef enum {
  OC_BLOCKWISE_CLIENT = 0,
  OC_BLOCKWISE_SERVER
} oc_blockwise_role_t;

typedef struct oc_blockwise_state_s
{
  struct oc_blockwise_state_s *next;
  oc_string_t href;
  oc_endpoint_t endpoint;
  oc_method_t method;
  oc_blockwise_role_t role;
  uint32_t payload_size;
  uint32_t next_block_offset;
  uint8_t ref_count;
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_string_t uri_query;
#ifdef OC_CLIENT
  uint16_t mid;
  void *client_cb;
#endif /* OC_CLIENT */
} oc_blockwise_state_t;

typedef struct oc_blockwise_request_state_s
{
  oc_blockwise_state_t base;
} oc_blockwise_request_state_t;

typedef struct oc_blockwise_response_state_s
{
  oc_blockwise_state_t base;
  uint8_t etag[COAP_ETAG_LEN];

#ifdef OC_CLIENT
  int32_t observe_seq;
#endif /* OC_CLIENT */
} oc_blockwise_response_state_t;

oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_mid(uint16_t mid);

oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_mid(uint16_t mid);

oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_client_cb(
  oc_endpoint_t *endpoint, void *client_cb);

oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_client_cb(
  oc_endpoint_t *endpoint, void *client_cb);

oc_blockwise_state_t *oc_blockwise_find_request_buffer(
  const char *href, int href_len, oc_endpoint_t *endpoint, oc_method_t method,
  const char *query, int query_len, oc_blockwise_role_t role);

oc_blockwise_state_t *oc_blockwise_find_response_buffer(
  const char *href, int href_len, oc_endpoint_t *endpoint, oc_method_t method,
  const char *query, int query_len, oc_blockwise_role_t role);

oc_blockwise_state_t *oc_blockwise_alloc_request_buffer(
  const char *href, int href_len, oc_endpoint_t *endpoint, oc_method_t method,
  oc_blockwise_role_t role);

oc_blockwise_state_t *oc_blockwise_alloc_response_buffer(
  const char *href, int href_len, oc_endpoint_t *endpoint, oc_method_t method,
  oc_blockwise_role_t role);

void oc_blockwise_free_request_buffer(oc_blockwise_state_t *buffer);

void oc_blockwise_free_response_buffer(oc_blockwise_state_t *buffer);

const void *oc_blockwise_dispatch_block(oc_blockwise_state_t *buffer,
                                        uint32_t block_offset,
                                        uint16_t requested_block_size,
                                        uint16_t *payload_size);

bool oc_blockwise_handle_block(oc_blockwise_state_t *buffer,
                               uint32_t incoming_block_offset,
                               const uint8_t *incoming_block,
                               uint16_t incoming_block_size);

void oc_blockwise_scrub_buffers();

void oc_blockwise_scrub_buffers_for_client_cb(void *cb);

#endif /* OC_BLOCKWISE_H */
