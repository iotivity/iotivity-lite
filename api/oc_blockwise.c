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

#include "port/oc_connectivity.h"
#include <config.h>
#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#include "oc_endpoint.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

OC_MEMB(oc_blockwise_request_states_s, oc_blockwise_request_state_t,
        OC_MAX_NUM_CONCURRENT_REQUESTS);
OC_MEMB(oc_blockwise_response_states_s, oc_blockwise_response_state_t,
        OC_MAX_NUM_CONCURRENT_REQUESTS);
OC_LIST(oc_blockwise_requests);
OC_LIST(oc_blockwise_responses);

static oc_blockwise_state_t *
oc_blockwise_init_buffer(struct oc_memb *pool, const char *href, int href_len,
                         oc_endpoint_t *endpoint, oc_method_t method,
                         oc_blockwise_role_t role)
{
  if (href_len == 0)
    return NULL;

  oc_blockwise_state_t *buffer = (oc_blockwise_state_t *)oc_memb_alloc(pool);
  if (buffer) {
#ifdef OC_DYNAMIC_ALLOCATION
    buffer->buffer = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
    if (!buffer->buffer) {
      oc_memb_free(pool, buffer);
      return NULL;
    }
#endif /* OC_DYNAMIC_ALLOCATION */
    buffer->next_block_offset = 0;
    buffer->payload_size = 0;
    buffer->ref_count = 1;
    buffer->method = method;
    buffer->role = role;
    memcpy(&buffer->endpoint, endpoint, sizeof(oc_endpoint_t));
    oc_new_string(&buffer->href, href, href_len);
    buffer->next = 0;
#ifdef OC_CLIENT
    buffer->mid = 0;
    buffer->client_cb = 0;
#endif /* OC_CLIENT */
    return buffer;
  }
  OC_WRN("block-wise buffers exhausted\n");
  return NULL;
}

static void
oc_blockwise_free_buffer(oc_list_t list, struct oc_memb *pool,
                         oc_blockwise_state_t *buffer)
{
  if (oc_string_len(buffer->uri_query))
    oc_free_string(&buffer->uri_query);
  oc_free_string(&buffer->href);
  oc_list_remove(list, buffer);
#ifdef OC_DYNAMIC_ALLOCATION
  free(buffer->buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_memb_free(pool, buffer);
}

static oc_event_callback_retval_t
oc_blockwise_request_timeout(void *data)
{
  oc_blockwise_free_buffer(oc_blockwise_requests,
                           &oc_blockwise_request_states_s, data);
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
oc_blockwise_response_timeout(void *data)
{
  oc_blockwise_free_buffer(oc_blockwise_responses,
                           &oc_blockwise_response_states_s, data);
  return OC_EVENT_DONE;
}

oc_blockwise_state_t *
oc_blockwise_alloc_request_buffer(const char *href, int href_len,
                                  oc_endpoint_t *endpoint, oc_method_t method,
                                  oc_blockwise_role_t role)
{
  oc_blockwise_request_state_t *buffer =
    (oc_blockwise_request_state_t *)oc_blockwise_init_buffer(
      &oc_blockwise_request_states_s, href, href_len, endpoint, method, role);
  if (buffer) {
    oc_ri_add_timed_event_callback_seconds(buffer, oc_blockwise_request_timeout,
                                           OC_EXCHANGE_LIFETIME);
    oc_list_add(oc_blockwise_requests, buffer);
  }
  return (oc_blockwise_state_t *)buffer;
}

oc_blockwise_state_t *
oc_blockwise_alloc_response_buffer(const char *href, int href_len,
                                   oc_endpoint_t *endpoint, oc_method_t method,
                                   oc_blockwise_role_t role)
{
  oc_blockwise_response_state_t *buffer =
    (oc_blockwise_response_state_t *)oc_blockwise_init_buffer(
      &oc_blockwise_response_states_s, href, href_len, endpoint, method, role);
  if (buffer) {
    int i = COAP_ETAG_LEN;
    uint32_t r = oc_random_value();
    while (i > 0) {
      memcpy(buffer->etag, &r, MIN((int)sizeof(r), i));
      i -= sizeof(r);
      r = oc_random_value();
    }
#ifdef OC_CLIENT
    buffer->observe_seq = -1;
#endif /* OC_CLIENT */
    oc_ri_add_timed_event_callback_seconds(
      buffer, oc_blockwise_response_timeout, OC_EXCHANGE_LIFETIME);
    oc_list_add(oc_blockwise_responses, buffer);
  }
  return (oc_blockwise_state_t *)buffer;
}

void
oc_blockwise_free_request_buffer(oc_blockwise_state_t *buffer)
{
  oc_ri_remove_timed_event_callback(buffer, oc_blockwise_request_timeout);
  oc_blockwise_request_timeout(buffer);
}

void
oc_blockwise_free_response_buffer(oc_blockwise_state_t *buffer)
{
  oc_ri_remove_timed_event_callback(buffer, oc_blockwise_response_timeout);
  oc_blockwise_response_timeout(buffer);
}

#ifdef OC_CLIENT
void
oc_blockwise_scrub_buffers_for_client_cb(void *cb)
{
  oc_blockwise_state_t *buffer = oc_list_head(oc_blockwise_requests), *next;
  while (buffer != NULL) {
    next = buffer->next;
    if (buffer->client_cb == cb) {
      oc_blockwise_free_request_buffer(buffer);
    }
    buffer = next;
  }

  buffer = oc_list_head(oc_blockwise_responses);
  while (buffer != NULL) {
    next = buffer->next;
    if (buffer->client_cb == cb) {
      oc_blockwise_free_response_buffer(buffer);
    }
    buffer = next;
  }
}
#endif /* OC_CLIENT */

void
oc_blockwise_scrub_buffers()
{
  oc_blockwise_state_t *buffer = oc_list_head(oc_blockwise_requests), *next;
  while (buffer != NULL) {
    next = buffer->next;
    if (buffer->ref_count == 0) {
      oc_blockwise_free_request_buffer(buffer);
    }
    buffer = next;
  }

  buffer = oc_list_head(oc_blockwise_responses);
  while (buffer != NULL) {
    next = buffer->next;
    if (buffer->ref_count == 0) {
      oc_blockwise_free_response_buffer(buffer);
    }
    buffer = next;
  }
}

#ifdef OC_CLIENT
static oc_blockwise_state_t *
oc_blockwise_find_buffer_by_mid(oc_list_t list, uint16_t mid)
{
  oc_blockwise_state_t *buffer = oc_list_head(list);
  while (buffer) {
    if (buffer->mid == mid && buffer->role == OC_BLOCKWISE_CLIENT)
      break;
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t *
oc_blockwise_find_request_buffer_by_mid(uint16_t mid)
{
  return oc_blockwise_find_buffer_by_mid(oc_blockwise_requests, mid);
}

oc_blockwise_state_t *
oc_blockwise_find_response_buffer_by_mid(uint16_t mid)
{
  return oc_blockwise_find_buffer_by_mid(oc_blockwise_responses, mid);
}

static oc_blockwise_state_t *
oc_blockwise_find_buffer_by_client_cb(oc_list_t list, oc_endpoint_t *endpoint,
                                      void *client_cb)
{
  oc_blockwise_state_t *buffer = oc_list_head(list);
  while (buffer) {
    if (buffer->role == OC_BLOCKWISE_CLIENT && buffer->client_cb == client_cb &&
        oc_endpoint_compare(endpoint, &buffer->endpoint) == 0) {
      break;
    }
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t *
oc_blockwise_find_request_buffer_by_client_cb(oc_endpoint_t *endpoint,
                                              void *client_cb)
{
  return oc_blockwise_find_buffer_by_client_cb(oc_blockwise_requests, endpoint,
                                               client_cb);
}

oc_blockwise_state_t *
oc_blockwise_find_response_buffer_by_client_cb(oc_endpoint_t *endpoint,
                                               void *client_cb)
{
  return oc_blockwise_find_buffer_by_client_cb(oc_blockwise_responses, endpoint,
                                               client_cb);
}
#endif /* OC_CLIENT */

static oc_blockwise_state_t *
oc_blockwise_find_buffer(oc_list_t list, const char *href, int href_len,
                         oc_endpoint_t *endpoint, oc_method_t method,
                         const char *query, int query_len,
                         oc_blockwise_role_t role)
{
  oc_blockwise_state_t *buffer = oc_list_head(list);
  while (buffer) {
    if (strncmp(href, oc_string(buffer->href), href_len) == 0 &&
        oc_endpoint_compare(&buffer->endpoint, endpoint) == 0 &&
        buffer->method == method && buffer->role == role &&
        query_len == (int)oc_string_len(buffer->uri_query) &&
        memcmp(query, oc_string(buffer->uri_query), query_len) == 0) {
      break;
    }
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t *
oc_blockwise_find_request_buffer(const char *href, int href_len,
                                 oc_endpoint_t *endpoint, oc_method_t method,
                                 const char *query, int query_len,
                                 oc_blockwise_role_t role)
{
  return oc_blockwise_find_buffer(oc_blockwise_requests, href, href_len,
                                  endpoint, method, query, query_len, role);
}

oc_blockwise_state_t *
oc_blockwise_find_response_buffer(const char *href, int href_len,
                                  oc_endpoint_t *endpoint, oc_method_t method,
                                  const char *query, int query_len,
                                  oc_blockwise_role_t role)
{
  return oc_blockwise_find_buffer(oc_blockwise_responses, href, href_len,
                                  endpoint, method, query, query_len, role);
}

const void *
oc_blockwise_dispatch_block(oc_blockwise_state_t *buffer, uint32_t block_offset,
                            uint16_t requested_block_size,
                            uint16_t *payload_size)
{
  if (block_offset < buffer->payload_size) {
    if (buffer->payload_size < requested_block_size)
      *payload_size = (uint16_t)buffer->payload_size;
    else {
      *payload_size = MIN(requested_block_size,
                          (uint16_t)(buffer->payload_size - block_offset));
    }
    buffer->next_block_offset = block_offset + *payload_size;
    return (const void *)&buffer->buffer[block_offset];
  }
  return NULL;
}

bool
oc_blockwise_handle_block(oc_blockwise_state_t *buffer,
                          uint32_t incoming_block_offset,
                          const uint8_t *incoming_block,
                          uint16_t incoming_block_size)
{
  if (incoming_block_offset >= (unsigned)OC_MAX_APP_DATA_SIZE ||
      incoming_block_size > (OC_MAX_APP_DATA_SIZE - incoming_block_offset) ||
      incoming_block_offset > buffer->next_block_offset)
    return false;

  if (buffer->next_block_offset == incoming_block_offset) {
    memcpy(&buffer->buffer[buffer->next_block_offset], incoming_block,
           incoming_block_size);

    buffer->next_block_offset += incoming_block_size;
  }

  return true;
}
#endif /* OC_BLOCK_WISE */
