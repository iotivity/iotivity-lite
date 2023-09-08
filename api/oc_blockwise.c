/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#include <oc_config.h>

#ifdef OC_BLOCK_WISE

#include "api/oc_blockwise_internal.h"
#include "api/oc_helpers_internal.h"
#include "messaging/coap/coap.h"
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "util/oc_list.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"
#include <inttypes.h>

OC_MEMB(oc_blockwise_request_states_s, oc_blockwise_request_state_t,
        OC_MAX_NUM_CONCURRENT_REQUESTS);
OC_MEMB(oc_blockwise_response_states_s, oc_blockwise_response_state_t,
        OC_MAX_NUM_CONCURRENT_REQUESTS);
OC_LIST(oc_blockwise_requests);
OC_LIST(oc_blockwise_responses);

#ifdef OC_APP_DATA_BUFFER_POOL
typedef struct oc_app_data_buffer_t
{
  uint8_t buffer[OC_APP_DATA_BUFFER_SIZE];
} oc_app_data_buffer_t;
OC_MEMB_STATIC(oc_app_data_s, oc_app_data_buffer_t, OC_APP_DATA_BUFFER_POOL);
#endif /* OC_APP_DATA_BUFFER_POOL */

static oc_blockwise_state_t *
blockwise_init_buffer(struct oc_memb *pool, const char *href, size_t href_len,
                      const oc_endpoint_t *endpoint, oc_method_t method,
                      oc_blockwise_role_t role, uint32_t buffer_size)
{
  if (href_len == 0) {
    OC_DBG("empty href");
    return NULL;
  }

  oc_blockwise_state_t *buffer = (oc_blockwise_state_t *)oc_memb_alloc(pool);
  if (buffer == NULL) {
    OC_WRN("block-wise buffers exhausted");
    return NULL;
  }

#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_APP_DATA_BUFFER_POOL
  oc_app_data_buffer_t *app_buffer =
    (oc_app_data_buffer_t *)oc_memb_alloc(&oc_app_data_s);
  if (app_buffer != NULL) {
    buffer->block = app_buffer;
    buffer->buffer = app_buffer->buffer;
    buffer->buffer_size = OC_APP_DATA_BUFFER_SIZE;
  }
#endif /* OC_APP_DATA_BUFFER_POOL */
  if (buffer->buffer == NULL) {
    buffer->buffer = (uint8_t *)malloc(buffer_size);
    buffer->buffer_size = buffer_size;
    OC_DBG("block-wise buffer allocated with size %" PRIu32, buffer_size);
  }
  if (buffer->buffer == NULL) {
    OC_ERR("cannot allocate block-wise buffer");
    oc_memb_free(pool, buffer);
    return NULL;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  (void)buffer_size;
#endif /* !OC_DYNAMIC_ALLOCATION */

  buffer->next_block_offset = 0;
  buffer->payload_size = 0;
  buffer->ref_count = 1;
  buffer->method = method;
  buffer->role = role;
  memcpy(&buffer->endpoint, endpoint, sizeof(oc_endpoint_t));
  buffer->endpoint.next = NULL;
  oc_new_string(&buffer->href, href, href_len);
  buffer->next = NULL;
  buffer->finish_cb = NULL;
#ifdef OC_CLIENT
  buffer->mid = 0;
  buffer->client_cb = NULL;
#endif /* OC_CLIENT */
  return buffer;
}

static void
blockwise_free_buffer(oc_list_t list, struct oc_memb *pool,
                      oc_blockwise_state_t *buffer)
{
  if (buffer == NULL) {
    return;
  }

  oc_free_string(&buffer->uri_query);
  oc_free_string(&buffer->href);
  oc_list_remove(list, buffer);
#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_APP_DATA_BUFFER_POOL
  if (buffer->block) {
    oc_memb_free(&oc_app_data_s, buffer->block);
    buffer->buffer = NULL;
  }
#endif /* OC_APP_DATA_BUFFER_POOL */
  if (buffer->buffer) {
    free(buffer->buffer);
  }
  buffer->buffer = NULL;
#endif
  oc_blockwise_finish_cb_t *finish_cb = buffer->finish_cb;
  oc_memb_free(pool, buffer);
  if (finish_cb) {
    finish_cb();
  }
}

static uint32_t
blockwise_get_buffer_size(const oc_blockwise_state_t *buffer)
{
#ifdef OC_DYNAMIC_ALLOCATION
  return buffer->buffer_size;
#else
  (void)buffer;
  return OC_MAX_APP_DATA_SIZE;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static oc_event_callback_retval_t
blockwise_free_request_async(void *data)
{
  blockwise_free_buffer(oc_blockwise_requests, &oc_blockwise_request_states_s,
                        (oc_blockwise_state_t *)data);
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
blockwise_free_response_async(void *data)
{
  blockwise_free_buffer(oc_blockwise_responses, &oc_blockwise_response_states_s,
                        (oc_blockwise_state_t *)data);
  return OC_EVENT_DONE;
}

oc_blockwise_state_t *
oc_blockwise_alloc_request_buffer(const char *href, size_t href_len,
                                  const oc_endpoint_t *endpoint,
                                  oc_method_t method, oc_blockwise_role_t role,
                                  uint32_t buffer_size)
{
  oc_blockwise_request_state_t *buffer =
    (oc_blockwise_request_state_t *)blockwise_init_buffer(
      &oc_blockwise_request_states_s, href, href_len, endpoint, method, role,
      buffer_size);
  if (buffer == NULL) {
    OC_ERR("cannot allocate block-wise request buffer");
    return NULL;
  }
  oc_ri_add_timed_event_callback_seconds(buffer, blockwise_free_request_async,
                                         OC_EXCHANGE_LIFETIME);
  oc_list_add(oc_blockwise_requests, buffer);
  return (oc_blockwise_state_t *)buffer;
}

oc_blockwise_state_t *
oc_blockwise_alloc_response_buffer(const char *href, size_t href_len,
                                   const oc_endpoint_t *endpoint,
                                   oc_method_t method, oc_blockwise_role_t role,
                                   uint32_t buffer_size, coap_status_t code,
                                   bool generate_etag)
{
  oc_blockwise_response_state_t *buffer =
    (oc_blockwise_response_state_t *)blockwise_init_buffer(
      &oc_blockwise_response_states_s, href, href_len, endpoint, method, role,
      buffer_size);
  if (buffer == NULL) {
    OC_ERR("cannot allocate block-wise response buffer");
    return NULL;
  }
  buffer->code = code;
  if (generate_etag) {
    oc_random_buffer(buffer->etag.value, sizeof(buffer->etag.value));
    buffer->etag.length = sizeof(buffer->etag.value);
  }
#ifdef OC_CLIENT
  buffer->observe_seq = OC_COAP_OPTION_OBSERVE_NOT_SET;
#endif /* OC_CLIENT */
  oc_ri_add_timed_event_callback_seconds(buffer, blockwise_free_response_async,
                                         OC_EXCHANGE_LIFETIME);
  oc_list_add(oc_blockwise_responses, buffer);
  return (oc_blockwise_state_t *)buffer;
}

void
oc_blockwise_free_request_buffer(oc_blockwise_state_t *buffer)
{
  oc_ri_remove_timed_event_callback(buffer, blockwise_free_request_async);
  blockwise_free_request_async(buffer);
}

void
oc_blockwise_free_response_buffer(oc_blockwise_state_t *buffer)
{
  oc_ri_remove_timed_event_callback(buffer, blockwise_free_response_async);
  blockwise_free_response_async(buffer);
}

void
oc_blockwise_free_all_request_buffers(bool all)
{
  oc_blockwise_state_t *buffer =
    (oc_blockwise_state_t *)oc_list_head(oc_blockwise_requests);
  while (buffer != NULL) {
    oc_blockwise_state_t *next = buffer->next;
    if (buffer->ref_count == 0 || all) {
      oc_blockwise_free_request_buffer(buffer);
    }
    buffer = next;
  }
}

void
oc_blockwise_free_all_response_buffers(bool all)
{
  oc_blockwise_state_t *buffer =
    (oc_blockwise_state_t *)oc_list_head(oc_blockwise_responses);
  while (buffer != NULL) {
    oc_blockwise_state_t *next = buffer->next;
    if (buffer->ref_count == 0 || all) {
      oc_blockwise_free_response_buffer(buffer);
    }
    buffer = next;
  }
}

void
oc_blockwise_free_all_buffers(bool all)
{
  oc_blockwise_free_all_request_buffers(all);
  oc_blockwise_free_all_response_buffers(all);
}

#ifdef OC_CLIENT

void
oc_blockwise_scrub_buffers_for_client_cb(const void *cb)
{
  oc_blockwise_state_t *buffer =
    (oc_blockwise_state_t *)oc_list_head(oc_blockwise_requests);
  while (buffer != NULL) {
    oc_blockwise_state_t *next = buffer->next;
    if (buffer->client_cb == cb) {
      oc_blockwise_free_request_buffer(buffer);
    }
    buffer = next;
  }

  buffer = (oc_blockwise_state_t *)oc_list_head(oc_blockwise_responses);
  while (buffer != NULL) {
    oc_blockwise_state_t *next = buffer->next;
    if (buffer->client_cb == cb) {
      oc_blockwise_free_response_buffer(buffer);
    }
    buffer = next;
  }
}

static oc_blockwise_state_t *
blockwise_find_buffer_by_token(oc_list_t list, const uint8_t *token,
                               uint8_t token_len)
{
  oc_blockwise_state_t *buffer = (oc_blockwise_state_t *)oc_list_head(list);
  while (buffer != NULL) {
    if (token_len > 0 && buffer->role == OC_BLOCKWISE_CLIENT &&
        buffer->token_len == token_len &&
        memcmp(buffer->token, token, token_len) == 0)
      break;
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t *
oc_blockwise_find_request_buffer_by_token(const uint8_t *token,
                                          uint8_t token_len)
{
  return blockwise_find_buffer_by_token(oc_blockwise_requests, token,
                                        token_len);
}

oc_blockwise_state_t *
oc_blockwise_find_response_buffer_by_token(const uint8_t *token,
                                           uint8_t token_len)
{
  return blockwise_find_buffer_by_token(oc_blockwise_responses, token,
                                        token_len);
}

static oc_blockwise_state_t *
blockwise_find_buffer_by_mid(oc_list_t list, uint16_t mid)
{
  oc_blockwise_state_t *buffer = (oc_blockwise_state_t *)oc_list_head(list);
  while (buffer) {
    if (buffer->mid == mid && buffer->role == OC_BLOCKWISE_CLIENT) {
      break;
    }
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t *
oc_blockwise_find_request_buffer_by_mid(uint16_t mid)
{
  return blockwise_find_buffer_by_mid(oc_blockwise_requests, mid);
}

oc_blockwise_state_t *
oc_blockwise_find_response_buffer_by_mid(uint16_t mid)
{
  return blockwise_find_buffer_by_mid(oc_blockwise_responses, mid);
}

static oc_blockwise_state_t *
blockwise_find_buffer_by_client_cb(oc_list_t list,
                                   const oc_endpoint_t *endpoint,
                                   const void *client_cb)
{
  oc_blockwise_state_t *buffer = (oc_blockwise_state_t *)oc_list_head(list);
  while (buffer != NULL) {
    if (buffer->role == OC_BLOCKWISE_CLIENT && buffer->client_cb == client_cb &&
        oc_endpoint_compare(endpoint, &buffer->endpoint) == 0) {
      break;
    }
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t *
oc_blockwise_find_request_buffer_by_client_cb(const oc_endpoint_t *endpoint,
                                              const void *client_cb)
{
  return blockwise_find_buffer_by_client_cb(oc_blockwise_requests, endpoint,
                                            client_cb);
}

oc_blockwise_state_t *
oc_blockwise_find_response_buffer_by_client_cb(const oc_endpoint_t *endpoint,
                                               const void *client_cb)
{
  return blockwise_find_buffer_by_client_cb(oc_blockwise_responses, endpoint,
                                            client_cb);
}
#endif /* OC_CLIENT */

static oc_blockwise_state_t *
blockwise_find_buffer(oc_list_t list, oc_string_view_t href,
                      const oc_endpoint_t *endpoint, oc_method_t method,
                      oc_string_view_t query, oc_blockwise_role_t role)
{
  oc_blockwise_state_t *buffer = (oc_blockwise_state_t *)oc_list_head(list);
  while (buffer != NULL) {
    if (buffer->method == method && buffer->role == role &&
        oc_string_is_cstr_equal(&buffer->href, href.data, href.length) &&
        oc_endpoint_compare(&buffer->endpoint, endpoint) == 0 &&
        oc_string_is_cstr_equal(&buffer->uri_query, query.data, query.length)) {
      break;
    }
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t *
oc_blockwise_find_request_buffer(const char *href, size_t href_len,
                                 const oc_endpoint_t *endpoint,
                                 oc_method_t method, const char *query,
                                 size_t query_len, oc_blockwise_role_t role)
{
  return blockwise_find_buffer(oc_blockwise_requests,
                               oc_string_view(href, href_len), endpoint, method,
                               oc_string_view(query, query_len), role);
}

oc_blockwise_state_t *
oc_blockwise_find_response_buffer(const char *href, size_t href_len,
                                  const oc_endpoint_t *endpoint,
                                  oc_method_t method, const char *query,
                                  size_t query_len, oc_blockwise_role_t role)
{
  return blockwise_find_buffer(oc_blockwise_responses,
                               oc_string_view(href, href_len), endpoint, method,
                               oc_string_view(query, query_len), role);
}

void *
oc_blockwise_dispatch_block(oc_blockwise_state_t *buffer, uint32_t block_offset,
                            uint32_t requested_block_size,
                            uint32_t *payload_size)
{
  if (block_offset < buffer->payload_size) {
    if (buffer->payload_size < requested_block_size) {
      *payload_size = buffer->payload_size;
    } else {
      *payload_size = MIN(requested_block_size,
                          (uint32_t)(buffer->payload_size - block_offset));
    }
    buffer->next_block_offset = block_offset + *payload_size;
    return (void *)&buffer->buffer[block_offset];
  }
  return NULL;
}

bool
oc_blockwise_handle_block(oc_blockwise_state_t *buffer,
                          uint32_t incoming_block_offset,
                          const uint8_t *incoming_block,
                          uint32_t incoming_block_size)
{
  if (incoming_block_offset >= blockwise_get_buffer_size(buffer) ||
      incoming_block_size >
        (blockwise_get_buffer_size(buffer) - incoming_block_offset) ||
      incoming_block_offset > buffer->next_block_offset) {
    return false;
  }

  if (buffer->next_block_offset == incoming_block_offset) {
    memcpy(&buffer->buffer[buffer->next_block_offset], incoming_block,
           incoming_block_size);

    buffer->next_block_offset += incoming_block_size;
  }

  return true;
}
#endif /* OC_BLOCK_WISE */
