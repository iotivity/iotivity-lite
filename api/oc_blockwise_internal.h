/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *               2023 plgd.dev s.r.o.
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
 ***************************************************************************/

#ifndef OC_BLOCKWISE_INTERNAL_H
#define OC_BLOCKWISE_INTERNAL_H

#include "oc_config.h"

#ifdef OC_BLOCK_WISE

#include "messaging/coap/oc_coap.h"
#include "oc_helpers.h"
#include "oc_endpoint.h"
#include "oc_etag.h"
#include "oc_ri.h"
#include "port/oc_connectivity.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief role of the transer
 */
typedef enum {
  OC_BLOCKWISE_CLIENT = 0, ///< client
  OC_BLOCKWISE_SERVER      ///< server
} oc_blockwise_role_t;

typedef void oc_blockwise_finish_cb_t(void);

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
#ifdef OC_APP_DATA_BUFFER_POOL
  void *block;
#endif /* OC_APP_DATA_BUFFER_POOL */
  uint8_t *buffer;
  uint32_t buffer_size;
#else                    /* OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MAX_APP_DATA_SIZE]; ///< the buffer
#endif                   /* !OC_DYNAMIC_ALLOCATION */
  oc_string_t uri_query; ///< the query
  oc_blockwise_finish_cb_t *finish_cb;
#ifdef OC_CLIENT
  uint8_t token[COAP_TOKEN_LEN]; ///< the token
  uint8_t token_len;             ///< token length
  uint16_t mid;                  ///< the message id
  void *client_cb;               ///< client callback
#endif                           /* OC_CLIENT */
} oc_blockwise_state_t;

typedef struct oc_blockwise_request_state_s
{
  oc_blockwise_state_t base;
} oc_blockwise_request_state_t;

typedef struct oc_blockwise_response_state_s
{
  oc_blockwise_state_t base;
  coap_status_t code;
  oc_coap_etag_t etag;

#ifdef OC_CLIENT
  int32_t observe_seq;
#endif /* OC_CLIENT */
} oc_blockwise_response_state_t;

/**
 * @brief allocate the request buffer
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint (cannot be NULL)
 * @param method method
 * @param role the role (client or server)
 * @param buffer_size the buffer size for allocation
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_alloc_request_buffer(
  const char *href, size_t href_len, const oc_endpoint_t *endpoint,
  oc_method_t method, oc_blockwise_role_t role, uint32_t buffer_size)
  OC_NONNULL(3);

/**
 * @brief allocate a response buffer
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint (cannot be NULL)
 * @param method method
 * @param role the role (client or server)
 * @param buffer_size the buffer size for allocation
 * @param code the response code
 * @param generate_etag generate ETag
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_alloc_response_buffer(
  const char *href, size_t href_len, const oc_endpoint_t *endpoint,
  oc_method_t method, oc_blockwise_role_t role, uint32_t buffer_size,
  coap_status_t code, bool generate_etag) OC_NONNULL(3);

/**
 * @brief free the request buffer
 *
 * @param buffer buffer to be freed
 */
void oc_blockwise_free_request_buffer(oc_blockwise_state_t *buffer);

/**
 * @brief free the response buffer
 *
 * @param buffer buffer to be freed
 */
void oc_blockwise_free_response_buffer(oc_blockwise_state_t *buffer);

/**
 * @brief free all request blocks that are handled (refcount = 0)
 *
 * @param all including ref count != 0
 */
void oc_blockwise_free_all_request_buffers(bool all);

/**
 * @brief free all response blocks that are handled (refcount = 0)
 *
 * @param all including ref count != 0
 */
void oc_blockwise_free_all_response_buffers(bool all);

/**
 * @brief free all blocks that are handled (refcount = 0)
 *
 * @param all including ref count != 0
 */
void oc_blockwise_free_all_buffers(bool all);

/**
 * @brief find request buffer based on more information
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint
 * @param method the method
 * @param query the query parameters
 * @param query_len the query length
 * @param role the role (client or server)
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer(
  const char *href, size_t href_len, const oc_endpoint_t *endpoint,
  oc_method_t method, const char *query, size_t query_len,
  oc_blockwise_role_t role);

/**
 * @brief find response buffer based on more information
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint
 * @param method the method
 * @param query the query parameters
 * @param query_len the query length
 * @param role the role (client or server)
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer(
  const char *href, size_t href_len, const oc_endpoint_t *endpoint,
  oc_method_t method, const char *query, size_t query_len,
  oc_blockwise_role_t role);

#ifdef OC_CLIENT

/**
 * @brief scrub client blockwise request and response blocks by matching client
 * callback
 *
 * @param cb client callback
 */
void oc_blockwise_scrub_buffers_for_client_cb(const void *cb);

/**
 * @brief find client blockwise request based on mid
 *
 * @param mid the message id
 * @return oc_blockwise_state_t* the blocktranfer
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_mid(uint16_t mid);

/**
 * @brief find client blockwise response based on mid
 *
 * @param mid the message id
 * @return oc_blockwise_state_t* the blocktranfer
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_mid(uint16_t mid);

/**
 * @brief find client blockwise request by token
 *
 * @param token the token
 * @param token_len the token length
 * @return oc_blockwise_state_t* the blocktranfer
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_token(
  const uint8_t *token, uint8_t token_len);

/**
 * @brief find client blockwise response by token
 *
 * @param token the token
 * @param token_len the token length
 * @return oc_blockwise_state_t* the blocktransfer
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_token(
  const uint8_t *token, uint8_t token_len);

/**
 * @brief find client request by client callback & endpoint
 *
 * @param endpoint the endpoint
 * @param client_cb the callback
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_client_cb(
  const oc_endpoint_t *endpoint, const void *client_cb);

/**
 * @brief find client response by client callback & endpoint
 *
 * @param endpoint the endpoint
 * @param client_cb the callback
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_client_cb(
  const oc_endpoint_t *endpoint, const void *client_cb);

#endif /* OC_CLIENT */

/**
 * @brief send the block
 *
 * @param buffer the whole message (cannot be NULL)
 * @param block_offset the block offset
 * @param requested_block_size blocksize to be send
 * @param payload_size the send payload size (cannot be NULL)
 * @return void*
 */
void *oc_blockwise_dispatch_block(oc_blockwise_state_t *buffer,
                                  uint32_t block_offset,
                                  uint32_t requested_block_size,
                                  uint32_t *payload_size) OC_NONNULL();

/**
 * @brief handle the incomming block (partial message)
 *
 * @param buffer the whole message (cannot be NULL)
 * @param incoming_block_offset the block offset
 * @param incoming_block the incomming block to be added (cannot be NULL)
 * @param incoming_block_size the size of the incomming block
 * @return true
 * @return false
 */
bool oc_blockwise_handle_block(oc_blockwise_state_t *buffer,
                               uint32_t incoming_block_offset,
                               const uint8_t *incoming_block,
                               uint32_t incoming_block_size) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_BLOCK_WISE */

#endif /* OC_BLOCKWISE_INTERNAL_H */
