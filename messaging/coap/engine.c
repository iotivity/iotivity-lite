/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#include "api/oc_helpers_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_main_internal.h"
#include "api/oc_message_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/log_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/engine_internal.h"
#include "messaging/coap/observe_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "util/oc_macros_internal.h"

#ifdef OC_SECURITY
#include "security/oc_audit_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_BLOCK_WISE
#include "api/oc_blockwise_internal.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
#include "api/client/oc_client_cb_internal.h"
#include "oc_client_state.h"
#endif /* OC_CLIENT */

#ifdef OC_TCP
#include "signal_internal.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

OC_PROCESS(g_coap_engine, "CoAP Engine");

#ifdef OC_REQUEST_HISTORY
// The size of the array used to deduplicate CoAP messages.
// A value of 25 means that the message ID & device counter
// are compared to the ones in the last 25 messages. If a
// match is found, the message is dropped as it must be
// a duplicate.
#define OC_REQUEST_HISTORY_SIZE (25)
static uint16_t g_history[OC_REQUEST_HISTORY_SIZE];
static uint32_t g_history_dev[OC_REQUEST_HISTORY_SIZE];
static uint8_t g_idx = 0;

void
oc_request_history_init(void)
{
  memset(g_history, 0, sizeof(g_history));
  memset(g_history_dev, 0, sizeof(g_history_dev));
  g_idx = 0;
}

bool
oc_coap_check_if_duplicate(const oc_endpoint_t *endpoint, uint16_t mid)
{
  for (size_t i = 0; i < OC_REQUEST_HISTORY_SIZE; i++) {
    if (g_history[i] == mid && g_history_dev[i] == (uint32_t)endpoint->device) {
#if OC_WRN_IS_ENABLED || OC_DBG_IS_ENABLED
      char ipaddr[OC_IPADDR_BUFF_SIZE];
      OC_SNPRINTFipaddr(ipaddr, OC_IPADDR_BUFF_SIZE, *endpoint);
      if (endpoint->flags & SECURED) {
        COAP_WRN("dropping duplicate request with mid %d from %s", (int)mid,
                 ipaddr);
      }
#if OC_DBG_IS_ENABLED
      else {
        COAP_DBG("dropping duplicate request with mid %d from %s", (int)mid,
                 ipaddr);
      }
#endif /* OC_DBG_IS_ENABLED */
#endif /* OC_WRN_IS_ENABLED || OC_DBG_IS_ENABLED */
      return true;
    }
  }
  return false;
}
#endif /* OC_REQUEST_HISTORY */

static void
coap_send_empty_response(coap_message_type_t type, uint16_t mid,
                         const uint8_t *token, size_t token_len, uint8_t code,
                         const oc_endpoint_t *endpoint)
{
  COAP_DBG("CoAP send empty message: mid=%u, code=%u", mid, code);
  coap_packet_t packet; // empty response
  coap_udp_init_message(&packet, type, code, mid);
  oc_message_t *message = oc_message_allocate_outgoing();
  if (message == NULL) {
    return;
  }
  memcpy(&message->endpoint, endpoint, sizeof(*endpoint));
  if (token && token_len > 0) {
    coap_set_token(&packet, token, token_len);
  }
  size_t len =
    coap_serialize_message(&packet, message->data, oc_message_buffer_size());
  if (len == 0) {
    oc_message_unref(message);
    return;
  }

  message->length = len;
  coap_send_message(message);
  if (message->ref_count == 0) {
    oc_message_unref(message);
  }
}

#ifdef OC_SECURITY
static void
coap_audit_log(const oc_message_t *msg)
{
  char ipaddr[OC_IPADDR_BUFF_SIZE];
  OC_SNPRINTFipaddr(ipaddr, OC_IPADDR_BUFF_SIZE, msg->endpoint);
  char buff1[16];
  memset(buff1, 0, sizeof(buff1));
  if (msg->length >= 4) {
    snprintf(buff1, sizeof(buff1), "[%02x:%02x:%02x:%02x]", msg->data[0],
             msg->data[1], msg->data[2], msg->data[3]);
  }
  // oc_string_array item length cannot exceed 128 bytes
  // hexdump format "XX:XX:..." : each byte is represented by 3 symbols
  char buff2[128];
  size_t length = (msg->length < 42) ? msg->length : 42;
  if (length > 0) {
    size_t size = length * 3 + 1;
    memset(buff2, 0, 128);
    SNPRINTFbytes(buff2, size - 1, msg->data, length);
  }
  char *aux[] = { ipaddr, buff1, buff2 };
  oc_audit_log(msg->endpoint.device, "COMM-1", "Unexpected CoAP command", 0x40,
               2, (const char **)aux, (length == 0) ? 2 : 3);
}
#endif /* OC_SECURITY */

/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/

coap_block_options_t
coap_packet_get_block_options(const coap_packet_t *message, bool block2)
{
  coap_block_options_t block = {
    .num = 0,
    .offset = 0,
    .size = (uint16_t)OC_BLOCK_SIZE,
    .more = 0,
    .enabled = false,
  };

  if (!block2) {
    if (coap_options_get_block1(message, &block.num, &block.more, &block.size,
                                &block.offset)) {
      block.enabled = true;
      block.size = MIN(block.size, (uint16_t)OC_BLOCK_SIZE);
    }
    return block;
  }

  if (coap_options_get_block2(message, &block.num, &block.more, &block.size,
                              &block.offset)) {
    block.enabled = true;
    block.size = MIN(block.size, (uint16_t)OC_BLOCK_SIZE);
  }
  return block;
}

#if OC_DBG_IS_ENABLED

static void
coap_packet_log_message(const coap_packet_t *message)
{
  COAP_DBG("  Parsed: CoAP version: %u, token: 0x%02X%02X, mid: %u",
           message->version, message->token[0], message->token[1],
           message->mid);
  if (message->type == COAP_TYPE_CON) {
    COAP_DBG("  type: CON");
  } else if (message->type == COAP_TYPE_NON) {
    COAP_DBG("  type: NON");
  } else if (message->type == COAP_TYPE_ACK) {
    COAP_DBG("  type: ACK");
  } else if (message->type == COAP_TYPE_RST) {
    COAP_DBG("  type: RST");
  }
}

#endif /* OC_DBG_IS_ENABLED */

static coap_receive_status_t
coap_receive_init_response(coap_packet_t *response,
                           const oc_endpoint_t *endpoint,
                           coap_message_type_t type, uint16_t mid,
                           const char *href, size_t href_len)
{
#ifdef OC_TCP
  if ((endpoint->flags & TCP) != 0) {
    coap_tcp_init_message(response, CONTENT_2_05);
    return COAP_RECEIVE_SUCCESS;
  }
#endif /* OC_TCP */

  if (type == COAP_TYPE_CON) {
    coap_udp_init_message(response, COAP_TYPE_ACK, CONTENT_2_05, mid);
  } else {
#ifdef OC_REQUEST_HISTORY
    if (oc_coap_check_if_duplicate(endpoint, mid)) {
      return COAP_RECEIVE_SKIP_DUPLICATE_MESSAGE;
    }
    g_history[g_idx] = mid;
    g_history_dev[g_idx] = (uint32_t)endpoint->device;
    g_idx = (g_idx + 1) % OC_REQUEST_HISTORY_SIZE;
#endif /* OC_REQUEST_HISTORY */
    coap_message_type_t response_type =
      (href_len == OC_CHAR_ARRAY_LEN("oic/res") &&
       memcmp(href, "oic/res", href_len) == 0)
        ? COAP_TYPE_CON
        : COAP_TYPE_NON;
    coap_udp_init_message(response, response_type, CONTENT_2_05,
                          coap_get_mid());
  }
  return COAP_RECEIVE_SUCCESS;
}

#ifdef OC_BLOCK_WISE

static oc_blockwise_state_t *
coap_receive_create_request_buffer(const coap_packet_t *request,
                                   const char *href, size_t href_len,
                                   const oc_endpoint_t *endpoint,
                                   uint32_t buffer_size,
                                   const uint8_t *incoming_block,
                                   uint32_t incoming_block_len)
{
  oc_blockwise_state_t *request_buffer = oc_blockwise_alloc_request_buffer(
    href, href_len, endpoint, request->code, OC_BLOCKWISE_SERVER, buffer_size);
  if (request_buffer == NULL) {
    COAP_ERR("could not create buffer to hold request payload");
    return NULL;
  }
  if (!oc_blockwise_handle_block(request_buffer, 0, incoming_block,
                                 (uint16_t)incoming_block_len)) {
    COAP_ERR("could not process incoming block");
    request_buffer->ref_count = 0;
    return NULL;
  }
  if (request->uri_query_len > 0) {
    oc_new_string(&request_buffer->uri_query, request->uri_query,
                  request->uri_query_len);
  }
  request_buffer->payload_size = incoming_block_len;
  return request_buffer;
}

static coap_receive_status_t
coap_receive_blockwise_block1(coap_receive_ctx_t *ctx, const char *href,
                              size_t href_len, const oc_endpoint_t *endpoint)
{
  assert(ctx->message->code == COAP_POST || ctx->message->code == COAP_PUT);
  COAP_DBG("processing block1 option");
  const uint8_t *incoming_block;
  uint32_t incoming_block_len = coap_get_payload(ctx->message, &incoming_block);
  ctx->request_buffer = oc_blockwise_find_request_buffer(
    href, href_len, endpoint, ctx->message->code, ctx->message->uri_query,
    ctx->message->uri_query_len, OC_BLOCKWISE_SERVER);

  if (ctx->request_buffer != NULL &&
      ctx->request_buffer->payload_size ==
        ctx->request_buffer->next_block_offset &&
      (ctx->request_buffer->next_block_offset - incoming_block_len) !=
        ctx->block1.offset) {
    oc_blockwise_free_request_buffer(ctx->request_buffer);
    ctx->request_buffer = NULL;
  }

  if (ctx->request_buffer == NULL && ctx->block1.num == 0) {
    uint32_t buffer_size;
    if (!coap_options_get_size1(ctx->message, &buffer_size) ||
        buffer_size == 0) {
      buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
    }
    COAP_DBG("creating new block-wise request buffer");
    ctx->request_buffer = oc_blockwise_alloc_request_buffer(
      href, href_len, endpoint, ctx->message->code, OC_BLOCKWISE_SERVER,
      buffer_size);

    if (ctx->request_buffer != NULL && ctx->message->uri_query_len > 0) {
      oc_new_string(&ctx->request_buffer->uri_query, ctx->message->uri_query,
                    ctx->message->uri_query_len);
    }
  }

  if (ctx->request_buffer == NULL) {
    COAP_ERR("could not create block-wise request buffer");
    return COAP_RECEIVE_ERROR;
  }

  COAP_DBG("processing incoming block");
  if (!oc_blockwise_handle_block(
        ctx->request_buffer, ctx->block1.offset, incoming_block,
        MIN((uint16_t)incoming_block_len, ctx->block1.size))) {
    COAP_ERR("could not process incoming block");
    return COAP_RECEIVE_ERROR;
  }

  if (ctx->block1.more) {
    COAP_DBG("more blocks expected; issuing request for the next block");
    ctx->response->code = CONTINUE_2_31;
    coap_options_set_block1(ctx->response, ctx->block1.num, ctx->block1.more,
                            ctx->block1.size, 0);
    ctx->request_buffer->ref_count = 1;
    return COAP_RECEIVE_SUCCESS;
  }

  COAP_DBG("received all blocks for payload");
  if (ctx->message->type == COAP_TYPE_CON) {
    coap_send_empty_response(COAP_TYPE_ACK, ctx->message->mid, /*token*/ NULL,
                             /*token_len*/ 0, /*code*/ 0, endpoint);
  }
  coap_udp_init_message(ctx->response, COAP_TYPE_CON, CONTENT_2_05,
                        coap_get_mid());
  ctx->transaction->mid = ctx->response->mid;
  coap_options_set_block1(ctx->response, ctx->block1.num, ctx->block1.more,
                          ctx->block1.size, 0);
  coap_options_set_accept(ctx->response, APPLICATION_VND_OCF_CBOR);
  ctx->request_buffer->payload_size = ctx->request_buffer->next_block_offset;
  ctx->request_buffer->ref_count = 0;
  return COAP_RECEIVE_INVOKE_HANDLER;
}

static coap_receive_status_t
coap_receive_blockwise_block2(coap_receive_ctx_t *ctx, const char *href,
                              size_t href_len, const oc_endpoint_t *endpoint)
{
  COAP_DBG("processing block2 option");
  const uint8_t *incoming_block;
  uint32_t incoming_block_len = coap_get_payload(ctx->message, &incoming_block);
  // block2 in request is expected to be used with GET/FETCH and should contain
  // no payload
  if (incoming_block_len > 0) {
    COAP_ERR("invalid GET/FETCH request containing payload");
    return COAP_RECEIVE_ERROR;
  }

  ctx->response_buffer = oc_blockwise_find_response_buffer(
    href, href_len, endpoint, ctx->message->code, ctx->message->uri_query,
    ctx->message->uri_query_len, OC_BLOCKWISE_SERVER);

  if (ctx->response_buffer != NULL) {
    if ((ctx->response_buffer->next_block_offset - ctx->block2.offset) >
        ctx->block2.size) {
      // UDP transfer can duplicate messages and we want to avoid terminate
      // BWT, so we drop the message.
      COAP_DBG(
        "dropped message because message was already provided for block2");
      coap_clear_transaction(ctx->transaction);
      return COAP_RECEIVE_SKIP_DUPLICATE_MESSAGE;
    }

    COAP_DBG("continuing ongoing block-wise transfer");
    uint32_t payload_size = 0;
    void *payload =
      oc_blockwise_dispatch_block(ctx->response_buffer, ctx->block2.offset,
                                  ctx->block2.size, &payload_size);
    if (payload == NULL) {
      COAP_ERR("could not dispatch block");
      return COAP_RECEIVE_ERROR;
    }
    COAP_DBG("dispatching next block");
    const oc_blockwise_response_state_t *response_state =
      (oc_blockwise_response_state_t *)ctx->response_buffer;
    uint8_t more = (ctx->response_buffer->next_block_offset <
                    ctx->response_buffer->payload_size)
                     ? 1
                     : 0;
    if (more == 0) {
      if (ctx->message->type == COAP_TYPE_CON) {
        coap_send_empty_response(COAP_TYPE_ACK, ctx->message->mid, NULL, 0, 0,
                                 endpoint);
      }
      coap_udp_init_message(ctx->response, COAP_TYPE_CON,
                            (uint8_t)response_state->code, coap_get_mid());
      ctx->transaction->mid = ctx->response->mid;
      coap_options_set_accept(ctx->response, APPLICATION_VND_OCF_CBOR);
    }
    oc_content_format_t cf = APPLICATION_VND_OCF_CBOR;
    if (response_state->base.content_format > 0) {
      cf = response_state->base.content_format;
    }
    coap_options_set_content_format(ctx->response, cf);
    coap_set_payload(ctx->response, payload, payload_size);
    coap_options_set_block2(ctx->response, ctx->block2.num, more,
                            ctx->block2.size, 0);
    if (response_state->etag.length > 0) {
      coap_options_set_etag(ctx->response, response_state->etag.value,
                            response_state->etag.length);
    }
    ctx->response_buffer->ref_count = more;
    return COAP_RECEIVE_SUCCESS;
  }

  if (ctx->block2.num != 0) {
    COAP_ERR("initiating block-wise transfer with request for block_num > 0");
    return COAP_RECEIVE_ERROR;
  }

#if 0
  COAP_DBG(
    "requesting block-wise transfer; creating new block-wise response buffer");
  if (incoming_block_len == 0)
  {
    return COAP_RECEIVE_INVOKE_HANDLER;
  }
  ctx->request_buffer = oc_blockwise_find_request_buffer(
    href, href_len, endpoint, ctx->message->code, ctx->message->uri_query,
    ctx->message->uri_query_len, OC_BLOCKWISE_SERVER);

  if (ctx->request_buffer != NULL) {
    return COAP_RECEIVE_INVOKE_HANDLER;
  }

  uint32_t buffer_size;
  if (!coap_options_get_size2(ctx->message, &buffer_size) || buffer_size == 0) {
    buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
  }

  ctx->request_buffer = coap_receive_create_request_buffer(
    ctx->message, href, href_len, endpoint, buffer_size, incoming_block,
    incoming_block_len);
  if (ctx->request_buffer == NULL) {
    return COAP_RECEIVE_ERROR;
  }
#endif
  assert(incoming_block_len == 0);
  return COAP_RECEIVE_INVOKE_HANDLER;
}

static coap_receive_status_t
coap_receive_blockwise(coap_receive_ctx_t *ctx, const char *href,
                       size_t href_len, const oc_endpoint_t *endpoint)
{
  // block1 and block2 options are expected to be used with UDP protocol
  if (ctx->block1.enabled) {
    // block1 is expected only for POST/PUT requests
    if (ctx->message->code == COAP_POST || ctx->message->code == COAP_PUT) {
      return coap_receive_blockwise_block1(ctx, href, href_len, endpoint);
    }
    COAP_ERR("unexpected block1 option");
    return COAP_RECEIVE_ERROR;
  }
  // block2
  //   -> GET/FETCH requests from client
  //   -> POST/PUT responses from server
  return coap_receive_blockwise_block2(ctx, href, href_len, endpoint);
}

static coap_receive_status_t
coap_receive_method_payload(coap_receive_ctx_t *ctx, const char *href,
                            size_t href_len, const oc_endpoint_t *endpoint)
{
  assert(ctx->message->code >= COAP_GET && ctx->message->code <= COAP_DELETE);

  if (ctx->block1.enabled || ctx->block2.enabled) {
    return coap_receive_blockwise(ctx, href, href_len, endpoint);
  }
  COAP_DBG("no block options; processing regular request");

  if (!oc_main_initialized()) {
    COAP_DBG("cannot process new requests during shutdown iotivity-lite stack");
    return COAP_RECEIVE_ERROR;
  }

#ifdef OC_SECURITY
  // Drop unsecured (unicast/multicast) requests during reset the device.
  if (oc_reset_in_progress(endpoint->device) &&
      ((endpoint->flags & SECURED) == 0)) {
    COAP_WRN("cannot process new requests during reset the device");
    return COAP_RECEIVE_ERROR;
  }
#endif /* OC_SECURITY */

  const uint8_t *incoming_block;
  uint32_t incoming_block_len = coap_get_payload(ctx->message, &incoming_block);
#ifdef OC_TCP
  bool is_valid_size =
    ((endpoint->flags & TCP) != 0 &&
     incoming_block_len <= (uint32_t)OC_MAX_APP_DATA_SIZE) ||
    ((endpoint->flags & TCP) == 0 && incoming_block_len <= ctx->block1.size);
#else  /* !OC_TCP */
  bool is_valid_size = incoming_block_len <= ctx->block1.size;
#endif /* OC_TCP */
  if (!is_valid_size) {
    COAP_ERR("incoming payload size exceeds maximal size");
    return COAP_RECEIVE_ERROR;
  }

  if (incoming_block_len > 0) {
    COAP_DBG("creating request buffer");
    ctx->request_buffer = oc_blockwise_find_request_buffer(
      href, href_len, endpoint, ctx->message->code, ctx->message->uri_query,
      ctx->message->uri_query_len, OC_BLOCKWISE_SERVER);
    if (ctx->request_buffer != NULL) {
      oc_blockwise_free_request_buffer(ctx->request_buffer);
      ctx->request_buffer = NULL;
    }
    uint32_t buffer_size;
    if (!coap_options_get_size1(ctx->message, &buffer_size) ||
        buffer_size == 0) {
      buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
    }

    ctx->request_buffer = coap_receive_create_request_buffer(
      ctx->message, href, href_len, endpoint, buffer_size, incoming_block,
      incoming_block_len);
    if (ctx->request_buffer == NULL) {
      return COAP_RECEIVE_ERROR;
    }
    ctx->request_buffer->ref_count = 0;
  }

  ctx->response_buffer = oc_blockwise_find_response_buffer(
    href, href_len, endpoint, ctx->message->code, ctx->message->uri_query,
    ctx->message->uri_query_len, OC_BLOCKWISE_SERVER);
  if (ctx->response_buffer != NULL) {
    if ((endpoint->flags & MULTICAST) != 0 &&
        ctx->response_buffer->next_block_offset <
          ctx->response_buffer->payload_size) {
      COAP_DBG("dropping duplicate block-wise transfer request due to repeated "
               "multicast");
      coap_set_global_status_code(CLEAR_TRANSACTION);
      return COAP_RECEIVE_SUCCESS;
    }
    oc_blockwise_free_response_buffer(ctx->response_buffer);
    ctx->response_buffer = NULL;
  }
  return COAP_RECEIVE_INVOKE_HANDLER;
}

#endif /* OC_BLOCK_WISE */

static void
coap_send_response(coap_receive_ctx_t *ctx)
{
  if (coap_global_status_code() == CLEAR_TRANSACTION) {
    coap_clear_transaction(ctx->transaction);
    coap_set_global_status_code(COAP_NO_ERROR);
    return;
  }

  if (ctx->transaction == NULL) {
    COAP_DBG("skip sending of response: transaction is NULL");
    return;
  }

  if (ctx->response->type == COAP_TYPE_RST || ctx->message->token_len <= 0) {
    goto send_transaction;
  }

  if (ctx->message->code >= COAP_GET && ctx->message->code <= COAP_DELETE) {
    coap_set_token(ctx->response, ctx->message->token, ctx->message->token_len);
    goto send_transaction;
  }

#if defined(OC_CLIENT) && defined(OC_BLOCK_WISE)
  const oc_blockwise_response_state_t *b =
    (oc_blockwise_response_state_t *)ctx->response_buffer;
  if (b != NULL && b->observe_seq != OC_COAP_OPTION_OBSERVE_NOT_SET) {
    ctx->response->token_len = sizeof(ctx->response->token);
    oc_random_buffer(ctx->response->token, ctx->response->token_len);
    if (ctx->request_buffer != NULL) {
      memcpy(ctx->request_buffer->token, ctx->response->token,
             ctx->response->token_len);
      ctx->request_buffer->token_len = ctx->response->token_len;
    }
    memcpy(ctx->response_buffer->token, ctx->response->token,
           ctx->response->token_len);
    ctx->response_buffer->token_len = ctx->response->token_len;
  } else {
    coap_set_token(ctx->response, ctx->message->token, ctx->message->token_len);
  }
#endif /* OC_CLIENT && OC_BLOCK_WISE */

send_transaction:
  if (ctx->response->token_len > 0) {
    memcpy(ctx->transaction->token, ctx->response->token,
           ctx->response->token_len);
    ctx->transaction->token_len = ctx->response->token_len;
  }
  COAP_DBG(
    "data buffer from:%p to:%p", (void *)ctx->transaction->message->data,
    (void *)(ctx->transaction->message->data + oc_message_buffer_size()));
  ctx->transaction->message->length = coap_serialize_message(
    ctx->response, ctx->transaction->message->data, oc_message_buffer_size());
  if (ctx->transaction->message->length > 0) {
    coap_send_transaction(ctx->transaction);
  } else {
    coap_clear_transaction(ctx->transaction);
  }
}

static uint8_t
coap_receive_set_response_by_handler(coap_receive_ctx_t *ctx,
                                     oc_endpoint_t *endpoint,
                                     coap_make_response_fn_t response_fn,
                                     void *response_fn_data)
{
  coap_make_response_ctx_t handler_ctx;
  handler_ctx.request = ctx->message;
  handler_ctx.response = ctx->response;
#ifdef OC_BLOCK_WISE
  handler_ctx.request_state = &ctx->request_buffer;
  handler_ctx.response_state = &ctx->response_buffer;
  handler_ctx.block2_size = ctx->block2.size;
#else  /* !OC_BLOCK_WISE */
  handler_ctx.buffer = ctx->transaction->message->data + COAP_MAX_HEADER_SIZE;
#endif /* OC_BLOCK_WISE */
  if (!response_fn(&handler_ctx, endpoint, response_fn_data) ||
      (ctx->response->code == VALID_2_03)) {
#ifdef OC_BLOCK_WISE
    if (ctx->request_buffer != NULL) {
      ctx->request_buffer->ref_count = 0;
    }
    if (ctx->response_buffer != NULL) {
      ctx->response_buffer->ref_count = 0;
    }
#endif /* OC_BLOCK_WISE */
    return ctx->response->code;
  }

  ctx->response_buffer->content_format = ctx->response->content_format;
#ifdef OC_BLOCK_WISE
#ifdef OC_TCP
  if ((endpoint->flags & TCP) != 0) {
    uint32_t payload_size = 0;
    void *payload = oc_blockwise_dispatch_block(
      ctx->response_buffer, 0, ctx->response_buffer->payload_size + 1,
      &payload_size);
    if (payload && ctx->response_buffer->payload_size > 0) {
      coap_set_payload(ctx->response, payload, payload_size);
    }
#ifdef OC_HAS_FEATURE_ETAG
    const oc_blockwise_response_state_t *response_state =
      (oc_blockwise_response_state_t *)ctx->response_buffer;
    if (response_state->etag.length > 0) {
      coap_options_set_etag(ctx->response, response_state->etag.value,
                            response_state->etag.length);
    }
#endif /* OC_HAS_FEATURE_ETAG */
    ctx->response_buffer->ref_count = 0;
    return ctx->response->code;
  }
#endif /* OC_TCP */

  uint32_t payload_size = 0;
  void *payload = oc_blockwise_dispatch_block(ctx->response_buffer, 0,
                                              ctx->block2.size, &payload_size);
  if (payload != NULL) {
    coap_set_payload(ctx->response, payload, payload_size);
  }

  bool set_etag = true;
  if (ctx->block2.enabled ||
      ctx->response_buffer->payload_size > ctx->block2.size) {
    coap_options_set_block2(
      ctx->response, 0,
      (ctx->response_buffer->payload_size > ctx->block2.size) ? 1 : 0,
      ctx->block2.size, 0);
    coap_options_set_size2(ctx->response, ctx->response_buffer->payload_size);
  } else {
#ifndef OC_HAS_FEATURE_ETAG
    set_etag = false;
#endif /* !OC_HAS_FEATURE_ETAG */
    ctx->response_buffer->ref_count = 0;
  }
  if (set_etag) {
    const oc_blockwise_response_state_t *response_state =
      (oc_blockwise_response_state_t *)ctx->response_buffer;
    if (response_state->etag.length > 0) {
      coap_options_set_etag(ctx->response, response_state->etag.value,
                            response_state->etag.length);
    }
  }
#endif /* OC_BLOCK_WISE */
  return ctx->response->code;
}

static coap_receive_status_t
coap_receive_request_with_method(coap_receive_ctx_t *ctx,
                                 oc_endpoint_t *endpoint,
                                 coap_make_response_fn_t response_fn,
                                 void *response_fn_data)
{
#if OC_DBG_IS_ENABLED
  COAP_DBG("  method: %s", oc_method_to_str((oc_method_t)ctx->message->code));
  COAP_DBG("  URL: %.*s", (int)ctx->message->uri_path_len,
           ctx->message->uri_path);
  COAP_DBG("  QUERY: %.*s", (int)ctx->message->uri_query_len,
           ctx->message->uri_query);
  COAP_DBG("  Payload: %.*s", (int)ctx->message->payload_len,
           ctx->message->payload);
#endif /* OC_DBG_IS_ENABLED */
  const char *href;
  size_t href_len = coap_options_get_uri_path(ctx->message, &href);
  if (coap_receive_init_response(ctx->response, endpoint, ctx->message->type,
                                 ctx->message->mid, href, href_len) ==
      COAP_RECEIVE_SKIP_DUPLICATE_MESSAGE) {
    return COAP_RECEIVE_SKIP_DUPLICATE_MESSAGE;
  }

  /* create transaction for response */
  ctx->transaction =
    coap_new_transaction(ctx->response->mid, NULL, 0, endpoint);
  if (ctx->transaction == NULL) {
    COAP_ERR("could not allocate transaction");
    return COAP_RECEIVE_ERROR;
  }

#ifdef OC_BLOCK_WISE
  coap_receive_status_t ret =
    coap_receive_method_payload(ctx, href, href_len, endpoint);
  if (ret != COAP_RECEIVE_INVOKE_HANDLER) {
    return ret;
  }
#endif /* OC_BLOCK_WISE */
  if (coap_receive_set_response_by_handler(ctx, endpoint, response_fn,
                                           response_fn_data) != 0) {
    return COAP_RECEIVE_SUCCESS;
  }
  return COAP_RECEIVE_SEND_RESET_MESSAGE;
}

#ifdef OC_CLIENT

static coap_receive_status_t
coap_receive_invoke_client_cb(coap_receive_ctx_t *ctx, oc_endpoint_t *endpoint,
                              oc_client_cb_t *client_cb)
{
  COAP_DBG("calling oc_client_cb_invoke");
#ifdef OC_BLOCK_WISE
  if (ctx->request_buffer != NULL) {
    ctx->request_buffer->ref_count = 0;
  }

  oc_client_cb_invoke(ctx->message, &ctx->response_buffer, client_cb, endpoint);
  if (!oc_ri_is_client_cb_valid(client_cb)) {
    return COAP_RECEIVE_SUCCESS;
  }

  /* Do not free the response buffer in case of a separate response signal from
   * the server. In this case, the client_cb continues to live until the
   * response arrives (or it times out).
   */
  if (client_cb->separate == 0) {
    if (ctx->response_buffer) {
      ctx->response_buffer->ref_count = 0;
    }
  } else {
    client_cb->separate = 0;
  }

  return COAP_RECEIVE_SUCCESS;
#else  /* !OC_BLOCK_WISE */
  oc_client_cb_invoke(ctx->message, client_cb, endpoint);
  return COAP_RECEIVE_SEND_RESET_MESSAGE;
#endif /* OC_BLOCK_WISE */
}

#endif /* OC_CLIENT */

static coap_receive_status_t
coap_receive_request_with_code(coap_receive_ctx_t *ctx, oc_endpoint_t *endpoint)
{
  if (ctx->message->type == COAP_TYPE_CON) {
    coap_send_empty_response(COAP_TYPE_ACK, ctx->message->mid, NULL, 0, 0,
                             endpoint);
  }
#ifdef OC_SERVER
  else if (ctx->message->type == COAP_TYPE_RST) {
    /* cancel possible subscriptions */
    coap_remove_observer_by_mid(endpoint, ctx->message->mid);
  }
#endif /* OC_SERVER */

#ifdef OC_CLIENT
  oc_client_cb_t *client_cb = NULL;

#ifdef OC_BLOCK_WISE
  uint16_t response_mid = coap_get_mid();
  bool error_response = false;
#endif /* OC_BLOCK_WISE */
  if (ctx->message->type != COAP_TYPE_RST) {
    client_cb = oc_ri_find_client_cb_by_token(ctx->message->token,
                                              ctx->message->token_len);
#ifdef OC_BLOCK_WISE
    if (ctx->message->code >= BAD_REQUEST_4_00 &&
        ctx->message->code != REQUEST_ENTITY_TOO_LARGE_4_13) {
      error_response = true;
    }
#endif /* OC_BLOCK_WISE */
  }

#ifdef OC_BLOCK_WISE
  if (client_cb != NULL) {
    ctx->request_buffer =
      oc_blockwise_find_request_buffer_by_client_cb(endpoint, client_cb);
  } else {
    ctx->request_buffer =
      oc_blockwise_find_request_buffer_by_mid(ctx->message->mid);
    if (!ctx->request_buffer) {
      ctx->request_buffer = oc_blockwise_find_request_buffer_by_token(
        ctx->message->token, ctx->message->token_len);
    }
  }

  if (!error_response && ctx->request_buffer != NULL &&
      (ctx->block1.enabled ||
       ctx->message->code == REQUEST_ENTITY_TOO_LARGE_4_13)) {
    COAP_DBG("found request buffer for uri %s",
             oc_string(ctx->request_buffer->href));
    client_cb = (oc_client_cb_t *)ctx->request_buffer->client_cb;
    uint32_t payload_size = 0;
    void *payload = NULL;

    if (ctx->block1.enabled) {
      payload = oc_blockwise_dispatch_block(
        ctx->request_buffer, ctx->block1.offset + ctx->block1.size,
        ctx->block1.size, &payload_size);
    } else {
      COAP_DBG("initiating block-wise transfer with block1 option");
      uint32_t peer_mtu = 0;
      if (coap_options_get_size1(ctx->message, &peer_mtu) == 1) {
        ctx->block1.size = MIN((uint16_t)peer_mtu, (uint16_t)OC_BLOCK_SIZE);
      } else {
        ctx->block1.size = (uint16_t)OC_BLOCK_SIZE;
      }
      payload = oc_blockwise_dispatch_block(ctx->request_buffer, 0,
                                            ctx->block1.size, &payload_size);
      ctx->request_buffer->ref_count = 1;
    }

    if (payload != NULL) {
      COAP_DBG("dispatching next block");
      ctx->transaction = coap_new_transaction(response_mid, NULL, 0, endpoint);
      if (ctx->transaction != NULL) {
        coap_udp_init_message(ctx->response, COAP_TYPE_CON,
                              (uint8_t)client_cb->method, response_mid);
        uint8_t more = (ctx->request_buffer->next_block_offset <
                        ctx->request_buffer->payload_size)
                         ? 1
                         : 0;
        coap_options_set_uri_path(ctx->response, oc_string(client_cb->uri),
                                  oc_string_len(client_cb->uri));
        coap_set_payload(ctx->response, payload, payload_size);
        if (ctx->block1.enabled) {
          coap_options_set_block1(ctx->response, ctx->block1.num + 1, more,
                                  ctx->block1.size, 0);
        } else {
          coap_options_set_block1(ctx->response, 0, more, ctx->block1.size, 0);
          coap_options_set_size1(ctx->response,
                                 ctx->request_buffer->payload_size);
        }
        if (oc_string_len(client_cb->query) > 0) {
          coap_options_set_uri_query(ctx->response, oc_string(client_cb->query),
                                     oc_string_len(client_cb->query));
        }
        coap_options_set_accept(ctx->response, APPLICATION_VND_OCF_CBOR);
        coap_options_set_content_format(ctx->response,
                                        APPLICATION_VND_OCF_CBOR);
        ctx->request_buffer->mid = response_mid;
        return COAP_RECEIVE_SUCCESS;
      }
    } else {
      ctx->request_buffer->ref_count = 0;
    }
  }

  if (ctx->request_buffer != NULL &&
      (ctx->request_buffer->ref_count == 0 || error_response)) {
    oc_blockwise_free_request_buffer(ctx->request_buffer);
    ctx->request_buffer = NULL;
  }

  if (client_cb != NULL) {
    ctx->response_buffer =
      oc_blockwise_find_response_buffer_by_client_cb(endpoint, client_cb);
    if (ctx->response_buffer == NULL) {
      uint32_t buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
      ctx->response_buffer = oc_blockwise_alloc_response_buffer(
        oc_string(client_cb->uri) + 1, oc_string_len(client_cb->uri) - 1,
        endpoint, client_cb->method, OC_BLOCKWISE_CLIENT, buffer_size,
        CONTENT_2_05, false);
      if (ctx->response_buffer != NULL) {
        COAP_DBG("created new response buffer for uri %s",
                 oc_string(ctx->response_buffer->href));
        ctx->response_buffer->client_cb = client_cb;
      }
    }
  } else {
    ctx->response_buffer =
      oc_blockwise_find_response_buffer_by_mid(ctx->message->mid);
    if (ctx->response_buffer == NULL) {
      ctx->response_buffer = oc_blockwise_find_response_buffer_by_token(
        ctx->message->token, ctx->message->token_len);
    }
  }

  if (!error_response && ctx->response_buffer != NULL) {
    COAP_DBG("got response buffer for uri %s",
             oc_string(ctx->response_buffer->href));
    client_cb = (oc_client_cb_t *)ctx->response_buffer->client_cb;
    oc_blockwise_response_state_t *response_state =
      (oc_blockwise_response_state_t *)ctx->response_buffer;
    coap_options_get_observe(ctx->message, &response_state->observe_seq);

    const uint8_t *incoming_block;
    uint32_t incoming_block_len =
      coap_get_payload(ctx->message, &incoming_block);
    if (incoming_block_len > 0 &&
        oc_blockwise_handle_block(ctx->response_buffer, ctx->block2.offset,
                                  incoming_block,
                                  (uint32_t)incoming_block_len)) {
      COAP_DBG("processing incoming block");
      if (ctx->block2.enabled && ctx->block2.more) {
        COAP_DBG("issuing request for next block");
        ctx->transaction =
          coap_new_transaction(response_mid, NULL, 0, endpoint);
        if (ctx->transaction != NULL) {
          coap_udp_init_message(ctx->response, COAP_TYPE_CON,
                                (uint8_t)client_cb->method, response_mid);
          ctx->response_buffer->mid = response_mid;
          client_cb->mid = response_mid;
          coap_options_set_accept(ctx->response, APPLICATION_VND_OCF_CBOR);
          coap_options_set_block2(ctx->response, ctx->block2.num + 1, 0,
                                  ctx->block2.size, 0);
          coap_options_set_uri_path(ctx->response, oc_string(client_cb->uri),
                                    oc_string_len(client_cb->uri));
          if (oc_string_len(client_cb->query) > 0) {
            coap_options_set_uri_query(ctx->response,
                                       oc_string(client_cb->query),
                                       oc_string_len(client_cb->query));
          }
          return COAP_RECEIVE_SUCCESS;
        }
      }
      ctx->response_buffer->payload_size =
        ctx->response_buffer->next_block_offset;
    }
  }

#endif /* OC_BLOCK_WISE */

  if (client_cb != NULL) {
    return coap_receive_invoke_client_cb(ctx, endpoint, client_cb);
  }
#endif /* OC_CLIENT */
  return COAP_RECEIVE_SEND_RESET_MESSAGE;
}

coap_receive_status_t
coap_receive(coap_receive_ctx_t *ctx, oc_endpoint_t *endpoint,
             coap_make_response_fn_t response_fn, void *response_fn_data)
{
  /* handle requests */
  if (ctx->message->code >= COAP_GET && ctx->message->code <= COAP_DELETE) {
    return coap_receive_request_with_method(ctx, endpoint, response_fn,
                                            response_fn_data);
  }
  return coap_receive_request_with_code(ctx, endpoint);
}

static coap_status_t
coap_parse_inbound_message(coap_packet_t *packet, oc_message_t *msg)
{
#ifdef OC_TCP
  if ((msg->endpoint.flags & TCP) != 0) {
    return coap_tcp_parse_message(packet, msg->data, msg->length, false);
  }
#endif /* OC_TCP */
  return coap_udp_parse_message(packet, msg->data, msg->length, false);
}

static void
coap_process_invalid_inbound_message(const coap_packet_t *packet,
                                     const oc_message_t *msg,
                                     coap_status_t status)
{
#ifdef OC_SECURITY
  coap_audit_log(msg);
#endif /* OC_SECURITY */
#ifdef OC_TCP
  if ((msg->endpoint.flags & TCP) != 0) {
    oc_connectivity_end_session(&msg->endpoint);
    return;
  }
#endif /* OC_TCP */
  coap_send_empty_response(
    packet->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON, packet->mid,
    packet->token, packet->token_len, (uint8_t)status, &msg->endpoint);
}

coap_status_t
coap_process_inbound_message(oc_message_t *msg)
{
  COAP_DBG("CoAP Engine: received datalen=%u from", (unsigned int)msg->length);
  COAP_LOGipaddr(msg->endpoint);
  COAP_LOGbytes(msg->data, msg->length);

  /* static declarations reduce stack peaks and program code size */
  static coap_packet_t message;
  static coap_packet_t response;
  static coap_receive_ctx_t ctx;

  coap_status_t status = coap_parse_inbound_message(&message, msg);
  coap_set_global_status_code(status);

  if (status != COAP_NO_ERROR) {
    coap_process_invalid_inbound_message(&message, msg, status);
    return status;
  }

#ifdef OC_TCP
  if ((msg->endpoint.flags & TCP) == 0)
#endif /* OC_TCP */
  {
    coap_transaction_t *transaction = coap_get_transaction_by_mid(message.mid);
    if (transaction != NULL) {
      coap_clear_transaction(transaction);
    }
  }

#if OC_DBG_IS_ENABLED
  coap_packet_log_message(&message);
#endif /* OC_DBG_IS_ENABLED */

#ifdef OC_TCP
  if (coap_check_signal_message(message.code) &&
      coap_signal_handle_message(&message, &msg->endpoint) ==
        COAP_SIGNAL_DONE) {
    return COAP_NO_ERROR;
  }
#endif /* OC_TCP */

  coap_receive_status_t ret;
  /* extract block options */
  coap_block_options_t block1 = coap_packet_get_block_options(&message, false);
  coap_block_options_t block2 = coap_packet_get_block_options(&message, true);
#ifdef OC_BLOCK_WISE
#ifdef OC_TCP
  if ((msg->endpoint.flags & TCP) != 0 && (block1.enabled || block2.enabled)) {
    COAP_ERR(
      "block options received but block-wise transfer not supported over TCP");
    ret = COAP_RECEIVE_ERROR;
    goto receive_result;
  }
#endif /* OC_TCP */
#else  /* !OC_BLOCK_WISE */
  if (block1.enabled || block2.enabled) {
    COAP_ERR("block options received but block-wise transfer not supported");
    ret = COAP_RECEIVE_ERROR;
    goto receive_result;
  }
#endif /* OC_BLOCK_WISE */

  ctx = (coap_receive_ctx_t){
    .message = &message,
    .response = &response,
    .transaction = NULL,
#ifdef OC_BLOCK_WISE
    .block1 = block1,
    .block2 = block2,
    .request_buffer = NULL,
    .response_buffer = NULL,
#endif /* OC_BLOCK_WISE */
  };

  ret =
    coap_receive(&ctx, &msg->endpoint, oc_ri_invoke_coap_entity_handler, NULL);

#if !defined(OC_BLOCK_WISE) || defined(OC_TCP)
receive_result:
#endif /* !OC_BLOCK_WISE || OC_TCP */
  if (ret < 0 || ret == COAP_RECEIVE_SEND_RESET_MESSAGE) {
#ifdef OC_BLOCK_WISE
    if (ctx.request_buffer != NULL) {
      ctx.request_buffer->ref_count = 0;
    }
    if (ctx.response_buffer != NULL) {
      ctx.response_buffer->ref_count = 0;
    }
#endif /* OC_BLOCK_WISE */
#ifdef OC_TCP
    if ((msg->endpoint.flags & TCP) != 0) {
      coap_tcp_init_message(ctx.response, INTERNAL_SERVER_ERROR_5_00);
    } else
#endif /* OC_TCP */
    {
      coap_udp_init_message(ctx.response, COAP_TYPE_RST, 0, ctx.message->mid);
    }
  }
  if (ret == COAP_RECEIVE_SKIP_DUPLICATE_MESSAGE) {
    return COAP_NO_ERROR;
  }

  coap_send_response(&ctx);

#ifdef OC_BLOCK_WISE
  oc_blockwise_free_all_buffers(false);
#endif /* OC_BLOCK_WISE */

  return coap_global_status_code();
}

OC_PROCESS_THREAD(g_coap_engine, ev, data)
{
  OC_PROCESS_BEGIN();

  coap_register_as_transaction_handler();
  coap_init_connection();

  while (oc_process_is_running(&g_coap_engine)) {
    OC_PROCESS_YIELD();

    if (ev == oc_event_to_oc_process_event(INBOUND_RI_EVENT)) {
      oc_message_t *msg = (oc_message_t *)data;
      coap_status_t ret = coap_process_inbound_message(msg);
      if (ret != COAP_NO_ERROR) {
        COAP_WRN("CoAP Engine: Error processing request (%d)", (int)ret);
      }

      oc_message_unref(msg);
    } else if (ev == OC_PROCESS_EVENT_TIMER) {
      coap_check_transactions();
    }
  }

  OC_PROCESS_END();
}
