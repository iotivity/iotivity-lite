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

#include "engine.h"

#include "api/oc_buffer_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_main_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/coap_options.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "util/oc_macros_internal.h"

#ifdef OC_SECURITY
#include "security/oc_audit.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
#include "api/client/oc_client_cb_internal.h"
#include "oc_client_state.h"
#endif /* OC_CLIENT */

#ifdef OC_TCP
#include "coap_signal.h"
#endif

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

bool
oc_coap_check_if_duplicate(uint16_t mid, uint32_t device)
{
  for (size_t i = 0; i < OC_REQUEST_HISTORY_SIZE; i++) {
    if (g_history[i] == mid && g_history_dev[i] == device) {
      OC_DBG("dropping duplicate request");
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
  OC_DBG("CoAP send empty message: mid=%u, code=%u", mid, code);
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

typedef struct
{
  uint32_t num;
  uint32_t offset;
  uint16_t size;
  uint8_t more;
  bool enabled;
} coap_block_options_t;

static coap_block_options_t
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
  OC_DBG("  Parsed: CoAP version: %u, token: 0x%02X%02X, mid: %u",
         message->version, message->token[0], message->token[1], message->mid);
  if (message->type == COAP_TYPE_CON) {
    OC_DBG("  type: CON");
  } else if (message->type == COAP_TYPE_NON) {
    OC_DBG("  type: NON");
  } else if (message->type == COAP_TYPE_ACK) {
    OC_DBG("  type: ACK");
  } else if (message->type == COAP_TYPE_RST) {
    OC_DBG("  type: RST");
  }
}

#endif /* OC_DBG_IS_ENABLED */

enum {
  COAP_SUCCESS = 0,
  COAP_SKIP_DUPLICATE_MESSAGE,
  COAP_SEND_MESSAGE,
  COAP_SEND_RESET_MESSAGE,
};

static int
coap_receive_init_response(coap_packet_t *response,
                           const oc_endpoint_t *endpoint,
                           coap_message_type_t type, uint16_t mid,
                           const char *href, size_t href_len)
{
#ifdef OC_TCP
  if ((endpoint->flags & TCP) != 0) {
    coap_tcp_init_message(response, CONTENT_2_05);
    return COAP_SUCCESS;
  }
#endif /* OC_TCP */

  if (type == COAP_TYPE_CON) {
    coap_udp_init_message(response, COAP_TYPE_ACK, CONTENT_2_05, mid);
  } else {
#ifdef OC_REQUEST_HISTORY
    if (oc_coap_check_if_duplicate(mid, (uint32_t)endpoint->device)) {
      return COAP_SKIP_DUPLICATE_MESSAGE;
    }
    g_history[g_idx] = mid;
    g_history_dev[g_idx] = (uint32_t)endpoint->device;
    g_idx = (g_idx + 1) % OC_REQUEST_HISTORY_SIZE;
#endif /* OC_REQUEST_HISTORY */
    coap_message_type_t reponse_type =
      (href_len == OC_CHAR_ARRAY_LEN("oic/res") &&
       memcmp(href, "oic/res", href_len) == 0)
        ? COAP_TYPE_CON
        : COAP_TYPE_NON;
    coap_udp_init_message(response, reponse_type, CONTENT_2_05, coap_get_mid());
  }
  return COAP_SUCCESS;
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
    OC_ERR("could not create buffer to hold request payload");
    return NULL;
  }
  if (!oc_blockwise_handle_block(request_buffer, 0, incoming_block,
                                 (uint16_t)incoming_block_len)) {
    OC_ERR("could not process incoming block");
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

typedef struct
{
  const coap_packet_t *request;
  oc_blockwise_state_t *request_buffer;
  coap_packet_t *response;
  oc_blockwise_state_t *response_buffer;
  coap_transaction_t *transaction;
  coap_block_options_t block1;
  coap_block_options_t block2;
} coap_receive_blockwise_ctx_t;

static int
coap_receive_blockwise(coap_receive_blockwise_ctx_t *ctx, const char *href,
                       size_t href_len, const oc_endpoint_t *endpoint)
{
  const uint8_t *incoming_block;
  uint32_t incoming_block_len = coap_get_payload(ctx->request, &incoming_block);

  if (ctx->block1.enabled) {
    OC_DBG("processing block1 option");
    ctx->request_buffer = oc_blockwise_find_request_buffer(
      href, href_len, endpoint, ctx->request->code, ctx->request->uri_query,
      ctx->request->uri_query_len, OC_BLOCKWISE_SERVER);

    if (ctx->request_buffer != NULL &&
        ctx->request_buffer->payload_size ==
          ctx->request_buffer->next_block_offset &&
        (ctx->request_buffer->next_block_offset - incoming_block_len) !=
          ctx->block1.offset) {
      oc_blockwise_free_request_buffer(ctx->request_buffer);
      ctx->request_buffer = NULL;
    }

    if (ctx->request_buffer == NULL && ctx->block1.num == 0) {
      if (oc_drop_command(endpoint->device) && ctx->request->code >= COAP_GET &&
          ctx->request->code <= COAP_DELETE) {
        OC_WRN("cannot process new request during closing TLS sessions");
        return COAP_SEND_RESET_MESSAGE;
      }

      uint32_t buffer_size;
      if (!coap_options_get_size1(ctx->request, &buffer_size) ||
          buffer_size == 0) {
        buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
      }
      OC_DBG("creating new block-wise request buffer");
      ctx->request_buffer = oc_blockwise_alloc_request_buffer(
        href, href_len, endpoint, ctx->request->code, OC_BLOCKWISE_SERVER,
        buffer_size);

      if (ctx->request_buffer != NULL && ctx->request->uri_query_len > 0) {
        oc_new_string(&ctx->request_buffer->uri_query, ctx->request->uri_query,
                      ctx->request->uri_query_len);
      }
    }

    if (ctx->request_buffer == NULL) {
      OC_ERR("could not create block-wise request buffer");
      return COAP_SEND_RESET_MESSAGE;
    }

    OC_DBG("processing incoming block");
    if (!oc_blockwise_handle_block(
          ctx->request_buffer, ctx->block1.offset, incoming_block,
          MIN((uint16_t)incoming_block_len, ctx->block1.size))) {
      OC_ERR("could not process incoming block");
      return COAP_SEND_RESET_MESSAGE;
    }

    if (ctx->block1.more) {
      OC_DBG("more blocks expected; issuing request for the next block");
      ctx->response->code = CONTINUE_2_31;
      coap_options_set_block1(ctx->response, ctx->block1.num, ctx->block1.more,
                              ctx->block1.size, 0);
      ctx->request_buffer->ref_count = 1;
      return COAP_SEND_MESSAGE;
    }

    OC_DBG("received all blocks for payload");
    if (ctx->request->type == COAP_TYPE_CON) {
      coap_send_empty_response(COAP_TYPE_ACK, ctx->request->mid, /*token*/ NULL,
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
    return COAP_SUCCESS;
  }

  if (ctx->block2.enabled) {
    OC_DBG("processing block2 option");
    ctx->response_buffer = oc_blockwise_find_response_buffer(
      href, href_len, endpoint, ctx->request->code, ctx->request->uri_query,
      ctx->request->uri_query_len, OC_BLOCKWISE_SERVER);

    if (ctx->response_buffer != NULL) {
      if ((ctx->response_buffer->next_block_offset - ctx->block2.offset) >
          ctx->block2.size) {
        // UDP transfer can duplicate messages and we want to avoid terminate
        // BWT, so we drop the message.
        OC_DBG(
          "dropped message because message was already provided for block2");
        coap_clear_transaction(ctx->transaction);
        return COAP_SKIP_DUPLICATE_MESSAGE;
      }

      OC_DBG("continuing ongoing block-wise transfer");
      uint32_t payload_size = 0;
      void *payload =
        oc_blockwise_dispatch_block(ctx->response_buffer, ctx->block2.offset,
                                    ctx->block2.size, &payload_size);
      if (payload == NULL) {
        OC_ERR("could not dispatch block");
        return COAP_SEND_RESET_MESSAGE;
      }
      OC_DBG("dispatching next block");
      uint8_t more = (ctx->response_buffer->next_block_offset <
                      ctx->response_buffer->payload_size)
                       ? 1
                       : 0;
      if (more == 0) {
        if (ctx->request->type == COAP_TYPE_CON) {
          coap_send_empty_response(COAP_TYPE_ACK, ctx->request->mid, NULL, 0, 0,
                                   endpoint);
        }
        coap_udp_init_message(ctx->response, COAP_TYPE_CON, CONTENT_2_05,
                              coap_get_mid());
        ctx->transaction->mid = ctx->response->mid;
        coap_options_set_accept(ctx->response, APPLICATION_VND_OCF_CBOR);
      }
      coap_options_set_content_format(ctx->response, APPLICATION_VND_OCF_CBOR);
      coap_set_payload(ctx->response, payload, payload_size);
      coap_options_set_block2(ctx->response, ctx->block2.num, more,
                              ctx->block2.size, 0);
      const oc_blockwise_response_state_t *response_state =
        (oc_blockwise_response_state_t *)ctx->response_buffer;
      coap_options_set_etag(ctx->response, response_state->etag, COAP_ETAG_LEN);
      ctx->response_buffer->ref_count = more;
      return COAP_SEND_MESSAGE;
    }

    OC_DBG("requesting block-wise transfer; creating new block-wise response "
           "buffer");
    if (ctx->block2.num != 0) {
      OC_ERR("initiating block-wise transfer with request for block_num > 0");
      return COAP_SEND_RESET_MESSAGE;
    }

    if (incoming_block_len == 0) {
      return COAP_SUCCESS;
    }
    ctx->request_buffer = oc_blockwise_find_request_buffer(
      href, href_len, endpoint, ctx->request->code, ctx->request->uri_query,
      ctx->request->uri_query_len, OC_BLOCKWISE_SERVER);

    if (ctx->request_buffer != NULL) {
      return COAP_SUCCESS;
    }

    if (oc_drop_command(endpoint->device) && ctx->request->code >= COAP_GET &&
        ctx->request->code <= COAP_DELETE) {
      OC_WRN("cannot process new request during closing TLS sessions");
      return COAP_SEND_RESET_MESSAGE;
    }

    uint32_t buffer_size;
    if (!coap_options_get_size2(ctx->request, &buffer_size) ||
        buffer_size == 0) {
      buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
    }

    ctx->request_buffer = coap_receive_create_request_buffer(
      ctx->request, href, href_len, endpoint, buffer_size, incoming_block,
      incoming_block_len);
    if (ctx->request_buffer == NULL) {
      return COAP_SEND_RESET_MESSAGE;
    }
    return COAP_SUCCESS;
  }

  OC_DBG("no block options; processing regular request");
  if (oc_drop_command(endpoint->device) && ctx->request->code >= COAP_GET &&
      ctx->request->code <= COAP_DELETE) {
    OC_WRN("cannot process new request during closing TLS sessions");
    return COAP_SEND_RESET_MESSAGE;
  }

#ifdef OC_TCP
  bool is_valid_size =
    ((endpoint->flags & TCP) != 0 &&
     incoming_block_len <= (uint32_t)OC_MAX_APP_DATA_SIZE) ||
    ((endpoint->flags & TCP) == 0 && incoming_block_len <= ctx->block1.size);
#else  /* !OC_TCP */
  bool is_valid_size = incoming_block_len <= ctx->block1.size;
#endif /* OC_TCP */
  if (!is_valid_size) {
    OC_ERR("incoming payload size exceeds block size");
    return COAP_SEND_RESET_MESSAGE;
  }

  if (incoming_block_len > 0) {
    OC_DBG("creating request buffer");
    ctx->request_buffer = oc_blockwise_find_request_buffer(
      href, href_len, endpoint, ctx->request->code, ctx->request->uri_query,
      ctx->request->uri_query_len, OC_BLOCKWISE_SERVER);
    if (ctx->request_buffer != NULL) {
      oc_blockwise_free_request_buffer(ctx->request_buffer);
      ctx->request_buffer = NULL;
    }
    uint32_t buffer_size;
    if (!coap_options_get_size1(ctx->request, &buffer_size) ||
        buffer_size == 0) {
      buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
    }

    ctx->request_buffer = coap_receive_create_request_buffer(
      ctx->request, href, href_len, endpoint, buffer_size, incoming_block,
      incoming_block_len);
    if (ctx->request_buffer == NULL) {
      return COAP_SEND_RESET_MESSAGE;
    }
    ctx->request_buffer->ref_count = 0;
  }

  ctx->response_buffer = oc_blockwise_find_response_buffer(
    href, href_len, endpoint, ctx->request->code, ctx->request->uri_query,
    ctx->request->uri_query_len, OC_BLOCKWISE_SERVER);
  if (ctx->response_buffer != NULL) {
    if ((endpoint->flags & MULTICAST) != 0 &&
        ctx->response_buffer->next_block_offset <
          ctx->response_buffer->payload_size) {
      OC_DBG("Dropping duplicate block-wise transfer request due to repeated "
             "multicast");
      coap_set_global_status_code(CLEAR_TRANSACTION);
      return COAP_SEND_MESSAGE;
    }
    oc_blockwise_free_response_buffer(ctx->response_buffer);
    ctx->response_buffer = NULL;
  }
  return COAP_SUCCESS;
}

#endif /* OC_BLOCK_WISE */

int
coap_receive(oc_message_t *msg)
{
  coap_set_global_status_code(COAP_NO_ERROR);

  OC_DBG("CoAP Engine: received datalen=%u from", (unsigned int)msg->length);
  OC_LOGipaddr(msg->endpoint);
  OC_LOGbytes(msg->data, msg->length);

  /* static declaration reduces stack peaks and program code size */
  static coap_packet_t
    message[1]; /* this way the packet can be treated as pointer as usual */
  static coap_packet_t response[1];
  static coap_transaction_t *transaction;
  transaction = NULL;

#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *request_buffer = NULL;
  oc_blockwise_state_t *response_buffer = NULL;
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
  oc_client_cb_t *client_cb = NULL;
#endif /* OC_CLIENT */

  coap_status_t status;
#ifdef OC_TCP
  if (msg->endpoint.flags & TCP) {
    status = coap_tcp_parse_message(message, msg->data, msg->length, false);
  } else
#endif /* OC_TCP */
  {
    status = coap_udp_parse_message(message, msg->data, msg->length, false);
  }
  coap_set_global_status_code(status);

  if (status != COAP_NO_ERROR) {
    OC_ERR("Unexpected CoAP command");
#ifdef OC_SECURITY
    coap_audit_log(msg);
#endif /* OC_SECURITY */
#ifdef OC_TCP
    if ((msg->endpoint.flags & TCP) != 0) {
      coap_send_empty_response(COAP_TYPE_NON, 0, message->token,
                               message->token_len, (uint8_t)status,
                               &msg->endpoint);
      return status;
    }
#endif /* OC_TCP */
    coap_send_empty_response(message->type == COAP_TYPE_CON ? COAP_TYPE_ACK
                                                            : COAP_TYPE_NON,
                             message->mid, message->token, message->token_len,
                             (uint8_t)status, &msg->endpoint);

    return status;
  }

#if OC_DBG_IS_ENABLED
  coap_packet_log_message(message);
#endif /* OC_DBG_IS_ENABLED */

#ifdef OC_TCP
  if (coap_check_signal_message(message)) {
    status = handle_coap_signal_message(message, &msg->endpoint);
    coap_set_global_status_code(status);
  }
#endif /* OC_TCP */

  /* extract block options */
  coap_block_options_t block1 = coap_packet_get_block_options(message, false);
  coap_block_options_t block2 = coap_packet_get_block_options(message, true);

#ifdef OC_TCP
  if ((msg->endpoint.flags & TCP) == 0)
#endif /* OC_TCP */
  {
    transaction = coap_get_transaction_by_mid(message->mid);
    if (transaction != NULL) {
      coap_clear_transaction(transaction);
    }
    transaction = NULL;
  }

  /* handle requests */
  if (message->code >= COAP_GET && message->code <= COAP_DELETE) {
#if OC_DBG_IS_ENABLED
    OC_DBG("  method: %s", oc_method_to_str((oc_method_t)message->code));
    OC_DBG("  URL: %.*s", (int)message->uri_path_len, message->uri_path);
    OC_DBG("  QUERY: %.*s", (int)message->uri_query_len, message->uri_query);
    OC_DBG("  Payload: %.*s", (int)message->payload_len, message->payload);
#endif /* OC_DBG_IS_ENABLED */
    const char *href;
    size_t href_len = coap_options_get_uri_path(message, &href);
    if (coap_receive_init_response(response, &msg->endpoint, message->type,
                                   message->mid, href,
                                   href_len) == COAP_SKIP_DUPLICATE_MESSAGE) {
      return 0;
    }

    /* create transaction for response */
    transaction = coap_new_transaction(response->mid, NULL, 0, &msg->endpoint);
    if (transaction == NULL) {
      goto init_reset_message;
    }

#ifdef OC_BLOCK_WISE
    coap_receive_blockwise_ctx_t bwt_ctx = {
      .request = message,
      .request_buffer = request_buffer,
      .response = response,
      .response_buffer = response_buffer,
      .transaction = transaction,
      .block1 = block1,
      .block2 = block2,
    };
    int bwt_ret =
      coap_receive_blockwise(&bwt_ctx, href, href_len, &msg->endpoint);
    request_buffer = bwt_ctx.request_buffer;
    response_buffer = bwt_ctx.response_buffer;
    if (bwt_ret == COAP_SEND_MESSAGE) {
      goto send_message;
    } else if (bwt_ret == COAP_SEND_RESET_MESSAGE) {
      goto init_reset_message;
    } else if (bwt_ret == COAP_SKIP_DUPLICATE_MESSAGE) {
      return 0;
    }
#else  /* OC_BLOCK_WISE */
    if (block1.enabled || block2.enabled) {
      goto init_reset_message;
    }
#endif /* !OC_BLOCK_WISE */

    oc_ri_invoke_coap_entity_handler_ctx_t handler_ctx;
#ifdef OC_BLOCK_WISE
    handler_ctx.request_state = &request_buffer;
    handler_ctx.response_state = &response_buffer;
    handler_ctx.block2_size = block2.size;
#else  /* !OC_BLOCK_WISE */
    handler_ctx.buffer = transaction->message->data + COAP_MAX_HEADER_SIZE;
#endif /* OC_BLOCK_WISE */
    if (oc_ri_invoke_coap_entity_handler(message, response, &msg->endpoint,
                                         handler_ctx) &&
        (response->code != VALID_2_03)) {
#ifdef OC_BLOCK_WISE
      uint32_t payload_size = 0;
#ifdef OC_TCP
      if (msg->endpoint.flags & TCP) {
        void *payload = oc_blockwise_dispatch_block(
          response_buffer, 0, response_buffer->payload_size + 1, &payload_size);
        if (payload && response_buffer->payload_size > 0) {
          coap_set_payload(response, payload, payload_size);
        }
        response_buffer->ref_count = 0;
      } else {
#endif /* OC_TCP */
        void *payload = oc_blockwise_dispatch_block(response_buffer, 0,
                                                    block2.size, &payload_size);
        if (payload) {
          coap_set_payload(response, payload, payload_size);
        }
        if (block2.enabled || response_buffer->payload_size > block2.size) {
          coap_options_set_block2(
            response, 0, (response_buffer->payload_size > block2.size) ? 1 : 0,
            block2.size, 0);
          coap_options_set_size2(response, response_buffer->payload_size);
          oc_blockwise_response_state_t *response_state =
            (oc_blockwise_response_state_t *)response_buffer;
          coap_options_set_etag(response, response_state->etag, COAP_ETAG_LEN);
        } else {
          response_buffer->ref_count = 0;
        }
#ifdef OC_TCP
      }
#endif /* OC_TCP */
#endif /* OC_BLOCK_WISE */
    }
#ifdef OC_BLOCK_WISE
    else {
      if (request_buffer) {
        request_buffer->ref_count = 0;
      }
      if (response_buffer) {
        response_buffer->ref_count = 0;
      }
    }
#endif /* OC_BLOCK_WISE */
    if (response->code != 0) {
      goto send_message;
    }
  } else {
#ifdef OC_CLIENT
#ifdef OC_BLOCK_WISE
    uint16_t response_mid = coap_get_mid();
    bool error_response = false;
#endif /* OC_BLOCK_WISE */
    if (message->type != COAP_TYPE_RST) {
      client_cb =
        oc_ri_find_client_cb_by_token(message->token, message->token_len);
#ifdef OC_BLOCK_WISE
      if (message->code >= BAD_REQUEST_4_00 &&
          message->code != REQUEST_ENTITY_TOO_LARGE_4_13) {
        error_response = true;
      }
#endif /* OC_BLOCK_WISE */
    }
#endif /* OC_CLIENT */

    if (message->type == COAP_TYPE_CON) {
      coap_send_empty_response(COAP_TYPE_ACK, message->mid, NULL, 0, 0,
                               &msg->endpoint);
    }
#ifdef OC_SERVER
    else if (message->type == COAP_TYPE_RST) {
      /* cancel possible subscriptions */
      coap_remove_observer_by_mid(&msg->endpoint, message->mid);
    }
#endif

#ifdef OC_CLIENT
#ifdef OC_BLOCK_WISE
    if (client_cb) {
      request_buffer = oc_blockwise_find_request_buffer_by_client_cb(
        &msg->endpoint, client_cb);
    } else {
      request_buffer = oc_blockwise_find_request_buffer_by_mid(message->mid);
      if (!request_buffer) {
        request_buffer = oc_blockwise_find_request_buffer_by_token(
          message->token, message->token_len);
      }
    }
    if (!error_response && request_buffer &&
        (block1.enabled || message->code == REQUEST_ENTITY_TOO_LARGE_4_13)) {
      OC_DBG("found request buffer for uri %s",
             oc_string(request_buffer->href));
      client_cb = (oc_client_cb_t *)request_buffer->client_cb;
      uint32_t payload_size = 0;
      void *payload = NULL;

      if (block1.enabled) {
        payload = oc_blockwise_dispatch_block(request_buffer,
                                              block1.offset + block1.size,
                                              block1.size, &payload_size);
      } else {
        OC_DBG("initiating block-wise transfer with block1 option");
        uint32_t peer_mtu = 0;
        if (coap_options_get_size1(message, &peer_mtu) == 1) {
          block1.size = MIN((uint16_t)peer_mtu, (uint16_t)OC_BLOCK_SIZE);
        } else {
          block1.size = (uint16_t)OC_BLOCK_SIZE;
        }
        payload = oc_blockwise_dispatch_block(request_buffer, 0, block1.size,
                                              &payload_size);
        request_buffer->ref_count = 1;
      }
      if (payload) {
        OC_DBG("dispatching next block");
        transaction =
          coap_new_transaction(response_mid, NULL, 0, &msg->endpoint);
        if (transaction) {
          coap_udp_init_message(response, COAP_TYPE_CON, client_cb->method,
                                response_mid);
          uint8_t more =
            (request_buffer->next_block_offset < request_buffer->payload_size)
              ? 1
              : 0;
          coap_options_set_uri_path(response, oc_string(client_cb->uri),
                                    oc_string_len(client_cb->uri));
          coap_set_payload(response, payload, payload_size);
          if (block1.enabled) {
            coap_options_set_block1(response, block1.num + 1, more, block1.size,
                                    0);
          } else {
            coap_options_set_block1(response, 0, more, block1.size, 0);
            coap_options_set_size1(response, request_buffer->payload_size);
          }
          if (oc_string_len(client_cb->query) > 0) {
            coap_options_set_uri_query(response, oc_string(client_cb->query),
                                       oc_string_len(client_cb->query));
          }
          coap_options_set_accept(response, APPLICATION_VND_OCF_CBOR);
          coap_options_set_content_format(response, APPLICATION_VND_OCF_CBOR);
          request_buffer->mid = response_mid;
          goto send_message;
        }
      } else {
        request_buffer->ref_count = 0;
      }
    }

    if (request_buffer && (request_buffer->ref_count == 0 || error_response)) {
      oc_blockwise_free_request_buffer(request_buffer);
      request_buffer = NULL;
    }

    if (client_cb) {
      response_buffer = oc_blockwise_find_response_buffer_by_client_cb(
        &msg->endpoint, client_cb);
      if (!response_buffer) {
        uint32_t buffer_size = (uint32_t)OC_MAX_APP_DATA_SIZE;
        response_buffer = oc_blockwise_alloc_response_buffer(
          oc_string(client_cb->uri) + 1, oc_string_len(client_cb->uri) - 1,
          &msg->endpoint, client_cb->method, OC_BLOCKWISE_CLIENT, buffer_size);
        if (response_buffer) {
          OC_DBG("created new response buffer for uri %s",
                 oc_string(response_buffer->href));
          response_buffer->client_cb = client_cb;
        }
      }
    } else {
      response_buffer = oc_blockwise_find_response_buffer_by_mid(message->mid);
      if (!response_buffer) {
        response_buffer = oc_blockwise_find_response_buffer_by_token(
          message->token, message->token_len);
      }
    }
    if (!error_response && response_buffer) {
      OC_DBG("got response buffer for uri %s",
             oc_string(response_buffer->href));
      client_cb = (oc_client_cb_t *)response_buffer->client_cb;
      oc_blockwise_response_state_t *response_state =
        (oc_blockwise_response_state_t *)response_buffer;
      coap_options_get_observe(message, &response_state->observe_seq);

      const uint8_t *incoming_block;
      uint32_t incoming_block_len = coap_get_payload(message, &incoming_block);
      if (incoming_block_len > 0 &&
          oc_blockwise_handle_block(response_buffer, block2.offset,
                                    incoming_block,
                                    (uint32_t)incoming_block_len)) {
        OC_DBG("processing incoming block");
        if (block2.enabled && block2.more) {
          OC_DBG("issuing request for next block");
          transaction =
            coap_new_transaction(response_mid, NULL, 0, &msg->endpoint);
          if (transaction) {
            coap_udp_init_message(response, COAP_TYPE_CON, client_cb->method,
                                  response_mid);
            response_buffer->mid = response_mid;
            client_cb->mid = response_mid;
            coap_options_set_accept(response, APPLICATION_VND_OCF_CBOR);
            coap_options_set_block2(response, block2.num + 1, 0, block2.size,
                                    0);
            coap_options_set_uri_path(response, oc_string(client_cb->uri),
                                      oc_string_len(client_cb->uri));
            if (oc_string_len(client_cb->query) > 0) {
              coap_options_set_uri_query(response, oc_string(client_cb->query),
                                         oc_string_len(client_cb->query));
            }
            goto send_message;
          }
        }
        response_buffer->payload_size = response_buffer->next_block_offset;
      }
    }

#endif /* OC_BLOCK_WISE */

    if (client_cb) {
      OC_DBG("calling oc_client_cb_invoke");
#ifdef OC_BLOCK_WISE
      if (request_buffer) {
        request_buffer->ref_count = 0;
      }

      oc_client_cb_invoke(message, &response_buffer, client_cb, &msg->endpoint);
      /* Do not free the response buffer in case of a separate response
       * signal from the server. In this case, the client_cb continues
       * to live until the response arrives (or it times out).
       */
      if (oc_ri_is_client_cb_valid(client_cb)) {
        if (client_cb->separate == 0) {
          if (response_buffer) {
            response_buffer->ref_count = 0;
          }
        } else {
          client_cb->separate = 0;
        }
      }
      goto send_message;
#else  /* OC_BLOCK_WISE */
      oc_client_cb_invoke(message, client_cb, &msg->endpoint);
#endif /* OC_BLOCK_WISE */
    }
#endif /* OC_CLIENT */
  }

init_reset_message:
#ifdef OC_TCP
  if (msg->endpoint.flags & TCP) {
    coap_tcp_init_message(response, INTERNAL_SERVER_ERROR_5_00);
  } else
#endif /* OC_TCP */
  {
    coap_udp_init_message(response, COAP_TYPE_RST, 0, message->mid);
  }
#ifdef OC_BLOCK_WISE
  if (request_buffer) {
    request_buffer->ref_count = 0;
  }
  if (response_buffer) {
    response_buffer->ref_count = 0;
  }
#endif /* OC_BLOCK_WISE */

send_message:
  if (coap_global_status_code() == CLEAR_TRANSACTION) {
    coap_clear_transaction(transaction);
  } else if (transaction) {
    if (response->type != COAP_TYPE_RST && message->token_len > 0) {
      if (message->code >= COAP_GET && message->code <= COAP_DELETE) {
        coap_set_token(response, message->token, message->token_len);
      }
#if defined(OC_CLIENT) && defined(OC_BLOCK_WISE)
      else {
        const oc_blockwise_response_state_t *b =
          (oc_blockwise_response_state_t *)response_buffer;
        if (b != NULL && b->observe_seq != OC_COAP_OPTION_OBSERVE_NOT_SET) {
          response->token_len = sizeof(response->token);
          oc_random_buffer(response->token, response->token_len);
          if (request_buffer) {
            memcpy(request_buffer->token, response->token, response->token_len);
            request_buffer->token_len = response->token_len;
          }
          if (response_buffer) {
            memcpy(response_buffer->token, response->token,
                   response->token_len);
            response_buffer->token_len = response->token_len;
          }
        } else {
          coap_set_token(response, message->token, message->token_len);
        }
      }
#endif /* OC_CLIENT && OC_BLOCK_WISE */
    }
    if (response->token_len > 0) {
      memcpy(transaction->token, response->token, response->token_len);
      transaction->token_len = response->token_len;
    }
    OC_DBG("data buffer from:%p to:%p", (void *)transaction->message->data,
           (void *)(transaction->message->data + oc_message_buffer_size()));
    transaction->message->length = coap_serialize_message(
      response, transaction->message->data, oc_message_buffer_size());
    if (transaction->message->length > 0) {
      coap_send_transaction(transaction);
    } else {
      coap_clear_transaction(transaction);
    }
  }

#ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers(false);
#endif /* OC_BLOCK_WISE */

  return coap_global_status_code();
}
/*---------------------------------------------------------------------------*/
void
coap_init_engine(void)
{
  coap_register_as_transaction_handler();
}
/*---------------------------------------------------------------------------*/
OC_PROCESS_THREAD(g_coap_engine, ev, data)
{
  OC_PROCESS_BEGIN();

  coap_register_as_transaction_handler();
  coap_init_connection();

  while (1) {
    OC_PROCESS_YIELD();

    if (ev == oc_event_to_oc_process_event(INBOUND_RI_EVENT)) {
      oc_message_t *msg = (oc_message_t *)data;
      coap_receive(msg);

      oc_message_unref(msg);
    } else if (ev == OC_PROCESS_EVENT_TIMER) {
      coap_check_transactions();
    }
  }

  OC_PROCESS_END();
}

/*---------------------------------------------------------------------------*/
