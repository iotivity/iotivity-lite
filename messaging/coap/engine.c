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

#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api/oc_events.h"
#include "oc_buffer.h"
#include "oc_ri.h"

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif /* OC_CLIENT */

OC_PROCESS(coap_engine, "CoAP Engine");

#ifdef OC_BLOCK_WISE
extern bool oc_ri_invoke_coap_entity_handler(
  void *request, void *response, oc_blockwise_state_t *request_state,
  oc_blockwise_state_t *response_state, uint16_t block2_size,
  oc_endpoint_t *endpoint);
#else  /* OC_BLOCK_WISE */
extern bool oc_ri_invoke_coap_entity_handler(void *request, void *response,
                                             uint8_t *buffer,
                                             oc_endpoint_t *endpoint);
#endif /* !OC_BLOCK_WISE */

#define OC_REQUEST_HISTORY_SIZE (250)
static uint16_t history[OC_REQUEST_HISTORY_SIZE];
static uint8_t history_dev[OC_REQUEST_HISTORY_SIZE];
static uint8_t idx;

static bool
check_if_duplicate(uint16_t mid, uint8_t device)
{
  size_t i;
  for (i = 0; i < OC_REQUEST_HISTORY_SIZE; i++) {
    if (history[i] == mid && history_dev[i] == device) {
      OC_DBG("dropping duplicate request\n");
      return true;
    }
  }
  return false;
}

void
coap_send_empty_ack(uint16_t mid, oc_endpoint_t *endpoint)
{
  coap_packet_t ack[1];
  coap_init_message(ack, COAP_TYPE_ACK, 0, mid);
  oc_message_t *ack_message = oc_allocate_message();
  if (ack_message) {
    memcpy(&ack_message->endpoint, endpoint, sizeof(*endpoint));
    ack_message->length = coap_serialize_message(ack, ack_message->data);
    coap_send_message(ack_message);
    if (ack_message->ref_count == 0)
      oc_message_unref(ack_message);
  }
}

/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
int
coap_receive(oc_message_t *msg)
{
  coap_status_code = COAP_NO_ERROR;

  OC_DBG("\n\nCoAP Engine: received datalen=%u from ",
         (unsigned int)msg->length);
#ifdef OC_DEBUG
  PRINTipaddr(msg->endpoint);
  PRINT("\n\n");
#endif /* OC_DEBUG */

  /* static declaration reduces stack peaks and program code size */
  static coap_packet_t
    message[1]; /* this way the packet can be treated as pointer as usual */
  static coap_packet_t response[1];
  static coap_transaction_t *transaction = NULL;

  /* block options */
  uint32_t block1_num = 0, block1_offset = 0, block2_num = 0, block2_offset = 0;
  uint16_t block1_size = (uint16_t)OC_BLOCK_SIZE,
           block2_size = (uint16_t)OC_BLOCK_SIZE;
  uint8_t block1_more = 0, block2_more = 0;
  bool block1 = false, block2 = false;

#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *request_buffer = 0, *response_buffer = 0;
#endif /* OC_BLOCK_WISE */

  coap_status_code =
    coap_parse_message(message, msg->data, (uint16_t)msg->length);

  if (coap_status_code == COAP_NO_ERROR) {

#if OC_DEBUG
    OC_DBG("  Parsed: CoAP version: %u, token: 0x%02X%02X, mid: %u\n",
           message->version, message->token[0], message->token[1],
           message->mid);
    switch (message->type) {
    case COAP_TYPE_CON:
      OC_DBG("  type: CON\n");
      break;
    case COAP_TYPE_NON:
      OC_DBG("  type: NON\n");
      break;
    case COAP_TYPE_ACK:
      OC_DBG("  type: ACK\n");
      break;
    case COAP_TYPE_RST:
      OC_DBG("  type: RST\n");
      break;
    default:
      break;
    }
#endif

    /* extract block options */
    if (coap_get_header_block1(message, &block1_num, &block1_more, &block1_size,
                               &block1_offset))
      block1 = true;
    if (coap_get_header_block2(message, &block2_num, &block2_more, &block2_size,
                               &block2_offset))
      block2 = true;

#ifdef OC_BLOCK_WISE
    block1_size = MIN(block1_size, (uint16_t)OC_BLOCK_SIZE);
    block2_size = MIN(block2_size, (uint16_t)OC_BLOCK_SIZE);
#endif /* OC_BLOCK_WISE */

    transaction = coap_get_transaction_by_mid(message->mid);
    if (transaction)
      coap_clear_transaction(transaction);
    transaction = NULL;

    /* handle requests */
    if (message->code >= COAP_GET && message->code <= COAP_DELETE) {

#if OC_DEBUG
      switch (message->code) {
      case COAP_GET:
        OC_DBG("  method: GET\n");
        break;
      case COAP_PUT:
        OC_DBG("  method: PUT\n");
        break;
      case COAP_POST:
        OC_DBG("  method: POST\n");
        break;
      case COAP_DELETE:
        OC_DBG("  method: DELETE\n");
        break;
      }
      OC_DBG("  URL: %.*s\n", (int)message->uri_path_len, message->uri_path);
      OC_DBG("  Payload: %.*s\n", (int)message->payload_len, message->payload);
#endif

      if (message->type == COAP_TYPE_CON) {
        coap_init_message(response, COAP_TYPE_ACK, CONTENT_2_05, message->mid);
      } else {
        if (check_if_duplicate(message->mid, (uint8_t)msg->endpoint.device)) {
          return 0;
        }
        history[idx] = message->mid;
        history_dev[idx] = (uint8_t)msg->endpoint.device;
        idx = (idx + 1) % OC_REQUEST_HISTORY_SIZE;
        coap_init_message(response, COAP_TYPE_NON, CONTENT_2_05,
                          coap_get_mid());
      }

      /* create transaction for response */
      transaction = coap_new_transaction(message->mid, &msg->endpoint);

      if (transaction) {
#ifdef OC_BLOCK_WISE
        const char *href;
        int href_len = coap_get_header_uri_path(message, &href);
        const uint8_t *incoming_block;
        int incoming_block_len = coap_get_payload(message, &incoming_block);
        if (block1) {
          OC_DBG("processing block1 option\n");
          request_buffer = oc_blockwise_find_request_buffer(
            href, href_len, &msg->endpoint, message->code, message->uri_query,
            message->uri_query_len, OC_BLOCKWISE_SERVER);

          if (!request_buffer && block1_num == 0) {
            OC_DBG("creating new block-wise request buffer\n");
            request_buffer = oc_blockwise_alloc_request_buffer(
              href, href_len, &msg->endpoint, message->code,
              OC_BLOCKWISE_SERVER);

            if (request_buffer) {
              if (message->uri_query_len > 0) {
                oc_new_string(&request_buffer->uri_query, message->uri_query,
                              message->uri_query_len);
              }
            }
          }

          if (request_buffer) {
            OC_DBG("processing incoming block\n");
            if (oc_blockwise_handle_block(
                  request_buffer, block1_offset, incoming_block,
                  MIN((uint16_t)incoming_block_len, block1_size))) {
              if (block1_more) {
                OC_DBG(
                  "more blocks expected; issuing request for the next block\n");
                response->code = CONTINUE_2_31;
                coap_set_header_block1(response, block1_num, block1_more,
                                       block1_size);
                request_buffer->ref_count = 1;
                goto send_message;
              } else {
                OC_DBG("received all blocks for payload\n");
                coap_set_header_block1(response, block1_num, block1_more,
                                       block1_size);
                request_buffer->payload_size =
                  request_buffer->next_block_offset;
                request_buffer->ref_count = 0;

                response_buffer = oc_blockwise_find_response_buffer(
                  href, href_len, &msg->endpoint, message->code,
                  message->uri_query, message->uri_query_len,
                  OC_BLOCKWISE_SERVER);
                if (!response_buffer) {
                  OC_DBG("creating new block-wise response buffer\n");
                  response_buffer = oc_blockwise_alloc_response_buffer(
                    href, href_len, &msg->endpoint, message->code,
                    OC_BLOCKWISE_SERVER);
                  if (response_buffer) {
                    if (message->uri_query_len > 0) {
                      oc_new_string(&response_buffer->uri_query,
                                    message->uri_query, message->uri_query_len);
                    }
                    goto request_handler;
                  }
                } else {
                  goto request_handler;
                }
              }
            }
          }
          OC_ERR("could not create block-wise request buffer\n");
          goto init_reset_message;
        } else if (block2) {
          OC_DBG("processing block2 option\n");
          unsigned int accept = 0;
          if (coap_get_header_accept(message, &accept) == 1) {
            coap_set_header_content_format(response, accept);
          } else {
            coap_set_header_content_format(response, APPLICATION_VND_OCF_CBOR);
          }
          response_buffer = oc_blockwise_find_response_buffer(
            href, href_len, &msg->endpoint, message->code, message->uri_query,
            message->uri_query_len, OC_BLOCKWISE_SERVER);
          if (response_buffer) {
            OC_DBG("continuing ongoing block-wise transfer\n");
            uint16_t payload_size = 0;
            const void *payload = oc_blockwise_dispatch_block(
              response_buffer, block2_offset, block2_size, &payload_size);
            if (payload) {
              OC_DBG("dispatching next block\n");
              uint8_t more = (response_buffer->next_block_offset <
                              response_buffer->payload_size)
                               ? 1
                               : 0;
              coap_set_payload(response, payload, payload_size);
              coap_set_header_block2(response, block2_num, more, block2_size);
              oc_blockwise_response_state_t *response_state =
                (oc_blockwise_response_state_t *)response_buffer;
              coap_set_header_etag(response, response_state->etag,
                                   COAP_ETAG_LEN);
              response_buffer->ref_count = more;
              goto send_message;
            } else {
              OC_ERR("could not dispatch block\n");
            }
          } else {
            OC_DBG("requesting block-wise transfer; creating new block-wise "
                   "response buffer\n");
            if (block2_num == 0) {
              response_buffer = oc_blockwise_alloc_response_buffer(
                href, href_len, &msg->endpoint, message->code,
                OC_BLOCKWISE_SERVER);
              if (response_buffer) {
                if (message->uri_query_len > 0) {
                  oc_new_string(&response_buffer->uri_query, message->uri_query,
                                message->uri_query_len);
                }
                if (incoming_block_len > 0) {
                  request_buffer = oc_blockwise_find_request_buffer(
                    href, href_len, &msg->endpoint, message->code,
                    message->uri_query, message->uri_query_len,
                    OC_BLOCKWISE_SERVER);
                  if (!request_buffer) {
                    request_buffer = oc_blockwise_alloc_request_buffer(
                      href, href_len, &msg->endpoint, message->code,
                      OC_BLOCKWISE_SERVER);
                    if (!(request_buffer && oc_blockwise_handle_block(
                                              request_buffer, 0, incoming_block,
                                              (uint16_t)incoming_block_len))) {
                      OC_ERR(
                        "could not create buffer to hold request payload\n");
                      goto init_reset_message;
                    }
                    if (message->uri_query_len > 0) {
                      oc_new_string(&request_buffer->uri_query,
                                    message->uri_query, message->uri_query_len);
                    }
                    request_buffer->payload_size = incoming_block_len;
                  }
                }
                goto request_handler;
              } else {
                OC_ERR("could not create response buffer\n");
              }
            } else {
              OC_ERR("initiating block-wise transfer with request for "
                     "block_num > 0\n");
            }
          }
          goto init_reset_message;
        } else {
          OC_DBG("no block options; processing regular request\n");
          if (incoming_block_len <= block1_size) {
            OC_DBG("creating response buffer\n");
            response_buffer = oc_blockwise_alloc_response_buffer(
              href, href_len, &msg->endpoint, message->code,
              OC_BLOCKWISE_SERVER);
            if (response_buffer) {
              if (message->uri_query_len > 0) {
                oc_new_string(&response_buffer->uri_query, message->uri_query,
                              message->uri_query_len);
              }
              if (incoming_block_len > 0) {
                OC_DBG("creating request buffer\n");
                request_buffer = oc_blockwise_alloc_request_buffer(
                  href, href_len, &msg->endpoint, message->code,
                  OC_BLOCKWISE_SERVER);
                if (!(request_buffer && oc_blockwise_handle_block(
                                          request_buffer, 0, incoming_block,
                                          (uint16_t)incoming_block_len))) {
                  OC_ERR("could not create buffer to hold request payload\n");
                  goto init_reset_message;
                }
                if (message->uri_query_len > 0) {
                  oc_new_string(&request_buffer->uri_query, message->uri_query,
                                message->uri_query_len);
                }
                request_buffer->payload_size = incoming_block_len;
                request_buffer->ref_count = 0;
              }
              goto request_handler;
            } else {
              OC_ERR("could not create response buffer\n");
            }
          } else {
            OC_ERR("incoming payload size exceeds block size\n");
          }
          goto init_reset_message;
        }
#else  /* OC_BLOCK_WISE */
        if (block1 || block2) {
          goto init_reset_message;
        }
#endif /* !OC_BLOCK_WISE */
#ifdef OC_BLOCK_WISE
      request_handler:
        if (oc_ri_invoke_coap_entity_handler(message, response, request_buffer,
                                             response_buffer, block2_size,
                                             &msg->endpoint)) {
#else  /* OC_BLOCK_WISE */
        if (oc_ri_invoke_coap_entity_handler(message, response,
                                             transaction->message->data +
                                               COAP_MAX_HEADER_SIZE,
                                             &msg->endpoint)) {
#endif /* !OC_BLOCK_WISE */
#ifdef OC_BLOCK_WISE
          uint16_t payload_size = 0;
          const void *payload = oc_blockwise_dispatch_block(
            response_buffer, 0, block2_size, &payload_size);
          if (payload) {
            coap_set_payload(response, payload, payload_size);
          }
          if (block2 || response_buffer->payload_size > block2_size) {
            coap_set_header_block2(
              response, 0,
              (response_buffer->payload_size > block2_size) ? 1 : 0,
              block2_size);
            coap_set_header_size2(response, response_buffer->payload_size);
            oc_blockwise_response_state_t *response_state =
              (oc_blockwise_response_state_t *)response_buffer;
            coap_set_header_etag(response, response_state->etag, COAP_ETAG_LEN);
          } else {
            response_buffer->ref_count = 0;
          }
#endif /* OC_BLOCK_WISE */
        }
#ifdef OC_BLOCK_WISE
        else {
          if (request_buffer)
            request_buffer->ref_count = 0;
          if (response_buffer)
            response_buffer->ref_count = 0;
        }
#endif /* OC_BLOCK_WISE */
        if (response->code != 0) {
          goto send_message;
        }
      }
    } else {
#ifdef OC_CLIENT
#ifdef OC_BLOCK_WISE
      uint16_t response_mid = coap_get_mid();
#endif /* OC_BLOCK_WISE */
      oc_client_cb_t *client_cb = 0;
      if (message->type != COAP_TYPE_RST) {
        client_cb =
          oc_ri_find_client_cb_by_token(message->token, message->token_len);
      }
#endif /* OC_CLIENT */

      if (message->type == COAP_TYPE_CON) {
        coap_send_empty_ack(message->mid, &msg->endpoint);
      } else if (message->type == COAP_TYPE_ACK) {
      } else if (message->type == COAP_TYPE_RST) {
#ifdef OC_SERVER
        /* cancel possible subscriptions */
        coap_remove_observer_by_mid(&msg->endpoint, message->mid);
#endif
      }

#ifdef OC_CLIENT
#ifdef OC_BLOCK_WISE
      if (client_cb) {
        request_buffer = oc_blockwise_find_request_buffer_by_client_cb(
          &msg->endpoint, client_cb);
      } else {
        request_buffer = oc_blockwise_find_request_buffer_by_mid(message->mid);
      }
      if (request_buffer &&
          (block1 || message->code == REQUEST_ENTITY_TOO_LARGE_4_13)) {
        OC_DBG("found request buffer for uri %s\n",
               oc_string(request_buffer->href));
        client_cb = (oc_client_cb_t *)request_buffer->client_cb;
        uint16_t payload_size = 0;
        const void *payload = 0;

        if (block1) {
          payload = oc_blockwise_dispatch_block(request_buffer,
                                                block1_offset + block1_size,
                                                block1_size, &payload_size);
        } else {
          OC_DBG("initiating block-wise transfer with block1 option\n");
          uint32_t peer_mtu = 0;
          if (coap_get_header_size1(message, (uint32_t *)&peer_mtu) == 1) {
            block1_size = MIN((uint16_t)peer_mtu, (uint16_t)OC_BLOCK_SIZE);
          } else {
            block1_size = (uint16_t)OC_BLOCK_SIZE;
          }
          payload = oc_blockwise_dispatch_block(request_buffer, 0, block1_size,
                                                &payload_size);
          request_buffer->ref_count = 1;
        }
        if (payload) {
          OC_DBG("dispatching next block\n");
          transaction = coap_new_transaction(response_mid, &msg->endpoint);
          if (transaction) {
            coap_init_message(response, COAP_TYPE_CON, client_cb->method,
                              response_mid);
            uint8_t more =
              (request_buffer->next_block_offset < request_buffer->payload_size)
                ? 1
                : 0;
            coap_set_header_uri_path(response, oc_string(client_cb->uri),
                                     oc_string_len(client_cb->uri));
            coap_set_payload(response, payload, payload_size);
            if (block1) {
              coap_set_header_block1(response, block1_num + 1, more,
                                     block1_size);
            } else {
              coap_set_header_block1(response, 0, more, block1_size);
              coap_set_header_size1(response, request_buffer->payload_size);
            }
            if (oc_string_len(client_cb->query) > 0) {
              coap_set_header_uri_query(response, oc_string(client_cb->query));
            }
            request_buffer->mid = response_mid;
            goto send_message;
          }
        } else {
          request_buffer->ref_count = 0;
        }
      }

      if (client_cb) {
        response_buffer = oc_blockwise_find_response_buffer_by_client_cb(
          &msg->endpoint, client_cb);
        if (!response_buffer) {
          response_buffer = oc_blockwise_alloc_response_buffer(
            oc_string(client_cb->uri) + 1, oc_string_len(client_cb->uri) - 1,
            &msg->endpoint, client_cb->method, OC_BLOCKWISE_CLIENT);
          if (response_buffer) {
            OC_DBG("created new response buffer for uri %s\n",
                   oc_string(response_buffer->href));
            response_buffer->client_cb = client_cb;
          }
        }
      } else {
        response_buffer =
          oc_blockwise_find_response_buffer_by_mid(message->mid);
      }
      if (response_buffer) {
        OC_DBG("got response buffer for uri %s\n",
               oc_string(response_buffer->href));
        client_cb = (oc_client_cb_t *)response_buffer->client_cb;
        oc_blockwise_response_state_t *response_state =
          (oc_blockwise_response_state_t *)response_buffer;
        coap_get_header_observe(message,
                                (uint32_t *)&response_state->observe_seq);

        const uint8_t *incoming_block;
        int incoming_block_len = coap_get_payload(message, &incoming_block);
        if (incoming_block_len > 0 &&
            oc_blockwise_handle_block(response_buffer, block2_offset,
                                      incoming_block,
                                      (uint16_t)incoming_block_len)) {
          OC_DBG("processing incoming block\n");
          if (block2 && block2_more) {
            OC_DBG("issuing request for next block\n");
            transaction = coap_new_transaction(response_mid, &msg->endpoint);
            if (transaction) {
              coap_init_message(response, COAP_TYPE_CON, client_cb->method,
                                response_mid);
              response_buffer->mid = response_mid;
              coap_set_header_block2(response, block2_num + 1, 0, block2_size);
              coap_set_header_uri_path(response, oc_string(client_cb->uri),
                                       oc_string_len(client_cb->uri));
              if (oc_string_len(client_cb->query) > 0) {
                coap_set_header_uri_query(response,
                                          oc_string(client_cb->query));
              }
              goto send_message;
            }
          }
          response_buffer->payload_size = response_buffer->next_block_offset;
        }
      }

      if (request_buffer && request_buffer->ref_count == 0) {
        oc_blockwise_free_request_buffer(request_buffer);
        request_buffer = 0;
      }
#endif /* OC_BLOCK_WISE */

      if (client_cb) {
        OC_DBG("calling oc_ri_invoke_client_cb\n");
#ifdef OC_BLOCK_WISE
        oc_ri_invoke_client_cb(message, &response_buffer, client_cb,
                               &msg->endpoint);
        goto free_blockwise_buffers;
#else  /* OC_BLOCK_WISE */
        oc_ri_invoke_client_cb(message, client_cb, &msg->endpoint);
#endif /* OC_BLOCK_WISE */
      }
#endif /* OC_CLIENT */
    }
  }

init_reset_message:
  coap_init_message(response, COAP_TYPE_RST, 0, message->mid);
#ifdef OC_BLOCK_WISE
#ifdef OC_CLIENT
free_blockwise_buffers:
#endif /* OC_CLIENT */
  if (request_buffer) {
    request_buffer->ref_count = 0;
  }
  if (response_buffer) {
    response_buffer->ref_count = 0;
  }
#endif /* OC_BLOCK_WISE */

send_message:
  if (coap_status_code == COAP_NO_ERROR) {
    if (transaction) {
      if (response->type != COAP_TYPE_RST && message->token_len) {
        if (message->code >= COAP_GET && message->code <= COAP_DELETE) {
          coap_set_token(response, message->token, message->token_len);
        }
#if defined(OC_CLIENT) && defined(OC_BLOCK_WISE)
        else {
          oc_blockwise_response_state_t *b =
            (oc_blockwise_response_state_t *)response_buffer;
          if (b && b->observe_seq != -1) {
            int i = 0;
            uint32_t r;
            while (i < COAP_TOKEN_LEN) {
              r = oc_random_value();
              memcpy(response->token + i, &r, sizeof(r));
              i += sizeof(r);
            }
            response->token_len = (uint8_t)i;
          } else {
            coap_set_token(response, message->token, message->token_len);
          }
        }
#endif /* OC_CLIENT && OC_BLOCK_WISE */
      }
      transaction->message->length =
        coap_serialize_message(response, transaction->message->data);
      if (transaction->message->length) {
        coap_send_transaction(transaction);
      } else {
        coap_clear_transaction(transaction);
      }
    }
  } else if (coap_status_code == CLEAR_TRANSACTION) {
    coap_clear_transaction(transaction);
  }

#ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers();
#endif /* OC_BLOCK_WISE */

  return coap_status_code;
}
/*---------------------------------------------------------------------------*/
void
coap_init_engine(void)
{
  coap_register_as_transaction_handler();
}
/*---------------------------------------------------------------------------*/
OC_PROCESS_THREAD(coap_engine, ev, data)
{
  OC_PROCESS_BEGIN();

  coap_register_as_transaction_handler();
  coap_init_connection();

  while (1) {
    OC_PROCESS_YIELD();

    if (ev == oc_events[INBOUND_RI_EVENT]) {
      coap_receive(data);

      oc_message_unref(data);
    } else if (ev == OC_PROCESS_EVENT_TIMER) {
      coap_check_transactions();
    }
  }

  OC_PROCESS_END();
}

/*---------------------------------------------------------------------------*/
