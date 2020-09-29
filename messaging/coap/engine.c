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
#include "oc_api.h"
#include "oc_buffer.h"

#ifdef OC_SECURITY
#include "security/oc_tls.h"
#include "security/oc_audit.h"
#endif /* OC_SECURITY */

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif /* OC_CLIENT */

#ifdef OC_TCP
#include "coap_signal.h"
#endif

OC_PROCESS(coap_engine, "CoAP Engine");

#ifdef OC_BLOCK_WISE
extern bool oc_ri_invoke_coap_entity_handler(
  void *request, void *response, oc_blockwise_state_t **request_state,
  oc_blockwise_state_t **response_state, uint16_t block2_size,
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
      OC_DBG("dropping duplicate request");
      return true;
    }
  }
  return false;
}

static void
coap_send_empty_response(coap_message_type_t type, uint16_t mid,
                         const uint8_t *token, size_t token_len, uint8_t code,
                         oc_endpoint_t *endpoint)
{
  OC_DBG("CoAP send empty message: mid=%u, code=%u", mid, code);
  coap_packet_t msg[1]; // empty response
  coap_udp_init_message(msg, type, code, mid);
  oc_message_t *message = oc_internal_allocate_outgoing_message();
  if (message) {
    memcpy(&message->endpoint, endpoint, sizeof(*endpoint));
    if (token && token_len > 0) {
      coap_set_token(msg, token, token_len);
    }
    size_t len = coap_serialize_message(msg, message->data);
    if (len > 0) {
      message->length = len;
      coap_send_message(message);
    }
    if (message->ref_count == 0) {
      oc_message_unref(message);
    }
  }
}

#ifdef OC_SECURITY
static void
coap_audit_log(oc_message_t *msg)
{
  char ipaddr[IPADDR_BUFF_SIZE];
  SNPRINTFipaddr(ipaddr, IPADDR_BUFF_SIZE, msg->endpoint);
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
int
coap_receive(oc_message_t *msg)
{
  coap_status_code = COAP_NO_ERROR;

  OC_DBG("CoAP Engine: received datalen=%u from", (unsigned int)msg->length);
  OC_LOGipaddr(msg->endpoint);
  OC_LOGbytes(msg->data, msg->length);

  /* static declaration reduces stack peaks and program code size */
  static coap_packet_t
    message[1]; /* this way the packet can be treated as pointer as usual */
  static coap_packet_t response[1];
  static coap_transaction_t *transaction;
  transaction = NULL;

  /* block options */
  uint32_t block1_num = 0, block1_offset = 0, block2_num = 0, block2_offset = 0;
  uint16_t block1_size = (uint16_t)OC_BLOCK_SIZE,
           block2_size = (uint16_t)OC_BLOCK_SIZE;
  uint8_t block1_more = 0, block2_more = 0;
  bool block1 = false, block2 = false;

#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *request_buffer = NULL, *response_buffer = NULL;
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
  oc_client_cb_t *client_cb = 0;
#endif /* OC_CLIENT */

#ifdef OC_TCP
  if (msg->endpoint.flags & TCP) {
    coap_status_code =
      coap_tcp_parse_message(message, msg->data, (uint32_t)msg->length);
  } else
#endif /* OC_TCP */
  {
    coap_status_code =
      coap_udp_parse_message(message, msg->data, (uint16_t)msg->length);
  }

  if (coap_status_code == COAP_NO_ERROR) {

#ifdef OC_DEBUG
    OC_DBG("  Parsed: CoAP version: %u, token: 0x%02X%02X, mid: %u",
           message->version, message->token[0], message->token[1],
           message->mid);
    switch (message->type) {
    case COAP_TYPE_CON:
      OC_DBG("  type: CON");
      break;
    case COAP_TYPE_NON:
      OC_DBG("  type: NON");
      break;
    case COAP_TYPE_ACK:
      OC_DBG("  type: ACK");
      break;
    case COAP_TYPE_RST:
      OC_DBG("  type: RST");
      break;
    default:
      break;
    }
#endif

#ifdef OC_TCP
    if (coap_check_signal_message(message)) {
      coap_status_code = handle_coap_signal_message(message, &msg->endpoint);
    }
#endif /* OC_TCP */

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

#ifdef OC_TCP
    if (!(msg->endpoint.flags & TCP))
#endif /* OC_TCP */
    {
      transaction = coap_get_transaction_by_mid(message->mid);
      if (transaction) {
        coap_clear_transaction(transaction);
      }
      transaction = NULL;
    }

    /* handle requests */
    if (message->code >= COAP_GET && message->code <= COAP_DELETE) {

#ifdef OC_DEBUG
      switch (message->code) {
      case COAP_GET:
        OC_DBG("  method: GET");
        break;
      case COAP_PUT:
        OC_DBG("  method: PUT");
        break;
      case COAP_POST:
        OC_DBG("  method: POST");
        break;
      case COAP_DELETE:
        OC_DBG("  method: DELETE");
        break;
      }
      OC_DBG("  URL: %.*s", (int)message->uri_path_len, message->uri_path);
      OC_DBG("  QUERY: %.*s", (int)message->uri_query_len, message->uri_query);
      OC_DBG("  Payload: %.*s", (int)message->payload_len, message->payload);
#endif
      const char *href;
      size_t href_len = coap_get_header_uri_path(message, &href);
#ifdef OC_TCP
      if (msg->endpoint.flags & TCP) {
        coap_tcp_init_message(response, CONTENT_2_05);
      } else
#endif /* OC_TCP */
      {
        if (message->type == COAP_TYPE_CON) {
          coap_udp_init_message(response, COAP_TYPE_ACK, CONTENT_2_05,
                                message->mid);
        } else {
          if (check_if_duplicate(message->mid, (uint8_t)msg->endpoint.device)) {
            return 0;
          }
          history[idx] = message->mid;
          history_dev[idx] = (uint8_t)msg->endpoint.device;
          idx = (idx + 1) % OC_REQUEST_HISTORY_SIZE;
          if (href_len == 7 && memcmp(href, "oic/res", 7) == 0) {
            coap_udp_init_message(response, COAP_TYPE_CON, CONTENT_2_05,
                                  coap_get_mid());
          } else {
            coap_udp_init_message(response, COAP_TYPE_NON, CONTENT_2_05,
                                  coap_get_mid());
          }
        }
      }

      /* create transaction for response */
      transaction = coap_new_transaction(response->mid, &msg->endpoint);

      if (transaction) {
#ifdef OC_BLOCK_WISE
        const uint8_t *incoming_block;
        uint32_t incoming_block_len =
          (uint32_t)coap_get_payload(message, &incoming_block);
        if (block1) {
          OC_DBG("processing block1 option");
          request_buffer = oc_blockwise_find_request_buffer(
            href, href_len, &msg->endpoint, message->code, message->uri_query,
            message->uri_query_len, OC_BLOCKWISE_SERVER);

          if (request_buffer && request_buffer->payload_size ==
                                  request_buffer->next_block_offset) {
            if ((request_buffer->next_block_offset - incoming_block_len) !=
                block1_offset) {
              oc_blockwise_free_request_buffer(request_buffer);
              request_buffer = NULL;
            }
          }

          if (!request_buffer && block1_num == 0) {
            OC_DBG("creating new block-wise request buffer");
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
            OC_DBG("processing incoming block");
            if (oc_blockwise_handle_block(
                  request_buffer, block1_offset, incoming_block,
                  MIN((uint16_t)incoming_block_len, block1_size))) {
              if (block1_more) {
                OC_DBG(
                  "more blocks expected; issuing request for the next block");
                response->code = CONTINUE_2_31;
                coap_set_header_block1(response, block1_num, block1_more,
                                       block1_size);
                request_buffer->ref_count = 1;
                goto send_message;
              } else {
                OC_DBG("received all blocks for payload");
                if (message->type == COAP_TYPE_CON) {
                  coap_send_empty_response(COAP_TYPE_ACK, message->mid, NULL, 0,
                                           0, &msg->endpoint);
                }
                coap_udp_init_message(response, COAP_TYPE_CON, CONTENT_2_05,
                                      coap_get_mid());
                transaction->mid = response->mid;
                coap_set_header_block1(response, block1_num, block1_more,
                                       block1_size);
                coap_set_header_accept(response, APPLICATION_VND_OCF_CBOR);
                request_buffer->payload_size =
                  request_buffer->next_block_offset;
                request_buffer->ref_count = 0;
                goto request_handler;
              }
            }
          }
          OC_ERR("could not create block-wise request buffer");
          goto init_reset_message;
        } else if (block2) {
          OC_DBG("processing block2 option");
          response_buffer = oc_blockwise_find_response_buffer(
            href, href_len, &msg->endpoint, message->code, message->uri_query,
            message->uri_query_len, OC_BLOCKWISE_SERVER);

          if (response_buffer && (response_buffer->next_block_offset -
                                  block2_offset) > block2_size) {
            oc_blockwise_free_response_buffer(response_buffer);
            response_buffer = NULL;
          }

          if (response_buffer) {
            OC_DBG("continuing ongoing block-wise transfer");
            uint32_t payload_size = 0;
            const void *payload = oc_blockwise_dispatch_block(
              response_buffer, block2_offset, block2_size, &payload_size);
            if (payload) {
              OC_DBG("dispatching next block");
              uint8_t more = (response_buffer->next_block_offset <
                              response_buffer->payload_size)
                               ? 1
                               : 0;
              if (more == 0) {
                if (message->type == COAP_TYPE_CON) {
                  coap_send_empty_response(COAP_TYPE_ACK, message->mid, NULL, 0,
                                           0, &msg->endpoint);
                }
                coap_udp_init_message(response, COAP_TYPE_CON, CONTENT_2_05,
                                      coap_get_mid());
                transaction->mid = response->mid;
                coap_set_header_accept(response, APPLICATION_VND_OCF_CBOR);
              }
              coap_set_header_content_format(response,
                                             APPLICATION_VND_OCF_CBOR);
              coap_set_payload(response, payload, payload_size);
              coap_set_header_block2(response, block2_num, more, block2_size);
              oc_blockwise_response_state_t *response_state =
                (oc_blockwise_response_state_t *)response_buffer;
              coap_set_header_etag(response, response_state->etag,
                                   COAP_ETAG_LEN);
              response_buffer->ref_count = more;
              goto send_message;
            } else {
              OC_ERR("could not dispatch block");
            }
          } else {
            OC_DBG("requesting block-wise transfer; creating new block-wise "
                   "response buffer");
            if (block2_num == 0) {
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
                    OC_ERR("could not create buffer to hold request payload");
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
              OC_ERR("initiating block-wise transfer with request for "
                     "block_num > 0");
            }
          }
          goto init_reset_message;
        } else {
          OC_DBG("no block options; processing regular request");
#ifdef OC_TCP
          if ((msg->endpoint.flags & TCP &&
               incoming_block_len <= (uint32_t)OC_MAX_APP_DATA_SIZE) ||
              (!(msg->endpoint.flags & TCP) &&
               incoming_block_len <= block1_size)) {
#else  /* OC_TCP */
          if (incoming_block_len <= block1_size) {
#endif /* !OC_TCP */
            if (incoming_block_len > 0) {
              OC_DBG("creating request buffer");
              request_buffer = oc_blockwise_find_request_buffer(
                href, href_len, &msg->endpoint, message->code,
                message->uri_query, message->uri_query_len,
                OC_BLOCKWISE_SERVER);

              if (request_buffer) {
                oc_blockwise_free_request_buffer(request_buffer);
                request_buffer = NULL;
              }

              request_buffer = oc_blockwise_alloc_request_buffer(
                href, href_len, &msg->endpoint, message->code,
                OC_BLOCKWISE_SERVER);

              if (!(request_buffer &&
                    oc_blockwise_handle_block(request_buffer, 0, incoming_block,
                                              (uint16_t)incoming_block_len))) {
                OC_ERR("could not create buffer to hold request payload");
                goto init_reset_message;
              }
              if (message->uri_query_len > 0) {
                oc_new_string(&request_buffer->uri_query, message->uri_query,
                              message->uri_query_len);
              }
              request_buffer->payload_size = incoming_block_len;
              request_buffer->ref_count = 0;
            }
            response_buffer = oc_blockwise_find_response_buffer(
              href, href_len, &msg->endpoint, message->code, message->uri_query,
              message->uri_query_len, OC_BLOCKWISE_SERVER);
            if (response_buffer) {
              if ((msg->endpoint.flags & MULTICAST) &&
                  response_buffer->next_block_offset <
                    response_buffer->payload_size) {
                OC_DBG("Dropping duplicate block-wise transfer request due to "
                       "repeated multicast");
                coap_status_code = CLEAR_TRANSACTION;
                goto send_message;
              } else {
                oc_blockwise_free_response_buffer(response_buffer);
                response_buffer = NULL;
              }
            }
            goto request_handler;
          } else {
            OC_ERR("incoming payload size exceeds block size");
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
        if (oc_ri_invoke_coap_entity_handler(message, response, &request_buffer,
                                             &response_buffer, block2_size,
                                             &msg->endpoint)) {
#else  /* OC_BLOCK_WISE */
        if (oc_ri_invoke_coap_entity_handler(message, response,
                                             transaction->message->data +
                                               COAP_MAX_HEADER_SIZE,
                                             &msg->endpoint)) {
#endif /* !OC_BLOCK_WISE */
#ifdef OC_BLOCK_WISE
          uint32_t payload_size = 0;
#ifdef OC_TCP
          if (msg->endpoint.flags & TCP) {
            const void *payload = oc_blockwise_dispatch_block(
              response_buffer, 0, response_buffer->payload_size + 1,
              &payload_size);
            if (payload && response_buffer->payload_size > 0) {
              coap_set_payload(response, payload, payload_size);
            }
            response_buffer->ref_count = 0;
          } else {
#endif /* OC_TCP */
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
              coap_set_header_etag(response, response_state->etag,
                                   COAP_ETAG_LEN);
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
        if (!request_buffer) {
          request_buffer = oc_blockwise_find_request_buffer_by_token(
            message->token, message->token_len);
        }
      }
      if (!error_response && request_buffer &&
          (block1 || message->code == REQUEST_ENTITY_TOO_LARGE_4_13)) {
        OC_DBG("found request buffer for uri %s",
               oc_string(request_buffer->href));
        client_cb = (oc_client_cb_t *)request_buffer->client_cb;
        uint32_t payload_size = 0;
        const void *payload = 0;

        if (block1) {
          payload = oc_blockwise_dispatch_block(request_buffer,
                                                block1_offset + block1_size,
                                                block1_size, &payload_size);
        } else {
          OC_DBG("initiating block-wise transfer with block1 option");
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
          OC_DBG("dispatching next block");
          transaction = coap_new_transaction(response_mid, &msg->endpoint);
          if (transaction) {
            coap_udp_init_message(response, COAP_TYPE_CON, client_cb->method,
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
            coap_set_header_accept(response, APPLICATION_VND_OCF_CBOR);
            coap_set_header_content_format(response, APPLICATION_VND_OCF_CBOR);
            request_buffer->mid = response_mid;
            goto send_message;
          }
        } else {
          request_buffer->ref_count = 0;
        }
      }

      if (request_buffer &&
          (request_buffer->ref_count == 0 || error_response)) {
        oc_blockwise_free_request_buffer(request_buffer);
        request_buffer = NULL;
      }

      if (client_cb) {
        response_buffer = oc_blockwise_find_response_buffer_by_client_cb(
          &msg->endpoint, client_cb);
        if (!response_buffer) {
          response_buffer = oc_blockwise_alloc_response_buffer(
            oc_string(client_cb->uri) + 1, oc_string_len(client_cb->uri) - 1,
            &msg->endpoint, client_cb->method, OC_BLOCKWISE_CLIENT);
          if (response_buffer) {
            OC_DBG("created new response buffer for uri %s",
                   oc_string(response_buffer->href));
            response_buffer->client_cb = client_cb;
          }
        }
      } else {
        response_buffer =
          oc_blockwise_find_response_buffer_by_mid(message->mid);
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
        coap_get_header_observe(message,
                                (uint32_t *)&response_state->observe_seq);

        const uint8_t *incoming_block;
        uint32_t incoming_block_len =
          (uint32_t)coap_get_payload(message, &incoming_block);
        if (incoming_block_len > 0 &&
            oc_blockwise_handle_block(response_buffer, block2_offset,
                                      incoming_block,
                                      (uint32_t)incoming_block_len)) {
          OC_DBG("processing incoming block");
          if (block2 && block2_more) {
            OC_DBG("issuing request for next block");
            transaction = coap_new_transaction(response_mid, &msg->endpoint);
            if (transaction) {
              coap_udp_init_message(response, COAP_TYPE_CON, client_cb->method,
                                    response_mid);
              response_buffer->mid = response_mid;
              coap_set_header_accept(response, APPLICATION_VND_OCF_CBOR);
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

#endif /* OC_BLOCK_WISE */

      if (client_cb) {
        OC_DBG("calling oc_ri_invoke_client_cb");
#ifdef OC_BLOCK_WISE
        if (request_buffer) {
          request_buffer->ref_count = 0;
        }

        oc_ri_invoke_client_cb(message, &response_buffer, client_cb,
                               &msg->endpoint);
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
        oc_ri_invoke_client_cb(message, client_cb, &msg->endpoint);
#endif /* OC_BLOCK_WISE */
      }
#endif /* OC_CLIENT */
    }
  } else {
    OC_ERR("Unexpected CoAP command");
#ifdef OC_SECURITY
    coap_audit_log(msg);
#endif /* OC_SECURITY */
    if (msg->endpoint.flags & TCP) {
      coap_send_empty_response(COAP_TYPE_NON, 0, message->token,
                               message->token_len, coap_status_code,
                               &msg->endpoint);
    } else {
      coap_send_empty_response(message->type == COAP_TYPE_CON ? COAP_TYPE_ACK
                                                              : COAP_TYPE_NON,
                               message->mid, message->token, message->token_len,
                               coap_status_code, &msg->endpoint);
    }
    return coap_status_code;
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
  if (coap_status_code == CLEAR_TRANSACTION) {
    coap_clear_transaction(transaction);
  } else if (transaction) {
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
    transaction->message->length =
      coap_serialize_message(response, transaction->message->data);
    if (transaction->message->length > 0) {
      coap_send_transaction(transaction);
    } else {
      coap_clear_transaction(transaction);
    }
  }

#ifdef OC_SECURITY
  if (coap_status_code == CLOSE_ALL_TLS_SESSIONS) {
    oc_close_all_tls_sessions_for_device(msg->endpoint.device);
  }
#endif /* OC_SECURITY */

#ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers(false);
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
