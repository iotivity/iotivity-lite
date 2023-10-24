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

#include "oc_config.h"

#ifdef OC_SERVER

#include "api/oc_message_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/log_internal.h"
#include "messaging/coap/separate_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_buffer.h"
#include "util/oc_memb.h"
#include <stdio.h>
#include <string.h>

OC_MEMB(g_separate_requests, coap_separate_t, OC_MAX_NUM_CONCURRENT_REQUESTS);

/*---------------------------------------------------------------------------*/
/*- Separate Response API ---------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

bool
coap_separate_accept(const coap_packet_t *request,
                     oc_separate_response_t *separate_response,
                     const oc_endpoint_t *endpoint, int observe,
                     uint16_t block2_size)
{
#ifndef OC_BLOCK_WISE
  (void)block2_size;
#endif /* !OC_BLOCK_WISE */

  coap_set_global_status_code(CLEAR_TRANSACTION);

  if (separate_response->active == 0) {
    OC_LIST_STRUCT_INIT(separate_response, requests);
#ifdef OC_DYNAMIC_ALLOCATION
    separate_response->buffer = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
    if (!separate_response->buffer) {
      COAP_WRN("insufficient memory to store separate response");
      return false;
    }
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  coap_separate_t *separate_store = NULL;
  for (separate_store = oc_list_head(separate_response->requests);
       separate_store != NULL; separate_store = separate_store->next) {
    if (separate_store->token_len == request->token_len &&
        memcmp(separate_store->token, request->token,
               separate_store->token_len) == 0 &&
        separate_store->observe == observe) {
      break;
    }
  }

  if (!separate_store) {
    separate_store = oc_memb_alloc(&g_separate_requests);

    if (!separate_store) {
      COAP_WRN(
        "insufficient memory to store new request for separate response");
      return false;
    }

    /* store correct response type */
    separate_store->type = COAP_TYPE_NON;

    memcpy(separate_store->token, request->token, request->token_len);
    separate_store->token_len = request->token_len;

    oc_new_string(&separate_store->uri, request->uri_path,
                  request->uri_path_len);

    separate_store->method = request->code;

#ifdef OC_BLOCK_WISE
    separate_store->block2_size = block2_size;
#endif /* OC_BLOCK_WISE */

    separate_store->observe = observe;

    oc_list_add(separate_response->requests, separate_store);
  }

  memcpy(&separate_store->endpoint, endpoint, sizeof(oc_endpoint_t));

  /* send separate ACK for CON */
  if (request->type == COAP_TYPE_CON) {
    COAP_DBG("Sending ACK for separate response");
    coap_packet_t ack;
    /* ACK with empty code (0) */
    coap_udp_init_message(&ack, COAP_TYPE_ACK, 0, request->mid);
    oc_message_t *message = oc_message_allocate_outgoing();
    if (message == NULL) {
      coap_separate_clear(separate_response, separate_store);
      return false;
    }
    message->length =
      coap_serialize_message(&ack, message->data, oc_message_buffer_size());
    if (message->length == 0) {
      oc_message_unref(message);
      coap_separate_clear(separate_response, separate_store);
      return false;
    }
    memcpy(&message->endpoint, endpoint, sizeof(oc_endpoint_t));
    coap_send_message(message);

    if (message->ref_count == 0) {
      oc_message_unref(message);
    }
  }

  return true;
}

void
coap_separate_resume(coap_packet_t *response,
                     const coap_separate_t *separate_store, uint8_t code,
                     uint16_t mid)
{
#ifdef OC_TCP
  if ((separate_store->endpoint.flags & TCP) != 0) {
    coap_tcp_init_message(response, code);
  } else
#endif /* OC_TCP */
  {
    coap_udp_init_message(response, separate_store->type, code, mid);
  }
  if (separate_store->token_len) {
    coap_set_token(response, separate_store->token, separate_store->token_len);
  }
}

void
coap_separate_clear(oc_separate_response_t *separate_response,
                    coap_separate_t *separate_store)
{
#ifdef OC_BLOCK_WISE
  oc_free_string(&separate_store->uri);
#endif /* OC_BLOCK_WISE */
  oc_list_remove(separate_response->requests, separate_store);
  oc_memb_free(&g_separate_requests, separate_store);
}

#endif /* OC_SERVER */
