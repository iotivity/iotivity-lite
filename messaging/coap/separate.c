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

#include "config.h"

#ifdef OC_SERVER

#include "oc_buffer.h"
#include "separate.h"
#include "transactions.h"
#include "util/oc_memb.h"
#include <stdio.h>
#include <string.h>

OC_MEMB(separate_requests, coap_separate_t, OC_MAX_NUM_CONCURRENT_REQUESTS);

/*---------------------------------------------------------------------------*/
/*- Separate Response API ---------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/**
 * \brief Initiate a separate response with an empty ACK
 * \param request The request to accept
 * \param separate_store A pointer to the data structure that will store the
 *   relevant information for the response
 *
 * When the server does not have enough resources left to store the information
 * for a separate response or otherwise cannot execute the resource handler,
 * this function will respond with 5.03 Service Unavailable. The client can
 * then retry later.
 */
#ifdef OC_BLOCK_WISE
int
coap_separate_accept(void *request, oc_separate_response_t *separate_response,
                     oc_endpoint_t *endpoint, int observe, uint16_t block2_size)
#else  /* OC_BLOCK_WISE */
int
coap_separate_accept(void *request, oc_separate_response_t *separate_response,
                     oc_endpoint_t *endpoint, int observe)
#endif /* !OC_BLOCK_WISE */
{
  if (separate_response->active == 0) {
    OC_LIST_STRUCT_INIT(separate_response, requests);
#ifdef OC_DYNAMIC_ALLOCATION
    separate_response->buffer = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  coap_packet_t *const coap_req = (coap_packet_t *)request;

  for (coap_separate_t *item = oc_list_head(separate_response->requests);
       item != NULL; item = item->next) {
    if (item->token_len == coap_req->token_len &&
        memcmp(item->token, coap_req->token, item->token_len) == 0) {
      return 0;
    }
  }

  coap_separate_t *separate_store = oc_memb_alloc(&separate_requests);

  if (!separate_store) {
    OC_WRN("insufficient memory to store new request for separate response\n");
    return 0;
  }

  oc_list_add(separate_response->requests, separate_store);

  coap_status_code = CLEAR_TRANSACTION;
  /* send separate ACK for CON */
  if (coap_req->type == COAP_TYPE_CON) {
    OC_DBG("Sending ACK for separate response\n");
    coap_packet_t ack[1];
    /* ACK with empty code (0) */
    coap_init_message(ack, COAP_TYPE_ACK, 0, coap_req->mid);
    if (observe < 2) {
      coap_set_header_observe(ack, observe);
    }
    coap_set_token(ack, coap_req->token, coap_req->token_len);
    oc_message_t *message = oc_allocate_message();
    if (message != NULL) {
      memcpy(&message->endpoint, endpoint, sizeof(oc_endpoint_t));
      message->length = coap_serialize_message(ack, message->data);
      coap_send_message(message);
      if (message->ref_count == 0)
        oc_message_unref(message);
    } else {
      coap_separate_clear(separate_response, separate_store);
      return 0;
    }
  }
  memcpy(&separate_store->endpoint, endpoint, sizeof(oc_endpoint_t));

  /* store correct response type */
  separate_store->type = COAP_TYPE_NON;

  memcpy(separate_store->token, coap_req->token, coap_req->token_len);
  separate_store->token_len = coap_req->token_len;

  oc_new_string(&separate_store->uri, coap_req->uri_path,
                coap_req->uri_path_len);

  separate_store->method = coap_req->code;

#ifdef OC_BLOCK_WISE
  separate_store->block2_size = block2_size;
#endif /* OC_BLOCK_WISE */

  separate_store->observe = observe;
  return 1;
}
/*----------------------------------------------------------------------------*/
void
coap_separate_resume(void *response, coap_separate_t *separate_store,
                     uint8_t code, uint16_t mid)
{
  coap_init_message(response, separate_store->type, code, mid);
  if (separate_store->token_len) {
    coap_set_token(response, separate_store->token, separate_store->token_len);
  }
}
/*---------------------------------------------------------------------------*/
void
coap_separate_clear(oc_separate_response_t *separate_response,
                    coap_separate_t *separate_store)
{
#ifdef OC_BLOCK_WISE
  if (oc_string_len(separate_store->uri) > 0)
    oc_free_string(&separate_store->uri);
#endif /* OC_BLOCK_WISE */
  oc_list_remove(separate_response->requests, separate_store);
  oc_memb_free(&separate_requests, separate_store);
}

#endif /* OC_SERVER */
