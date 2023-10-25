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

#ifndef COAP_SEPARATE_INTERNAL_H
#define COAP_SEPARATE_INTERNAL_H

#include "coap_internal.h"
#include "oc_coap.h"
#include "oc_ri.h"
#include "transactions_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coap_separate
{
  struct coap_separate *next;
  coap_message_type_t type;
  uint8_t token_len;
  uint8_t token[COAP_TOKEN_LEN];
  uint16_t block2_size;
  int32_t observe;
  oc_endpoint_t endpoint;
  oc_method_t method;
  oc_string_t uri;
} coap_separate_t;

/**
 * \brief Initiate a separate response with an empty ACK
 * \param request The request to accept
 * \param separate_response A pointer to the data structure that will store the
 *   relevant information for the response
 * \return true if the response was initiated
 * \return false otherwise
 *
 * When the server does not have enough resources left to store the information
 * for a separate response or otherwise cannot execute the resource handler,
 * this function will respond with 5.03 Service Unavailable. The client can
 * then retry later.
 */
bool coap_separate_accept(const coap_packet_t *request,
                          oc_separate_response_t *separate_response,
                          const oc_endpoint_t *endpoint, int observe,
                          uint16_t block2_size);

void coap_separate_resume(coap_packet_t *response,
                          const coap_separate_t *separate_store, uint8_t code,
                          uint16_t mid);

void coap_separate_clear(oc_separate_response_t *separate_response,
                         coap_separate_t *separate_store);

#ifdef __cplusplus
}
#endif

#endif /* COAP_SEPARATE_INTERNAL_H */
