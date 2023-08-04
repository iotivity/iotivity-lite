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

#ifndef ENGINE_H
#define ENGINE_H

#include "coap.h"
#include "port/oc_connectivity.h"
#include "transactions.h"
#include "util/oc_compiler.h"
#include "util/oc_process.h"

#ifdef OC_BLOCK_WISE
#include "api/oc_blockwise_internal.h"
#endif /* OC_BLOCK_WISE */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

OC_PROCESS_NAME(g_coap_engine);

enum {
  COAP_SUCCESS = 0,
  COAP_SKIP_DUPLICATE_MESSAGE,
  COAP_SEND_EMPTY_MESSAGE,
  COAP_INVOKE_HANDLER,
};

int coap_process_inbound_message(oc_message_t *message) OC_NONNULL();

typedef struct
{
  uint32_t num;
  uint32_t offset;
  uint16_t size;
  uint8_t more;
  bool enabled;
} coap_block_options_t;

coap_block_options_t coap_packet_get_block_options(const coap_packet_t *message,
                                                   bool block2);

typedef struct coap_make_response_ctx_t
{
  const coap_packet_t *request;
  coap_packet_t *response;
#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t **request_state;
  oc_blockwise_state_t **response_state;
  uint16_t block2_size;
#else  /* !OC_BLOCK_WISE */
  uint8_t *buffer;
#endif /* OC_BLOCK_WISE */
} coap_make_response_ctx_t;

/** @brief Callback function to create a response to the coap request */
typedef bool (*coap_make_response_fn_t)(coap_make_response_ctx_t *,
                                        oc_endpoint_t *, void *);

typedef struct
{
  const coap_packet_t *request;
  coap_packet_t *response;
  coap_transaction_t *transaction;
  coap_block_options_t block1;
  coap_block_options_t block2;
#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *request_buffer;
  oc_blockwise_state_t *response_buffer;
#endif /* OC_BLOCK_WISE */
} coap_receive_ctx_t;

int coap_receive(coap_receive_ctx_t *ctx, oc_endpoint_t *endpoint,
                 coap_make_response_fn_t response_fn, void *response_fn_data)
  OC_NONNULL(1, 2, 3);

bool oc_coap_check_if_duplicate(uint16_t mid, uint32_t device);

#ifdef __cplusplus
}
#endif

#endif /* ENGINE_H */
