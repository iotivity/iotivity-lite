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

#include "api/oc_endpoint_internal.h"
#include "api/oc_main_internal.h"
#include "api/oc_message_internal.h"
#include "log_internal.h"
#include "observe_internal.h"
#include "oc_buffer.h"
#include "transactions_internal.h"
#include "util/oc_list.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"
#include "util/oc_macros_internal.h"
#include <string.h>

#ifdef OC_BLOCK_WISE
#include "api/oc_blockwise_internal.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif /* OC_CLIENT */

#ifdef OC_SECURITY
#include "security/oc_tls_internal.h"
#endif

OC_MEMB(transactions_memb, coap_transaction_t, COAP_MAX_OPEN_TRANSACTIONS);
OC_LIST(transactions_list);

static struct oc_process *transaction_handler_process = NULL;

/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
void
coap_register_as_transaction_handler(void)
{
  transaction_handler_process = OC_PROCESS_CURRENT();
}

coap_transaction_t *
coap_new_transaction(uint16_t mid, const uint8_t *token, uint8_t token_len,
                     const oc_endpoint_t *endpoint)
{
  coap_transaction_t *t = oc_memb_alloc(&transactions_memb);
  if (t == NULL) {
    COAP_ERR("insufficient memory to create transaction");
    return NULL;
  }

  t->message = oc_message_allocate_outgoing();
  if (t->message == NULL) {
    oc_memb_free(&transactions_memb, t);
    return NULL;
  }

  COAP_DBG("Created new transaction %u: %p", mid, (void *)t);
  t->mid = mid;
  if (token_len > 0) {
    memcpy(t->token, token, token_len);
    t->token_len = token_len;
  }
  t->retrans_counter = 0;

  /* save client address */
  memcpy(&t->message->endpoint, endpoint, sizeof(oc_endpoint_t));

  oc_list_add(transactions_list,
              t); /* list itself makes sure same element is not added twice */
  return t;
}

void
coap_send_transaction(coap_transaction_t *t)
{
  if (!oc_main_initialized()) {
    return;
  }
  bool confirmable =
    (COAP_TYPE_CON == ((COAP_HEADER_TYPE_MASK & t->message->data[0]) >>
                       COAP_HEADER_TYPE_POSITION));
#ifdef OC_TCP
  confirmable = confirmable && (t->message->endpoint.flags & TCP) == 0;
#endif /* OC_TCP */

  COAP_DBG("Sending transaction(len: %zd, confirmable: %d) %u: %p",
           t->message->length, (int)confirmable, t->mid, (void *)t);
  COAP_LOGbytes(t->message->data, t->message->length);

  if (!confirmable) {
    oc_message_add_ref(t->message);

    coap_send_message(t->message);

    coap_clear_transaction(t);
    return;
  }

  if (t->retrans_counter < COAP_MAX_RETRANSMIT) {
    /* not timed out yet */
    COAP_DBG("Keeping transaction %u: %p", t->mid, (void *)t);

    if (t->retrans_counter == 0) {
      t->retrans_timer.timer.interval =
        COAP_RESPONSE_TIMEOUT_TICKS +
        (oc_random_value() %
         (oc_clock_time_t)COAP_RESPONSE_TIMEOUT_BACKOFF_MASK);
      COAP_DBG("Initial interval %d", (int)t->retrans_timer.timer.interval);
    } else {
      t->retrans_timer.timer.interval <<= 1; /* double */
      COAP_DBG("Doubled %d", (int)t->retrans_timer.timer.interval);
    }

    OC_PROCESS_CONTEXT_BEGIN(transaction_handler_process)
    oc_etimer_restart(&t->retrans_timer); /* interval updated above */
    OC_PROCESS_CONTEXT_END(transaction_handler_process)

    oc_message_add_ref(t->message);

    coap_send_message(t->message);

    t = NULL;
  } else {
    /* timed out */
#if OC_WRN_IS_ENABLED
    char endpoint_buf[256];
    memset(endpoint_buf, 0, sizeof(endpoint_buf));
    OC_SNPRINT_ENDPOINT_ADDR(endpoint_buf, sizeof(endpoint_buf),
                             t->message->endpoint, addr);
    COAP_WRN("Timeout for %s with mid %d", endpoint_buf, t->mid);
#endif /* OC_WRN_IS_ENABLED */
#ifdef OC_SERVER
    /* remove observers */
    coap_remove_observers_by_client(&t->message->endpoint);
#endif /* OC_SERVER */

#ifdef OC_CLIENT
    oc_ri_free_client_cbs_by_mid_v1(t->mid, OC_TRANSACTION_TIMEOUT);
#endif /* OC_CLIENT */

#ifdef OC_BLOCK_WISE
    oc_blockwise_free_all_buffers(false);
#endif /* OC_BLOCK_WISE */
#ifdef OC_SECURITY
    if (t->message->endpoint.flags & SECURED) {
      oc_tls_close_connection(&t->message->endpoint);
    } else
#endif /* OC_SECURITY */
    {
      coap_clear_transaction(t);
    }
  }
}

void
coap_clear_transaction(coap_transaction_t *t)
{
  if (t) {
    COAP_DBG("Freeing transaction %u: %p", t->mid, (void *)t);

    oc_etimer_stop(&t->retrans_timer);
    oc_message_unref(t->message);
    oc_list_remove(transactions_list, t);
    oc_memb_free(&transactions_memb, t);
  }
}
coap_transaction_t *
coap_get_transaction_by_mid(uint16_t mid)
{
  for (coap_transaction_t *t =
         (coap_transaction_t *)oc_list_head(transactions_list);
       t != NULL; t = t->next) {
    if (t->mid == mid) {
      COAP_DBG("Found transaction for MID %u: %p", t->mid, (void *)t);
      return t;
    }
  }
  return NULL;
}

coap_transaction_t *
coap_get_transaction_by_token(const uint8_t *token, uint8_t token_len)
{
  for (coap_transaction_t *t =
         (coap_transaction_t *)oc_list_head(transactions_list);
       t != NULL; t = t->next) {
    if (t->token_len == token_len && memcmp(t->token, token, token_len) == 0) {
      COAP_DBG("Found transaction by token %p", (void *)t);
      return t;
    }
  }
  return NULL;
}

void
coap_check_transactions(void)
{
  coap_transaction_t *t = (coap_transaction_t *)oc_list_head(transactions_list);
  while (t != NULL) {
    coap_transaction_t *next = t->next;
    if (oc_etimer_expired(&t->retrans_timer)) {
      ++(t->retrans_counter);
      COAP_DBG("Retransmitting %u (%u)", t->mid, t->retrans_counter);
      int removed = oc_list_length(transactions_list);
      coap_send_transaction(t);
      if ((removed - oc_list_length(transactions_list)) > 1) {
        t = (coap_transaction_t *)oc_list_head(transactions_list);
        continue;
      }
    }
    t = next;
  }
}

void
coap_free_all_transactions(void)
{
  coap_transaction_t *t = (coap_transaction_t *)oc_list_head(transactions_list);
  while (t != NULL) {
    coap_transaction_t *next = t->next;
    coap_clear_transaction(t);
    t = next;
  }
}

void
coap_free_transactions_by_endpoint(const oc_endpoint_t *endpoint,
                                   oc_status_t code)
{
#if OC_DBG_IS_ENABLED
  oc_string64_t ep_str;
  oc_endpoint_to_string64(endpoint, &ep_str);
  COAP_DBG("free transactions for endpoint(%s)", oc_string(ep_str));
#endif /* OC_DBG_IS_ENABLED */
#ifndef OC_CLIENT
  (void)code;
#endif /* !OC_CLIENT */
  coap_transaction_t *t = (coap_transaction_t *)oc_list_head(transactions_list);
  while (t != NULL) {
    coap_transaction_t *next = t->next;
    if (oc_endpoint_compare(&t->message->endpoint, endpoint) == 0) {
      int removed = oc_list_length(transactions_list);
#ifdef OC_CLIENT
      /* Remove the client callback tied to this transaction */
      oc_ri_free_client_cbs_by_mid_v1(t->mid, code);
#endif /* OC_CLIENT */
      if ((removed - oc_list_length(transactions_list)) > 0) {
        t = (coap_transaction_t *)oc_list_head(transactions_list);
        continue;
      }
      coap_clear_transaction(t);
    }
    t = next;
  }
}
