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

#include "messaging/coap/engine.h"
#include "oc_signal_event_loop.h"
#include "util/oc_memb.h"
#include <stdint.h>
#include <stdio.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_SECURITY
#include "security/oc_dtls.h"
#endif /* OC_SECURITY */

#include "config.h"
#include "oc_buffer.h"
#include "oc_events.h"

OC_PROCESS(message_buffer_handler, "OC Message Buffer Handler");
OC_MEMB(oc_buffers_s, oc_message_t, (OC_MAX_NUM_CONCURRENT_REQUESTS * 2));

oc_message_t *
oc_allocate_message(void)
{
  oc_message_t *message = (oc_message_t *)oc_memb_alloc(&oc_buffers_s);
  if (message) {
#ifdef OC_DYNAMIC_ALLOCATION
    message->data = malloc(OC_PDU_SIZE);
    if (!message->data) {
      oc_memb_free(&oc_buffers_s, message);
      return NULL;
    }
#endif /* OC_DYNAMIC_ALLOCATION */
    message->length = 0;
    message->next = 0;
    message->ref_count = 1;
#ifndef OC_DYNAMIC_ALLOCATION
    OC_DBG("buffer: Allocated TX/RX buffer; num free: %d\n",
           oc_memb_numfree(&oc_buffers_s));
#endif /* !OC_DYNAMIC_ALLOCATION */
  }
#ifndef OC_DYNAMIC_ALLOCATION
  else {
    OC_WRN("buffer: No free TX/RX buffers!\n");
  }
#endif /* !OC_DYNAMIC_ALLOCATION */
  return message;
}

void
oc_message_add_ref(oc_message_t *message)
{
  if (message)
    message->ref_count++;
}

void
oc_message_unref(oc_message_t *message)
{
  if (message) {
    message->ref_count--;
    if (message->ref_count <= 0) {
#ifdef OC_DYNAMIC_ALLOCATION
      free(message->data);
#endif /* OC_DYNAMIC_ALLOCATION */
      oc_memb_free(&oc_buffers_s, message);
#ifndef OC_DYNAMIC_ALLOCATION
      OC_DBG("buffer: freed TX/RX buffer; num free: %d\n",
             oc_memb_numfree(&oc_buffers_s));
#endif /* !OC_DYNAMIC_ALLOCATION */
    }
  }
}

void
oc_recv_message(oc_message_t *message)
{
  if (oc_process_post(&message_buffer_handler, oc_events[INBOUND_NETWORK_EVENT],
                      message) == OC_PROCESS_ERR_FULL)
    oc_message_unref(message);
}

void
oc_send_message(oc_message_t *message)
{
  if (oc_process_post(&message_buffer_handler,
                      oc_events[OUTBOUND_NETWORK_EVENT],
                      message) == OC_PROCESS_ERR_FULL)
    message->ref_count--;

  _oc_signal_event_loop();
}

OC_PROCESS_THREAD(message_buffer_handler, ev, data)
{
  OC_PROCESS_BEGIN();
  OC_DBG("Started buffer handler process\n");
  while (1) {
    OC_PROCESS_YIELD();

    if (ev == oc_events[INBOUND_NETWORK_EVENT]) {
#ifdef OC_SECURITY
      uint8_t b = (uint8_t)((oc_message_t *)data)->data[0];
      if (b > 19 && b < 64) {
        OC_DBG("Inbound network event: encrypted request\n");
        oc_process_post(&oc_dtls_handler, oc_events[UDP_TO_DTLS_EVENT], data);
      } else {
        OC_DBG("Inbound network event: decrypted request\n");
        oc_process_post(&coap_engine, oc_events[INBOUND_RI_EVENT], data);
      }
#else  /* OC_SECURITY */
      OC_DBG("Inbound network event: decrypted request\n");
      oc_process_post(&coap_engine, oc_events[INBOUND_RI_EVENT], data);
#endif /* !OC_SECURITY */
    } else if (ev == oc_events[OUTBOUND_NETWORK_EVENT]) {
      oc_message_t *message = (oc_message_t *)data;

#ifdef OC_CLIENT
      if (message->endpoint.flags & DISCOVERY) {
        OC_DBG("Outbound network event: multicast request\n");
        oc_send_discovery_request(message);
        oc_message_unref(message);
      } else
#endif /* OC_CLIENT */
#ifdef OC_SECURITY
        if (message->endpoint.flags & SECURED) {
        OC_DBG("Outbound network event: forwarding to DTLS\n");

#ifdef OC_CLIENT
        if (!oc_sec_dtls_connected(&message->endpoint)) {
          OC_DBG("Posting INIT_DTLS_CONN_EVENT\n");
          oc_process_post(&oc_dtls_handler, oc_events[INIT_DTLS_CONN_EVENT],
                          data);
        } else
#endif /* OC_CLIENT */
        {
          OC_DBG("Posting RI_TO_DTLS_EVENT\n");
          oc_process_post(&oc_dtls_handler, oc_events[RI_TO_DTLS_EVENT], data);
        }
      } else
#endif /* OC_SECURITY */
      {
        OC_DBG("Outbound network event: unicast message\n");
        oc_send_buffer(message);
        oc_message_unref(message);
      }
    }
  }
  OC_PROCESS_END();
}
