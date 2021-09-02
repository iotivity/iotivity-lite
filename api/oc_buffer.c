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
#include "port/oc_network_events_mutex.h"
#include "util/oc_memb.h"
#include <stdint.h>
#include <stdio.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_SECURITY
#include "security/oc_tls.h"
#ifdef OC_OSCORE
#include "security/oc_oscore.h"
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */

#include "oc_buffer.h"
#include "oc_config.h"
#include "oc_events.h"

OC_PROCESS(message_buffer_handler, "OC Message Buffer Handler");
#ifdef OC_INOUT_BUFFER_POOL
OC_MEMB_STATIC(oc_incoming_buffers, oc_message_t, OC_INOUT_BUFFER_POOL);
OC_MEMB_STATIC(oc_outgoing_buffers, oc_message_t, OC_INOUT_BUFFER_POOL);
#else  /* OC_INOUT_BUFFER_POOL */
OC_MEMB(oc_incoming_buffers, oc_message_t, OC_MAX_NUM_CONCURRENT_REQUESTS);
OC_MEMB(oc_outgoing_buffers, oc_message_t, OC_MAX_NUM_CONCURRENT_REQUESTS);
#endif /* !OC_INOUT_BUFFER_POOL */

static oc_message_t *
allocate_message(struct oc_memb *pool)
{
  oc_network_event_handler_mutex_lock();
  oc_message_t *message = (oc_message_t *)oc_memb_alloc(pool);
  oc_network_event_handler_mutex_unlock();
  if (message) {
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
    message->data = malloc(OC_PDU_SIZE);
    if (!message->data) {
      oc_memb_free(pool, message);
      return NULL;
    }
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
    message->pool = pool;
    message->length = 0;
    message->next = 0;
    message->ref_count = 1;
    message->endpoint.interface_index = -1;
#ifdef OC_SECURITY
    message->encrypted = 0;
#endif /* OC_SECURITY */
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_SIZE)
    OC_DBG("buffer: Allocated TX/RX buffer; num free: %d",
           oc_memb_numfree(pool));
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  }
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_SIZE)
  else {
    OC_WRN("buffer: No free TX/RX buffers!");
  }
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  return message;
}

oc_message_t *
oc_allocate_message_from_pool(struct oc_memb *pool)
{
  if (pool) {
    return allocate_message(pool);
  }
  return NULL;
}

void
oc_set_buffers_avail_cb(oc_memb_buffers_avail_callback_t cb)
{
  oc_memb_set_buffers_avail_cb(&oc_incoming_buffers, cb);
}

oc_message_t *
oc_allocate_message(void)
{
  return allocate_message(&oc_incoming_buffers);
}

oc_message_t *
oc_internal_allocate_outgoing_message(void)
{
  return allocate_message(&oc_outgoing_buffers);
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
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
      free(message->data);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
      struct oc_memb *pool = message->pool;
      oc_memb_free(pool, message);
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_SIZE)
      OC_DBG("buffer: freed TX/RX buffer; num free: %d", oc_memb_numfree(pool));
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
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

#ifdef OC_SECURITY
void
oc_close_all_tls_sessions_for_device(size_t device)
{
  oc_process_post(&message_buffer_handler, oc_events[TLS_CLOSE_ALL_SESSIONS],
                  (oc_process_data_t)device);
}

void
oc_close_all_tls_sessions(void)
{
  oc_process_poll(&(oc_tls_handler));
  _oc_signal_event_loop();
}
#endif /* OC_SECURITY */

OC_PROCESS_THREAD(message_buffer_handler, ev, data)
{
  OC_PROCESS_BEGIN();
  OC_DBG("Started buffer handler process");
  while (1) {
    OC_PROCESS_YIELD();

    if (ev == oc_events[INBOUND_NETWORK_EVENT]) {
#ifdef OC_SECURITY
      if (((oc_message_t *)data)->encrypted == 1) {
        OC_DBG("Inbound network event: encrypted request");
        oc_process_post(&oc_tls_handler, oc_events[UDP_TO_TLS_EVENT], data);
      } else {
#ifdef OC_OSCORE
        if (((oc_message_t *)data)->endpoint.flags & MULTICAST) {
          OC_DBG("Inbound network event: multicast request");
          oc_process_post(&oc_oscore_handler, oc_events[INBOUND_OSCORE_EVENT],
                          data);
        } else {
          OC_DBG("Inbound network event: decrypted request");
          oc_process_post(&coap_engine, oc_events[INBOUND_RI_EVENT], data);
        }
#else  /* OC_OSCORE */
        OC_DBG("Inbound network event: decrypted request");
        oc_process_post(&coap_engine, oc_events[INBOUND_RI_EVENT], data);
#endif /* OC_OSCORE */
      }
#else  /* OC_SECURITY */
      OC_DBG("Inbound network event: decrypted request");
      oc_process_post(&coap_engine, oc_events[INBOUND_RI_EVENT], data);
#endif /* !OC_SECURITY */
    } else if (ev == oc_events[OUTBOUND_NETWORK_EVENT]) {
      oc_message_t *message = (oc_message_t *)data;

#ifdef OC_CLIENT
      if (message->endpoint.flags & DISCOVERY) {
        OC_DBG("Outbound network event: multicast request");
        oc_send_discovery_request(message);
        oc_message_unref(message);
      }
#if defined(OC_SECURITY) && defined(OC_OSCORE)
      else if ((message->endpoint.flags & MULTICAST) &&
               (message->endpoint.flags & SECURED)) {
        OC_DBG("Outbound secure multicast request: forwarding to OSCORE");
        oc_process_post(&oc_oscore_handler,
                        oc_events[OUTBOUND_GROUP_OSCORE_EVENT], data);
      }
#endif /* OC_SECURITY && OC_OSCORE */
      else
#endif /* OC_CLIENT */
#ifdef OC_SECURITY
        if (message->endpoint.flags & SECURED) {
#ifdef OC_OSCORE
        OC_DBG("Outbound network event: forwarding to OSCORE");
        oc_process_post(&oc_oscore_handler, oc_events[OUTBOUND_OSCORE_EVENT],
                        data);
      } else
#else /* OC_OSCORE */
#ifdef OC_CLIENT
        OC_DBG("Outbound network event: forwarding to TLS");
        if (!oc_tls_connected(&message->endpoint)) {
          OC_DBG("Posting INIT_TLS_CONN_EVENT");
          oc_process_post(&oc_tls_handler, oc_events[INIT_TLS_CONN_EVENT],
                          data);
        } else
#endif /* OC_CLIENT */
        {
          OC_DBG("Posting RI_TO_TLS_EVENT");
          oc_process_post(&oc_tls_handler, oc_events[RI_TO_TLS_EVENT], data);
        }
      } else
#endif /* !OC_OSCORE */
#endif /* OC_SECURITY */
      {
        OC_DBG("Outbound network event: unicast message");
        oc_send_buffer(message);
        oc_message_unref(message);
      }
    }
#ifdef OC_SECURITY
    else if (ev == oc_events[TLS_CLOSE_ALL_SESSIONS]) {
      OC_DBG("Signaling to close all TLS sessions from this device");
      oc_process_post(&oc_tls_handler, oc_events[TLS_CLOSE_ALL_SESSIONS], data);
    }
#endif /* OC_SECURITY */
  }
  OC_PROCESS_END();
}
