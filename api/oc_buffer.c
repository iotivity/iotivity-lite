/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "messaging/coap/engine.h"
#include "oc_buffer.h"
#include "oc_buffer_internal.h"
#include "oc_config.h"
#include "oc_events.h"
#include "oc_signal_event_loop.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_features.h"
#include "util/oc_memb.h"

#ifdef OC_SECURITY
#ifdef OC_OSCORE
#include "security/oc_oscore.h"
#endif /* OC_OSCORE */
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#include <stdint.h>
#include <stdio.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

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
    message->data = (uint8_t *)malloc(OC_PDU_SIZE);
    if (!message->data) {
      OC_ERR("Out of memory, cannot allocate message");
      oc_network_event_handler_mutex_lock();
      oc_memb_free(pool, message);
      oc_network_event_handler_mutex_unlock();
      return NULL;
    }
    memset(message->data, 0, OC_PDU_SIZE);
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
  if (message == NULL) {
    return;
  }
  bool swapped = false;
  uint8_t count = OC_ATOMIC_LOAD8(message->ref_count);
  while (!swapped) { // NOLINT(bugprone-infinite-loop)
    OC_ATOMIC_COMPARE_AND_SWAP8(message->ref_count, count, count + 1, swapped);
  }
}

void
oc_message_unref(oc_message_t *message)
{
  if (message == NULL) {
    return;
  }
  bool dealloc = false;
  uint8_t count = OC_ATOMIC_LOAD8(message->ref_count);
  while (count > 0) {
    bool swapped = false;
    uint8_t new_count = count - 1;
    OC_ATOMIC_COMPARE_AND_SWAP8(message->ref_count, count, new_count, swapped);
    if (swapped) {
      dealloc = new_count == 0;
      break;
    }
  }

  if (dealloc) {
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
    free(message->data);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
    struct oc_memb *pool = message->pool;
    oc_network_event_handler_mutex_lock();
    oc_memb_free(pool, message);
    oc_network_event_handler_mutex_unlock();
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_SIZE)
    OC_DBG("buffer: freed TX/RX buffer; num free: %d", oc_memb_numfree(pool));
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  }
}

void
oc_recv_message(oc_message_t *message)
{
  if (oc_process_post(&message_buffer_handler, oc_events[INBOUND_NETWORK_EVENT],
                      message) == OC_PROCESS_ERR_FULL) {
    oc_message_unref(message);
  }
}

void
oc_send_message(oc_message_t *message)
{
  if (oc_process_post(&message_buffer_handler,
                      oc_events[OUTBOUND_NETWORK_EVENT],
                      message) == OC_PROCESS_ERR_FULL) {
    oc_message_unref(message);
  }
  _oc_signal_event_loop();
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
void
oc_tcp_connect_session(oc_tcp_on_connect_event_t *event)
{
  if (oc_process_post(&message_buffer_handler, oc_events[TCP_CONNECT_SESSION],
                      event) == OC_PROCESS_ERR_FULL) {
    oc_tcp_on_connect_event_free(event);
  }
  _oc_signal_event_loop();
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

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
  oc_process_poll(&oc_tls_handler);
  _oc_signal_event_loop();
}
#endif /* OC_SECURITY */

static void
handle_inbound_network_event(oc_process_data_t data)
{
#ifdef OC_SECURITY
  if (((oc_message_t *)data)->encrypted == 1) {
    OC_DBG("Inbound network event: encrypted request");
    oc_process_post(&oc_tls_handler, oc_events[UDP_TO_TLS_EVENT], data);
    return;
  }
#ifdef OC_OSCORE
  if (((oc_message_t *)data)->endpoint.flags & MULTICAST) {
    OC_DBG("Inbound network event: multicast request");
    oc_process_post(&oc_oscore_handler, oc_events[INBOUND_OSCORE_EVENT], data);
    return;
  }
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */
  OC_DBG("Inbound network event: decrypted request");
  oc_process_post(&g_coap_engine, oc_events[INBOUND_RI_EVENT], data);
}

static void
handle_outbound_network_event(oc_process_data_t data)
{
  oc_message_t *message = (oc_message_t *)data;
#ifdef OC_CLIENT
  if (message->endpoint.flags & DISCOVERY) {
    OC_DBG("Outbound network event: multicast request");
    oc_send_discovery_request(message);
    oc_message_unref(message);
    return;
  }
#if defined(OC_SECURITY) && defined(OC_OSCORE)
  if ((message->endpoint.flags & MULTICAST) &&
      (message->endpoint.flags & SECURED)) {
    OC_DBG("Outbound secure multicast request: forwarding to OSCORE");
    oc_process_post(&oc_oscore_handler, oc_events[OUTBOUND_GROUP_OSCORE_EVENT],
                    data);
    return;
  }
#endif /* OC_SECURITY && OC_OSCORE */
#endif /* OC_CLIENT */
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
#ifdef OC_OSCORE
    OC_DBG("Outbound network event: forwarding to OSCORE");
    oc_process_post(&oc_oscore_handler, oc_events[OUTBOUND_OSCORE_EVENT], data);
    return;
  }
#else /* !OC_OSCORE */
#ifdef OC_CLIENT
    OC_DBG("Outbound network event: forwarding to TLS");
    if (!oc_tls_connected(&message->endpoint)) {
      OC_DBG("Posting INIT_TLS_CONN_EVENT");
      oc_process_post(&oc_tls_handler, oc_events[INIT_TLS_CONN_EVENT], data);
      return;
    }
#endif /* OC_CLIENT */
    OC_DBG("Posting RI_TO_TLS_EVENT");
    oc_process_post(&oc_tls_handler, oc_events[RI_TO_TLS_EVENT], data);
    return;
  }
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */
  OC_DBG("Outbound network event: unicast message");
  if (oc_send_buffer(message) < 0) {
    OC_ERR("failed to send unicast message");
  }
  oc_message_unref(message);
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
static void
handle_tcp_connect_event(oc_process_data_t data)
{
  oc_tcp_on_connect_event_t *event = (oc_tcp_on_connect_event_t *)data;
  assert((event->endpoint.flags & TCP) != 0);
  if (event->fn != NULL) {
    event->fn(&event->endpoint, event->state, event->fn_data);
  }
  oc_tcp_on_connect_event_free(event);
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

OC_PROCESS_THREAD(message_buffer_handler, ev, data)
{
  OC_PROCESS_BEGIN();
  OC_DBG("Started buffer handler process");
  while (true) {
    OC_PROCESS_YIELD();

    if (ev == oc_events[INBOUND_NETWORK_EVENT]) {
      handle_inbound_network_event(data);
      continue;
    }
    if (ev == oc_events[OUTBOUND_NETWORK_EVENT]) {
      handle_outbound_network_event(data);
      continue;
    }
#ifdef OC_SECURITY
    if (ev == oc_events[TLS_CLOSE_ALL_SESSIONS]) {
      OC_DBG("Signaling to close all TLS sessions from this device");
      oc_process_post(&oc_tls_handler, oc_events[TLS_CLOSE_ALL_SESSIONS], data);
      continue;
    }
#endif /* OC_SECURITY */
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
    if (ev == oc_events[TCP_CONNECT_SESSION]) {
      handle_tcp_connect_event(data);
      continue;
    }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  }
  OC_PROCESS_END();
}
