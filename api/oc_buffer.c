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
#include "oc_events_internal.h"
#include "oc_signal_event_loop.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"
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

OC_PROCESS(oc_message_buffer_handler, "OC Message Buffer Handler");
#ifdef OC_INOUT_BUFFER_POOL_SIZE
OC_MEMB_STATIC(oc_incoming_buffers, oc_message_t, OC_INOUT_BUFFER_POOL_SIZE);
OC_MEMB_STATIC(oc_outgoing_buffers, oc_message_t, OC_INOUT_BUFFER_POOL_SIZE);
#else  /* OC_INOUT_BUFFER_POOL_SIZE */
OC_MEMB(oc_incoming_buffers, oc_message_t, OC_MAX_NUM_CONCURRENT_REQUESTS);
OC_MEMB(oc_outgoing_buffers, oc_message_t, OC_MAX_NUM_CONCURRENT_REQUESTS);
#endif /* !OC_INOUT_BUFFER_POOL_SIZE */

static void
message_deallocate(oc_message_t *message, struct oc_memb *pool)
{
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
  free(message->data);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
  oc_network_event_handler_mutex_lock();
  oc_memb_free(pool, message);
  oc_network_event_handler_mutex_unlock();
}

static oc_message_t *
message_allocate_with_size(struct oc_memb *pool, size_t size)
{
  oc_network_event_handler_mutex_lock();
  oc_message_t *message = (oc_message_t *)oc_memb_alloc(pool);
  oc_network_event_handler_mutex_unlock();
  if (message == NULL) {
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_SIZE)
    OC_WRN("buffer: No free TX/RX buffers!");
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
    return NULL;
  }
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
  message->data = (uint8_t *)malloc(size);
  if (message->data == NULL) {
    OC_ERR("Out of memory, cannot allocate message");
    message_deallocate(message, pool);
    return NULL;
  }
  memset(message->data, 0, size);
#else  /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  (void)size;
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
  OC_DBG("buffer: Allocated TX/RX buffer; num free: %d", oc_memb_numfree(pool));
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  OC_DBG("buffer: allocated message(%p) from pool(%p)", (void *)message,
         (void *)pool);
  return message;
}

static oc_message_t *
message_allocate(struct oc_memb *pool)
{
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
  return message_allocate_with_size(pool, OC_PDU_SIZE);
#else  /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  return message_allocate_with_size(pool, 0);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
}

size_t
oc_message_buffer_size(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_INOUT_BUFFER_SIZE
  return OC_ARRAY_SIZE(((oc_message_t *)(NULL))->data);
#else
  return OC_PDU_SIZE;
#endif /* OC_DYNAMIC_ALLOCATION && OC_INOUT_BUFFER_SIZE */
#else  /* !OC_DYNAMIC_ALLOCATION */
  return OC_ARRAY_SIZE(((oc_message_t *)(NULL))->data);
#endif /* OC_DYNAMIC_ALLOCATION  */
}

oc_message_t *
oc_allocate_message_from_pool(struct oc_memb *pool)
{
  if (pool) {
    return message_allocate(pool);
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
  return message_allocate(&oc_incoming_buffers);
}

oc_message_t *
oc_message_allocate_with_size(size_t size)
{
  return message_allocate_with_size(&oc_incoming_buffers, size);
}

oc_message_t *
oc_message_allocate_outgoing(void)
{
  return message_allocate(&oc_outgoing_buffers);
}

oc_message_t *
oc_message_allocate_outgoing_with_size(size_t size)
{
  return message_allocate_with_size(&oc_outgoing_buffers, size);
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
  uint8_t new_count = 0;
  while (count > 0) {
    bool swapped = false;
    new_count = count - 1;
    OC_ATOMIC_COMPARE_AND_SWAP8(message->ref_count, count, new_count, swapped);
    if (swapped) {
      dealloc = new_count == 0;
      break;
    }
  }

  if (!dealloc) {
    OC_DBG("buffer: message(%p) unreferenced, ref_count=%d", (void *)message,
           (int)new_count);
    return;
  }

  struct oc_memb *pool = message->pool;
  message_deallocate(message, pool);
  OC_DBG("buffer: deallocated message(%p) from pool(%p)", (void *)message,
         (void *)pool);
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_SIZE)
  OC_DBG("buffer: freed TX/RX buffer; num free: %d", oc_memb_numfree(pool));
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
}

void
oc_recv_message(oc_message_t *message)
{
  if (oc_process_post(&oc_message_buffer_handler,
                      oc_event_to_oc_process_event(INBOUND_NETWORK_EVENT),
                      message) == OC_PROCESS_ERR_FULL) {
    oc_message_unref(message);
  }
}

void
oc_send_message(oc_message_t *message)
{
  if (oc_process_post(&oc_message_buffer_handler,
                      oc_event_to_oc_process_event(OUTBOUND_NETWORK_EVENT),
                      message) == OC_PROCESS_ERR_FULL) {
    oc_message_unref(message);
  }
  _oc_signal_event_loop();
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
void
oc_tcp_connect_session(oc_tcp_on_connect_event_t *event)
{
  if (oc_process_post(&oc_message_buffer_handler,
                      oc_event_to_oc_process_event(TCP_CONNECT_SESSION),
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
  oc_process_post(&oc_message_buffer_handler,
                  oc_event_to_oc_process_event(TLS_CLOSE_ALL_SESSIONS),
                  (oc_process_data_t)device);
}
#endif /* OC_SECURITY */

static void
handle_inbound_network_event(oc_process_data_t data)
{
#ifdef OC_SECURITY
  if (((oc_message_t *)data)->encrypted == 1) {
    OC_DBG("Inbound network event: encrypted request");
    oc_process_post(&oc_tls_handler,
                    oc_event_to_oc_process_event(UDP_TO_TLS_EVENT), data);
    return;
  }
#ifdef OC_OSCORE
  if (((oc_message_t *)data)->endpoint.flags & MULTICAST) {
    OC_DBG("Inbound network event: multicast request");
    oc_process_post(&oc_oscore_handler,
                    oc_event_to_oc_process_event(INBOUND_OSCORE_EVENT), data);
    return;
  }
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */
  OC_DBG("Inbound network event: decrypted request");
  oc_process_post(&g_coap_engine,
                  oc_event_to_oc_process_event(INBOUND_RI_EVENT), data);
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
    oc_process_post(&oc_oscore_handler,
                    oc_event_to_oc_process_event(OUTBOUND_GROUP_OSCORE_EVENT),
                    data);
    return;
  }
#endif /* OC_SECURITY && OC_OSCORE */
#endif /* OC_CLIENT */
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
#ifdef OC_OSCORE
    OC_DBG("Outbound network event: forwarding to OSCORE");
    oc_process_post(&oc_oscore_handler,
                    oc_event_to_oc_process_event(OUTBOUND_OSCORE_EVENT), data);
    return;
  }
#else  /* !OC_OSCORE */
    OC_DBG("Posting RI_TO_TLS_EVENT");
    oc_process_post(&oc_tls_handler,
                    oc_event_to_oc_process_event(RI_TO_TLS_EVENT), data);
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

OC_PROCESS_THREAD(oc_message_buffer_handler, ev, data)
{
  OC_PROCESS_BEGIN();
  OC_DBG("Started buffer handler process");
  while (oc_process_is_running(&oc_message_buffer_handler)) {
    OC_PROCESS_YIELD();

    if (ev == oc_event_to_oc_process_event(INBOUND_NETWORK_EVENT)) {
      handle_inbound_network_event(data);
      continue;
    }
    if (ev == oc_event_to_oc_process_event(OUTBOUND_NETWORK_EVENT)) {
      handle_outbound_network_event(data);
      continue;
    }
#ifdef OC_SECURITY
    if (ev == oc_event_to_oc_process_event(TLS_CLOSE_ALL_SESSIONS)) {
      OC_DBG("Signaling to close all TLS sessions from this device");
      oc_process_post(&oc_tls_handler,
                      oc_event_to_oc_process_event(TLS_CLOSE_ALL_SESSIONS),
                      data);
      continue;
    }
#endif /* OC_SECURITY */
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
    if (ev == oc_event_to_oc_process_event(TCP_CONNECT_SESSION)) {
      handle_tcp_connect_event(data);
      continue;
    }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  }
  OC_PROCESS_END();
}

void
oc_message_buffer_handler_start(void)
{
  oc_process_start(&oc_message_buffer_handler, NULL);
}

void
oc_message_buffer_handler_stop(void)
{
  oc_process_exit(&oc_message_buffer_handler);
}
