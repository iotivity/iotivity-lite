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
#include "util/oc_mem.h"
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_SECURITY
#include "security/oc_tls.h"
#endif /* OC_SECURITY */

#include "config.h"
#include "oc_buffer.h"
#include "oc_events.h"
#include <pthread.h>

OC_PROCESS(message_buffer_handler, "OC Message Buffer Handler");
OC_MEMB(oc_buffers_s, oc_message_t, (OC_MAX_NUM_CONCURRENT_REQUESTS * 2));

#define OC_MAX_NUM_BUFFER_SIZE     6

static int g_buffersize_count;
static pthread_mutex_t buffercount_mutex;

static pthread_mutex_t buffer_avail_mutex;
static pthread_cond_t buffer_avail_cv;

static void notify_buffer_availability(void);

oc_message_t *
oc_allocate_message(void)
{
  oc_network_event_handler_mutex_lock();
#ifdef OC_DYNAMIC_ALLOCATION
  pthread_mutex_lock(&buffercount_mutex);
  if(g_buffersize_count > OC_MAX_NUM_BUFFER_SIZE/2){
    OC_DBG("[BUFFER_TEST]Buffer Full");
    pthread_mutex_unlock(&buffercount_mutex);
	oc_network_event_handler_mutex_unlock();
    return NULL;
    }
    OC_DBG("[BUFFER_TEST]BufferSize %d",g_buffersize_count);
  g_buffersize_count++;
  pthread_mutex_unlock(&buffercount_mutex);
#endif
  oc_message_t *message = (oc_message_t *)oc_memb_alloc(&oc_buffers_s);
  oc_network_event_handler_mutex_unlock();
  if (message) {
#ifdef OC_DYNAMIC_ALLOCATION
    message->data = oc_mem_malloc(OC_PDU_SIZE);
    if (!message->data) {
      oc_memb_free(&oc_buffers_s, message);
      return NULL;
    }
#endif /* OC_DYNAMIC_ALLOCATION */
    message->length = 0;
    message->next = 0;
    message->ref_count = 1;
#ifndef OC_DYNAMIC_ALLOCATION
    OC_DBG("buffer: Allocated TX/RX buffer; num free: %d",
           oc_memb_numfree(&oc_buffers_s));
#endif /* !OC_DYNAMIC_ALLOCATION */
  }
#ifndef OC_DYNAMIC_ALLOCATION
  else {
    OC_WRN("buffer: No free TX/RX buffers!");
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
      OC_DBG("[BUFFER_TEST] Size %d",g_buffersize_count);
      pthread_mutex_lock(&buffercount_mutex);
      if(g_buffersize_count > 0) {
        g_buffersize_count--;
        OC_DBG("[BUFFER_TEST] Decreasing Size %d",g_buffersize_count);
      }
      notify_buffer_availability();
      pthread_mutex_unlock(&buffercount_mutex);
      oc_mem_free(message->data);
#endif /* OC_DYNAMIC_ALLOCATION */
      oc_memb_free(&oc_buffers_s, message);
#ifndef OC_DYNAMIC_ALLOCATION
      OC_DBG("buffer: freed TX/RX buffer; num free: %d",
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
  OC_DBG("Started buffer handler process");
  while (1) {
    OC_PROCESS_YIELD();

    if (ev == oc_events[INBOUND_NETWORK_EVENT]) {
#ifdef OC_SECURITY
      uint8_t b = (uint8_t)((oc_message_t *)data)->data[0];
      if (b > 19 && b < 64) {
        OC_DBG("Inbound network event: encrypted request");
        oc_process_post(&oc_tls_handler, oc_events[UDP_TO_TLS_EVENT], data);
      } else {
        OC_DBG("Inbound network event: decrypted request");
        oc_process_post(&coap_engine, oc_events[INBOUND_RI_EVENT], data);
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
      } else
#endif /* OC_CLIENT */
#ifdef OC_SECURITY
          if (message->endpoint.flags & SECURED) {
        OC_DBG("Outbound network event: forwarding to TLS");

#ifdef OC_CLIENT
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
#endif /* OC_SECURITY */
      {
        OC_DBG("Outbound network event: unicast message");
        oc_send_buffer(message);
        oc_message_unref(message);
      }
    }
  }
  OC_PROCESS_END();
}

void
notify_buffer_availability(void) {
  pthread_mutex_lock(&buffer_avail_mutex);
  OC_DBG("Notifying consumers - buffer availability");
  pthread_cond_signal(&buffer_avail_cv);
  pthread_mutex_unlock(&buffer_avail_mutex);
}

void
oc_wait_for_buffer(void) {
  pthread_mutex_lock(&buffer_avail_mutex);
  //TODO: Timed wait is required
  pthread_cond_wait(&buffer_avail_cv, &buffer_avail_mutex);
}
