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

#include "api/oc_events_internal.h"
#include "api/oc_message_buffer_internal.h"
#include "api/oc_message_internal.h"
#include "messaging/coap/engine_internal.h"
#include "oc_signal_event_loop.h"
#include "oc_buffer.h"
#include "port/oc_connectivity.h"
#include "util/oc_features.h"
#include "util/oc_process.h"

#ifdef OC_SECURITY
#ifdef OC_OSCORE
#include "security/oc_oscore_internal.h"
#endif /* OC_OSCORE */
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
#include "api/oc_tcp_internal.h"
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#include <assert.h>

OC_PROCESS(oc_message_buffer_handler, "OC Message Buffer Handler");

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
oc_close_all_tls_sessions_for_device_reset(size_t device)
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
