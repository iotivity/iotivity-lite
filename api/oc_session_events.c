/*
// Copyright (c) 2018 Intel Corporation
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

#include "oc_session_events.h"
#include "oc_config.h"

#include "api/oc_session_events_internal.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_signal_event_loop.h"
#include "util/oc_atomic.h"
#include "util/oc_list.h"
#ifdef OC_SECURITY
#include "security/oc_tls.h"
#endif /* OC_SECURITY */
#if defined(OC_SERVER)
#include "messaging/coap/observe.h"
#endif /* OC_SERVER */

#ifdef OC_TCP
OC_LIST(g_session_start_events);
OC_LIST(g_session_end_events);

static int g_session_state_free_delay_secs;
static OC_ATOMIC_UINT8_T g_session_end_ref = 0;

static int
get_session_start_events_count()
{
  oc_network_event_handler_mutex_lock();
  int count = oc_list_length(g_session_start_events);
  oc_network_event_handler_mutex_unlock();
  return count;
}

static int
get_session_end_events_count()
{
  oc_network_event_handler_mutex_lock();
  int count = oc_list_length(g_session_end_events);
  oc_network_event_handler_mutex_unlock();
  return count;
}

static oc_event_callback_retval_t
free_session_state_delayed(void *data)
{
  (void)data;
  OC_ATOMIC_STORE8(g_session_end_ref, 1);
  oc_endpoint_t *session_event = NULL;
  do {
    oc_network_event_handler_mutex_lock();
    session_event = (oc_endpoint_t *)oc_list_pop(g_session_end_events);
    oc_network_event_handler_mutex_unlock();
    if (session_event) {
      oc_handle_session(session_event, OC_SESSION_DISCONNECTED);
      oc_free_endpoint(session_event);
    }
  } while (get_session_end_events_count() > 0);
  OC_ATOMIC_STORE8(g_session_end_ref, 0);
  return OC_EVENT_DONE;
}

bool
oc_session_events_is_ongoing(void)
{
  return OC_ATOMIC_LOAD8(g_session_end_ref) == 1;
}

void
oc_session_events_set_event_delay(int secs)
{
  g_session_state_free_delay_secs = secs;
}

static void
oc_process_session_event(void)
{
  oc_endpoint_t *session_event = NULL;
  do {
    oc_network_event_handler_mutex_lock();
    session_event = (oc_endpoint_t *)oc_list_pop(g_session_start_events);
    oc_network_event_handler_mutex_unlock();
    if (session_event) {
      oc_handle_session(session_event, OC_SESSION_CONNECTED);
      oc_free_endpoint(session_event);
    }
  } while (get_session_start_events_count() > 0);

  if (get_session_end_events_count() > 0) {
    oc_set_delayed_callback(NULL, &free_session_state_delayed,
                            (uint16_t)g_session_state_free_delay_secs);
  }
}

OC_PROCESS(oc_session_events, "");
OC_PROCESS_THREAD(oc_session_events, ev, data)
{
  (void)data;
  OC_PROCESS_POLLHANDLER(oc_process_session_event());
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&(oc_session_events))) {
    OC_PROCESS_YIELD();
  }
  free_session_state_delayed(NULL);
  OC_PROCESS_END();
}

void
oc_session_start_event(oc_endpoint_t *endpoint)
{
  if (!oc_process_is_running(&(oc_session_events))) {
    return;
  }

  oc_endpoint_t *ep = oc_new_endpoint();
  memcpy(ep, endpoint, sizeof(oc_endpoint_t));
  ep->next = NULL;

  oc_network_event_handler_mutex_lock();
  oc_list_add(g_session_start_events, ep);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&(oc_session_events));
  _oc_signal_event_loop();
}

void
oc_session_end_event(oc_endpoint_t *endpoint)
{
  if (!oc_process_is_running(&(oc_session_events))) {
    return;
  }

  oc_endpoint_t *ep = oc_new_endpoint();
  memcpy(ep, endpoint, sizeof(oc_endpoint_t));
  ep->next = NULL;

  oc_network_event_handler_mutex_lock();
  oc_list_add(g_session_end_events, ep);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&(oc_session_events));
  _oc_signal_event_loop();
}
#endif /* OC_TCP */

void
oc_handle_session(oc_endpoint_t *endpoint, oc_session_state_t state)
{
  (void)endpoint;
  (void)state;
  if (state == OC_SESSION_DISCONNECTED) {
#ifdef OC_SECURITY
    if (endpoint->flags & SECURED && endpoint->flags & TCP) {
      oc_tls_remove_peer(endpoint);
    }
#endif /* OC_SECURITY */
#ifdef OC_SERVER
    /* remove all observations for the endpoint */
    coap_remove_observer_by_client(endpoint);
#endif /* OC_SERVER */
  }
#ifdef OC_SESSION_EVENTS
  handle_session_event_callback(endpoint, state);
#endif /* OC_SESSION_EVENTS */
}
