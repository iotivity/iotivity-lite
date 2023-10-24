/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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

#include "oc_session_events.h"
#include "oc_config.h"

#include "api/oc_session_events_internal.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_network_monitor.h"
#include "oc_signal_event_loop.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_atomic.h"
#include "util/oc_list.h"

#ifdef OC_SECURITY
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */
#if defined(OC_SERVER)
#include "messaging/coap/observe_internal.h"
#endif /* OC_SERVER */

#ifdef OC_SESSION_EVENTS

OC_LIST(oc_session_event_cb_list);
OC_MEMB(oc_session_event_cb_s, oc_session_event_cb_t, OC_MAX_SESSION_EVENT_CBS);

#endif /* OC_SESSION_EVENTS */

#ifdef OC_TCP
OC_LIST(g_session_start_events);
OC_LIST(g_session_end_events);

static int g_session_state_free_delay_secs = 0;
static OC_ATOMIC_UINT8_T g_session_end_ref = 0;

static int
get_session_end_events_count(void)
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
    if (session_event == NULL) {
      break;
    }
    oc_handle_session(session_event, OC_SESSION_DISCONNECTED);
    oc_free_endpoint(session_event);
  } while (true);
  OC_ATOMIC_STORE8(g_session_end_ref, 0);
  return OC_EVENT_DONE;
}

bool
oc_session_events_disconnect_is_ongoing(void)
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
    if (session_event == NULL) {
      break;
    }
    oc_handle_session(session_event, OC_SESSION_CONNECTED);
    oc_free_endpoint(session_event);
  } while (true);

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
  while (oc_process_is_running(&oc_session_events)) {
    OC_PROCESS_YIELD();
  }
  free_session_state_delayed(NULL);
  OC_PROCESS_END();
}

void
oc_session_start_event(const oc_endpoint_t *endpoint)
{
  if (!oc_process_is_running(&oc_session_events)) {
    return;
  }

  oc_endpoint_t *ep = oc_new_endpoint();
  memcpy(ep, endpoint, sizeof(oc_endpoint_t));
  ep->next = NULL;

  oc_network_event_handler_mutex_lock();
  oc_list_add(g_session_start_events, ep);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&oc_session_events);
  _oc_signal_event_loop();
}

void
oc_session_end_event(const oc_endpoint_t *endpoint)
{
  if (!oc_process_is_running(&oc_session_events)) {
    return;
  }

  oc_endpoint_t *ep = oc_new_endpoint();
  memcpy(ep, endpoint, sizeof(oc_endpoint_t));
  ep->next = NULL;

  oc_network_event_handler_mutex_lock();
  oc_list_add(g_session_end_events, ep);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&oc_session_events);
  _oc_signal_event_loop();
}
#endif /* OC_TCP */

#ifdef OC_SESSION_EVENTS

session_event_versioned_handler_t
oc_session_event_versioned_handler(session_event_handler_t cb)
{
  session_event_versioned_handler_t h = {
    {
      .v0 = cb,
    },
    .version = OC_SESSION_EVENT_API_V0,
  };
  return h;
}

session_event_versioned_handler_t
oc_session_event_versioned_handler_v1(session_event_handler_v1_t cb)
{
  session_event_versioned_handler_t h = {
    {
      .v1 = cb,
    },
    .version = OC_SESSION_EVENT_API_V1,
  };
  return h;
}

static int
session_event_add_callback(session_event_versioned_handler_t cb,
                           void *user_data)
{
  assert((cb.version == OC_SESSION_EVENT_API_V0 && cb.handler.v0 != NULL) ||
         (cb.version == OC_SESSION_EVENT_API_V1 && cb.handler.v1 != NULL));
  oc_session_event_cb_t *cb_item = oc_memb_alloc(&oc_session_event_cb_s);
  if (cb_item == NULL) {
    OC_ERR("session event callback item alloc failed");
    return -1;
  }

  assert(cb.version != OC_SESSION_EVENT_API_V0 || user_data == NULL);
  cb_item->vh = cb;
  cb_item->user_data = user_data;
  oc_list_add(oc_session_event_cb_list, cb_item);
  return 0;
}

int
oc_add_session_event_callback(session_event_handler_t cb)
{
  if (cb == NULL) {
    return -1;
  }
  return session_event_add_callback(oc_session_event_versioned_handler(cb),
                                    NULL);
}

int
oc_add_session_event_callback_v1(session_event_handler_v1_t cb, void *user_data)
{
  if (cb == NULL) {
    return -1;
  }

  return session_event_add_callback(oc_session_event_versioned_handler_v1(cb),
                                    user_data);
}

oc_session_event_cb_t *
oc_session_event_callback_find(session_event_versioned_handler_t cb,
                               const void *user_data, bool ignore_user_data)
{
  oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list);
  for (; cb_item != NULL; cb_item = cb_item->next) {
    if (cb.version != cb_item->vh.version) {
      continue;
    }
    if (cb.version == OC_SESSION_EVENT_API_V0) {
      if (cb.handler.v0 == cb_item->vh.handler.v0) {
        return cb_item;
      }
      continue;
    }
    if (cb.version == OC_SESSION_EVENT_API_V1) {
      if (cb.handler.v1 == cb_item->vh.handler.v1 &&
          (ignore_user_data || user_data == cb_item->user_data)) {
        return cb_item;
      }
      continue;
    }
  }
  return NULL;
}

static int
session_event_remove_callback(session_event_versioned_handler_t cb,
                              void *user_data, bool ignore_user_data)
{
  oc_session_event_cb_t *cb_item =
    oc_session_event_callback_find(cb, user_data, ignore_user_data);
  if (cb_item == NULL) {
    return OC_ERR_SESSION_EVENT_HANDLER_NOT_FOUND;
  }

  oc_list_remove(oc_session_event_cb_list, cb_item);
  oc_memb_free(&oc_session_event_cb_s, cb_item);
  return 0;
}

int
oc_remove_session_event_callback(session_event_handler_t cb)
{
  if (cb == NULL) {
    return -1;
  }
  if (session_event_remove_callback(oc_session_event_versioned_handler(cb),
                                    NULL, false) < 0) {
    return -1;
  }
  return 0;
}

int
oc_remove_session_event_callback_v1(session_event_handler_v1_t cb,
                                    void *user_data, bool ignore_user_data)
{
  if (cb == NULL) {
    return -1;
  }
  return session_event_remove_callback(
    oc_session_event_versioned_handler_v1(cb), user_data, ignore_user_data);
}

void
handle_session_event_callback(const oc_endpoint_t *endpoint,
                              oc_session_state_t state)
{
  if (oc_list_length(oc_session_event_cb_list) > 0) {
    oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list);
    for (; cb_item != NULL; cb_item = cb_item->next) {
      if (cb_item->vh.version == OC_SESSION_EVENT_API_V0) {
        cb_item->vh.handler.v0(endpoint, state);
        continue;
      }
      if (cb_item->vh.version == OC_SESSION_EVENT_API_V1) {
        cb_item->vh.handler.v1(endpoint, state, cb_item->user_data);
        continue;
      }
    }
  }
}

void
oc_session_events_remove_all_callbacks(void)
{
  oc_session_event_cb_t *cb_item;
  while ((cb_item = oc_list_pop(oc_session_event_cb_list)) != NULL) {
    oc_memb_free(&oc_session_event_cb_s, cb_item);
  }
}

#endif /* OC_SESSION_EVENTS */

static void
handle_session_disconnected(const oc_endpoint_t *endpoint)
{
  (void)endpoint;
#ifdef OC_SECURITY
  if ((endpoint->flags & SECURED) != 0 && (endpoint->flags & TCP) != 0) {
    oc_tls_remove_peer(endpoint);
  }
#endif /* OC_SECURITY */
#ifdef OC_SERVER
  /* remove all observations for the endpoint */
  coap_remove_observers_by_client(endpoint);
#endif /* OC_SERVER */
}

void
oc_handle_session(const oc_endpoint_t *endpoint, oc_session_state_t state)
{
  OC_DBG("handle session: state=%d", (int)state);
  if (state == OC_SESSION_DISCONNECTED) {
    handle_session_disconnected(endpoint);
  }
#ifdef OC_SESSION_EVENTS
  handle_session_event_callback(endpoint, state);
#endif /* OC_SESSION_EVENTS */
}
