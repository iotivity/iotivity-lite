/****************************************************************************
 *
 * Copyright (c) 2016-2018 Intel Corporation, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_network_events_internal.h"
#include "api/oc_buffer_internal.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_features.h"
#include "util/oc_list.h"
#include "oc_buffer.h"
#include "oc_config.h"
#include "oc_events.h"
#include "oc_signal_event_loop.h"
#include "oc_tcp_internal.h"

OC_LIST(g_network_events);
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
OC_LIST(g_network_tcp_connect_events);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
#ifdef OC_NETWORK_MONITOR
static bool g_interface_up;
static bool g_interface_down;
#endif /* OC_NETWORK_MONITOR */

static void
oc_process_network_event(void)
{
  oc_network_event_handler_mutex_lock();
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  oc_tcp_on_connect_event_t *event =
    (oc_tcp_on_connect_event_t *)oc_list_pop(g_network_tcp_connect_events);
  while (event != NULL) {
    oc_tcp_connect_session(event);
    event = oc_list_pop(g_network_tcp_connect_events);
  }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  oc_message_t *message = (oc_message_t *)oc_list_pop(g_network_events);
  while (message != NULL) {
    oc_recv_message(message);
    message = oc_list_pop(g_network_events);
  }
#ifdef OC_NETWORK_MONITOR
  if (g_interface_up) {
    oc_process_post(&oc_network_events, oc_events[INTERFACE_UP], NULL);
    g_interface_up = false;
  }
  if (g_interface_down) {
    oc_process_post(&oc_network_events, oc_events[INTERFACE_DOWN], NULL);
    g_interface_down = false;
  }
#endif /* OC_NETWORK_MONITOR */
  oc_network_event_handler_mutex_unlock();
}

OC_PROCESS(oc_network_events, "");
OC_PROCESS_THREAD(oc_network_events, ev, data)
{
  (void)data;
  OC_PROCESS_POLLHANDLER(oc_process_network_event());
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&oc_network_events)) {
    OC_PROCESS_YIELD();
#ifdef OC_NETWORK_MONITOR
    if (ev == oc_events[INTERFACE_DOWN]) {
      handle_network_interface_event_callback(NETWORK_INTERFACE_DOWN);
    } else if (ev == oc_events[INTERFACE_UP]) {
      handle_network_interface_event_callback(NETWORK_INTERFACE_UP);
    }
#endif /* OC_NETWORK_MONITOR */
  }
  OC_PROCESS_END();
}

void
oc_network_receive_event(oc_message_t *message)
{
  if (!oc_process_is_running(&oc_network_events)) {
    oc_message_unref(message);
    return;
  }
  oc_network_event_handler_mutex_lock();
  oc_list_add(g_network_events, message);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&oc_network_events);
  _oc_signal_event_loop();
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
void
oc_network_tcp_connect_event(oc_tcp_on_connect_event_t *event)
{
  if (!oc_process_is_running(&oc_network_events)) {
    oc_tcp_on_connect_event_free(event);
    return;
  }
  oc_network_event_handler_mutex_lock();
  oc_list_add(g_network_tcp_connect_events, event);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&oc_network_events);
  _oc_signal_event_loop();
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#ifdef OC_NETWORK_MONITOR
void
oc_network_interface_event(oc_interface_event_t event)
{
  if (!oc_process_is_running(&oc_network_events)) {
    return;
  }
  if (event != NETWORK_INTERFACE_DOWN && event != NETWORK_INTERFACE_UP) {
    return;
  }
  oc_network_event_handler_mutex_lock();
  if (event == NETWORK_INTERFACE_DOWN) {
    g_interface_down = true;
  } else if (event == NETWORK_INTERFACE_UP) {
    g_interface_up = true;
  }
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&oc_network_events);
  _oc_signal_event_loop();
}
#endif /* OC_NETWORK_MONITOR */
