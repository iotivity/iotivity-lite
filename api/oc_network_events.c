/****************************************************************************
 *
 * Copyright (c) 2016-2018 Intel Corporation, All Rights Reserved.
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

#include "api/oc_endpoint_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_message_buffer_internal.h"
#include "api/oc_message_internal.h"
#include "api/oc_network_events_internal.h"
#include "messaging/coap/coap_internal.h"
#include "oc_buffer.h"
#include "oc_config.h"
#include "oc_events_internal.h"
#include "oc_signal_event_loop.h"
#include "oc_tcp_internal.h"
#include "oc_udp_internal.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_features.h"
#include "util/oc_list.h"

#include <assert.h>

OC_LIST(g_network_events);
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
OC_LIST(g_network_tcp_connect_events);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
#ifdef OC_NETWORK_MONITOR
static bool g_interface_up;
static bool g_interface_down;
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_DYNAMIC_ALLOCATION
static size_t
get_events_queue_length(size_t device, oc_list_t events)
{
  size_t msg_count = 0;
  for (oc_message_t *msg = (oc_message_t *)oc_list_head(events); msg != NULL;
       msg = msg->next) {
    if (msg->endpoint.device == device) {
      ++msg_count;
    }
  }
  return msg_count;
}

static void
send_wakeup_signal(oc_list_t events)
{
  size_t msg_total = oc_list_length(events);

  int deviceId = 0;
  while (msg_total >= OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS) {
    size_t msg_device_count = get_events_queue_length(deviceId, events);
    if (msg_device_count >= OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS) {
      oc_connectivity_wakeup(deviceId);
    }
    msg_total -= msg_device_count;
    ++deviceId; // advance to the next device
  }
}
#endif /* OC_DYNAMIC_ALLOCATION */

static void
oc_process_network_event(void)
{
  oc_network_event_handler_mutex_lock();
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  OC_LIST_LOCAL(network_tcp_connect_events);
  oc_list_copy(network_tcp_connect_events, g_network_tcp_connect_events);
  oc_list_init(g_network_tcp_connect_events);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  OC_LIST_LOCAL(network_events);
  oc_list_copy(network_events, g_network_events);
  oc_list_init(g_network_events);
#ifdef OC_NETWORK_MONITOR
  bool interface_up = g_interface_up;
  g_interface_up = false;
  bool interface_down = g_interface_down;
  g_interface_down = false;
#endif /* OC_NETWORK_MONITOR */
  oc_network_event_handler_mutex_unlock();

#ifdef OC_DYNAMIC_ALLOCATION
  // send a wake-up signal in case the queue might reach the limit for a device
  send_wakeup_signal(network_events);
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  oc_tcp_on_connect_event_t *event =
    (oc_tcp_on_connect_event_t *)oc_list_pop(network_tcp_connect_events);
  while (event != NULL) {
    oc_tcp_connect_session(event);
    event =
      (oc_tcp_on_connect_event_t *)oc_list_pop(network_tcp_connect_events);
  }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  oc_message_t *message = (oc_message_t *)oc_list_pop(network_events);
  while (message != NULL) {
    oc_recv_message(message);
    message = (oc_message_t *)oc_list_pop(network_events);
  }
#ifdef OC_NETWORK_MONITOR
  if (interface_up) {
    oc_process_post(&oc_network_events,
                    oc_event_to_oc_process_event(INTERFACE_UP), NULL);
  }
  if (interface_down) {
    oc_process_post(&oc_network_events,
                    oc_event_to_oc_process_event(INTERFACE_DOWN), NULL);
  }
#endif /* OC_NETWORK_MONITOR */
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
    if (ev == oc_event_to_oc_process_event(INTERFACE_DOWN)) {
      handle_network_interface_event_callback(NETWORK_INTERFACE_DOWN);
    } else if (ev == oc_event_to_oc_process_event(INTERFACE_UP)) {
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
  // validate UDP/DTLS message, TCP messages is validated directly in the port
  // layer for closing the connection
  if (((message->endpoint.flags & TCP) == 0) &&
      !oc_udp_is_valid_message(message)) {
    OC_ERR("invalid header - dropping message");
    oc_message_unref(message);
    return;
  }
#ifdef OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER
  oc_message_shrink_buffer(message, message->length);
#endif /* OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
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

size_t
oc_network_drop_receive_events(const oc_endpoint_t *endpoint)
{
  size_t dropped = 0;
  oc_network_event_handler_mutex_lock();
  for (oc_message_t *message = (oc_message_t *)oc_list_head(g_network_events);
       message != NULL;) {
    oc_message_t *next = message->next;
    if (oc_endpoint_compare(&message->endpoint, endpoint) == 0) {
      oc_list_remove(g_network_events, message);
#if OC_DBG_IS_ENABLED
      // GCOVR_EXCL_START
      oc_process_event_t ev =
        oc_event_to_oc_process_event(INBOUND_NETWORK_EVENT);
      oc_string_view_t ev_name = oc_process_event_name(ev);
      oc_string64_t endpoint_str;
      oc_endpoint_to_string64(endpoint, &endpoint_str);
      int64_t session_id = oc_endpoint_session_id(endpoint);
      OC_DBG("oc_network_events: dropping %s for endpoint(addr=%s, "
             "session_id=%" PRId64 ")",
             ev_name.data, oc_string(endpoint_str), session_id);
      // GCOVR_EXCL_STOP
#endif /* OC_DBG_IS_ENABLED */
      oc_message_unref(message);
      ++dropped;
    }
    message = next;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  size_t queue_len =
    get_events_queue_length(endpoint->device, g_network_events);
  // unlock mutex and send a wake-up signal in case the queue for the device was
  // full
  oc_network_event_handler_mutex_unlock();
  if (queue_len + dropped >= OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS) {
    oc_connectivity_wakeup(endpoint->device);
  }
#else
  oc_network_event_handler_mutex_unlock();
#endif /* OC_DYNAMIC_ALLOCATION */

  return dropped;
}

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

#ifdef OC_DYNAMIC_ALLOCATION
size_t
oc_network_get_event_queue_length(size_t device)
{
  oc_network_event_handler_mutex_lock();
  size_t msg_count = get_events_queue_length(device, g_network_events);
  oc_network_event_handler_mutex_unlock();
  return msg_count;
}
#endif /* OC_DYNAMIC_ALLOCATION */
