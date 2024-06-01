/****************************************************************************
 *
 * Copyright (c) 2016, 2018, 2020 Intel Corporation
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

#ifndef OC_PORT_CONNECTIVITY_INTERNAL_H
#define OC_PORT_CONNECTIVITY_INTERNAL_H

#include "oc_config.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_network_events.h"
#include "oc_session_events.h"
#include "port/oc_connectivity.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_SEND_MESSAGE_QUEUED INT_MAX

/**
 * @brief initialize the connectivity (e.g. open sockets) for the device
 *
 * @param device the device index
 * @param ports the ports to listen on
 * @return int 0 = success
 */
int oc_connectivity_init(size_t device, oc_connectivity_ports_t ports);

/**
 * @brief shut down the connectivity for device at device index
 *
 * @param device the device index
 */
void oc_connectivity_shutdown(size_t device);

/**
 * @brief Send message to endpoint.
 *
 * @param message message to be sent (cannot be NULL)
 * @param queue true if message can be queued when it cannot be sent immediately
 * (possible for TCP sessions)
 * @return <0 on error
 * @return OC_SEND_MESSAGE_QUEUED if message was queued
 * @return >= number of written bytes
 */
int oc_send_buffer2(oc_message_t *message, bool queue);

#ifdef OC_NETWORK_MONITOR
/**
 * @brief the callback function for an network change
 *
 * @param event the network event
 */
void handle_network_interface_event_callback(oc_interface_event_t event);
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SESSION_EVENTS
/**
 * @brief the session callback
 *
 * @param endpoint endpoint for the session
 * @param state the state of the session
 */
void handle_session_event_callback(const oc_endpoint_t *endpoint,
                                   oc_session_state_t state);
#endif /* OC_SESSION_EVENTS */

#ifdef OC_TCP

/**
 * @brief End TCP session for the specific endpoint.
 *
 * @param endpoint the endpoint to close the session for
 * @param notify_session_end send the notification about the disconnection
 * session.
 * @param session_endpoint the endpoint of the session with session id
 * @return bool true if the session will be closed
 */
bool oc_connectivity_end_session_v1(const oc_endpoint_t *endpoint,
                                    bool notify_session_end,
                                    oc_endpoint_t *session_endpoint)
  OC_NONNULL(1);

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

typedef struct
{
  uint8_t max_count; ///< maximal number of retries for opening a single TCP
                     /// connection (default: 5)
  uint16_t timeout;  ///< timeout of a single retry in seconds (default: 5)
} oc_tcp_connect_retry_t;

#define OC_TCP_CONNECT_RETRY_MAX_COUNT 5
#define OC_TCP_CONNECT_RETRY_TIMEOUT 5

/** @brief Connect to endpoint and return connection state and session id */
typedef struct
{
  uint32_t session_id;
  oc_tcp_socket_state_t state;
  int error;
} oc_tcp_connect_result_t;

/** @brief Connect to TCP endpoint and return connection state and session id */
oc_tcp_connect_result_t oc_tcp_connect_to_endpoint(
  oc_endpoint_t *endpoint, on_tcp_connect_t on_tcp_connect,
  void *on_tcp_connect_data) OC_NONNULL(1);

void oc_tcp_set_connect_retry(uint8_t max_count, uint16_t timeout);

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

/**
 * @brief Get state of TCP connection for given session id.
 *
 * @param session_id session id
 * @return OC_TCP_SOCKET_STATE_CONNECTED TCP connection exists and it is ongoing
 * @return OC_TCP_SOCKET_STATE_CONNECTING TCP connection is waiting to be
 * established
 * @return -1 otherwise
 */
int oc_tcp_session_state(uint32_t session_id);

#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_CONNECTIVITY_INTERNAL_H */
