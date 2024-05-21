/****************************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
 * Copyright 2018 Samsung Electronics, All Rights Reserved.
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

#ifndef TCP_SESION_H
#define TCP_SESION_H

#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "util/oc_features.h"
#include "ipcontext.h"
#include "oc_endpoint.h"
#include "tcpcontext.h"
#include <stddef.h>
#include <sys/select.h>

#ifdef OC_TCP

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send a message through a TCP connection.
 *
 * For applications capable of opening connections
 * (OC_HAS_FEATURE_TCP_ASYNC_CONNECT is true):
 * If a connection to the address is not yet established then a signal is send
 * to network thread to open a connection.
 * The message cannot be sent until the connection is opened, so during this
 * interval the reference count of the message is increased, the message is
 * added to a queue associated with the connection. The messages queued for this
 * connection will be send once the connection has been opened.
 *
 * If the application cannot open a TCP connection
 * (OC_HAS_FEATURE_TCP_ASYNC_CONNECT is false) then oc_tcp_send_buffer2 is
 * called.
 *
 * @param dev the device network context (cannot be NULL)
 * @param message message with data to send (cannot be NULL)
 * @param receiver address of the receiver (cannot be NULL)
 * @return OC_SEND_MESSAGE_QUEUED message was queued and will be sent once a
 * connection is established
 * @return >=0 number of written bytes
 * @return -1 on error
 *
 * @note thread-safe
 */
int oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                       const struct sockaddr_storage *receiver);

/**
 * @brief Send a message through a TCP connection.
 *
 * Unlike oc_tcp_send_buffer this function will not try to open a TCP session
 * and it pressuposes that the connection is opened (either we are a client and
 * the oc_tcp_connect has been already called previously or we are a server and
 * we have accepted a connection).
 *
 * @param message message with endpoint address and data to send (cannot be
 * NULL)
 * @param queue true if the message can be queued (the session for given
 * endpoint exists, but it hasn't finished opening yet, the message will be sent
 * once it is opened)
 * @return OC_SEND_MESSAGE_QUEUED message has been queued
 * @return >0 message was sent and that many bytes were sent
 * @return OC_TCP_SOCKET_ERROR_NOT_CONNECTED no session for given endpoint
 * exists (ie. oc_tcp_connect has not been called for the endpoint)
 * @return -1 on other error
 *
 * @note thread-safe
 */
int oc_tcp_send_buffer2(oc_message_t *message, bool queue);

/**
 * @brief Try to receive data from a socket.
 *
 * @param dev the device network context (cannot be NULL)
 * @param fds set of file descriptors with available read events (cannot be
 * NULL)
 * @param message message to store the received data
 * @return adapter_receive_state_t
 *
 * @note thread-safe
 */
adapter_receive_state_t tcp_receive_message(ip_context_t *dev, fd_set *fds,
                                            oc_message_t *message);

/**
 * @brief Schedule the session associated with the endpoint to be stopped and
 * deallocated (if it exists).
 */
bool tcp_end_session(const oc_endpoint_t *endpoint, bool notify_session_end);

/**
 * @brief Handle data received on the signal pipe.
 */
void tcp_session_handle_signal(void);

/**
 * @brief Stop and deallocate all sessions.
 */
void tcp_session_shutdown(const ip_context_t *dev);

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
/**
 * @brief Iterate over TCP sessions waiting for connection. Deallocate expired
 * sessions. Retry the connection process for sessions that haven't reached the
 * maximal amount of retries. Get the nearest timeout of a non-expired session.
 *
 * @param now_mt current monotonic time
 * @return 0 no non-expired session was found
 * @return >0 the nearest timeout of a non-expired session
 *
 * @note thread-safe
 */
oc_clock_time_t tcp_check_expiring_sessions(oc_clock_time_t now_mt);

/**
 * @brief Go through the list of TCP sessions waiting to be opened. If a session
 * with socket that is in the file descriptor set is found then remove the
 * socket from the file descriptor, remove the session from the list of waiting
 * sessions and add it to the list of ongoing sessions and send messages that
 * were queued for this session.
 * If an error occurs for the session then the session socket is closed and the
 * whole process will be retried again on next select wake-up.
 *
 * @param fds set of file descriptors with available write event(s)
 * @return true session with socket in the file descriptor set was found and
 * processed
 * @return false no session was found
 */
bool tcp_process_waiting_sessions(fd_set *fds);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#ifdef __cplusplus
}
#endif

#endif /* OC_TCP */

#endif /* TCP_SESION_H */
