/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#ifndef PORT_COMMON_OC_TCP_SOCKET_H
#define PORT_COMMON_OC_TCP_SOCKET_H

#ifdef OC_TCP

#include "oc_endpoint.h"
#include "util/oc_features.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#else /* !_WIN32 */
#include <sys/socket.h>
#endif /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define OC_SOCKET_T SOCKET
#define OC_CLOSE_SOCKET closesocket
#define OC_INVALID_SOCKET (INVALID_SOCKET)
#else /* !_WIN32 */
#define OC_SOCKET_T int
#define OC_CLOSE_SOCKET close
#define OC_INVALID_SOCKET (-1)
#endif /* _WIN32 */

typedef struct
{
  OC_SOCKET_T fd;
  int state;
} oc_tcp_socket_t;

/**
 * @brief Initialize a non-blocking TCP socket and attempt to connect to the
 * given endpoint.
 *
 * @param endpoint endpoint of the socket
 * @param receiver receiver of the socket (if NULL, the address from the
 * endpoint will be used)
 * @return oc_tcp_socket_t value with -1 in state on error
 * @return oc_tcp_socket_t with a valid file descriptor and in
 * OC_TCP_SOCKET_STATE_CONNECTED or OC_TCP_SOCKET_STATE_CONNECTING state on
 * success
 */
oc_tcp_socket_t oc_tcp_socket_connect(const oc_endpoint_t *endpoint,
                                      const struct sockaddr_storage *receiver)
  OC_NONNULL(1);

#ifndef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

/**
 * @brief Initialize a non-blocking TCP socket and attempt to connect to the
 * given endpoint. This function will block until the socket is connected or the
 * timeout expires.
 *
 * @param endpoint endpoint of the socket
 * @param receiver receiver of the socket
 * @param timeout_s timeout in seconds
 * @return OC_SOCKET_T on success
 * @return OC_INVALID_SOCKET on error
 */
OC_SOCKET_T oc_tcp_socket_connect_and_wait(
  const oc_endpoint_t *endpoint, const struct sockaddr_storage *receiver,
  int timeout_s) OC_NONNULL(1);

#endif /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#ifdef __cplusplus
}
#endif

#endif /* OC_TCP */

#endif /* PORT_COMMON_OC_TCP_SOCKET_H */
