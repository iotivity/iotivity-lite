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

#include "util/oc_features.h"

#ifdef OC_TCP

#include "messaging/coap/coap_internal.h"
#include "port/common/oc_fcntl_internal.h"
#include "port/common/oc_tcp_socket_internal.h"
#include "port/common/posix/oc_socket_internal.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>

#else /* !_WIN32 */

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#endif /* _WIN32 */

#ifdef _WIN32
#define OC_ADDRLEN_T int
#else /* !_WIN32 */
#define OC_ADDRLEN_T socklen_t
#endif /* _WIN32 */

#ifdef _WIN32

static SOCKET
tcp_create_socket(const oc_endpoint_t *endpoint)
{
  SOCKET sock = INVALID_SOCKET;
  if ((endpoint->flags & IPV6) != 0) {
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#ifdef OC_IPV4
  } else if ((endpoint->flags & IPV4) != 0) {
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
  }

  if (sock == INVALID_SOCKET) {
    OC_ERR("could not create socket for new TCP session %d", WSAGetLastError());
    return INVALID_SOCKET;
  }
  return sock;
}

static int
tcp_try_connect_nonblocking(SOCKET sock, const struct sockaddr *r, int r_len)
{
  if (!oc_fcntl_set_nonblocking(sock)) {
    OC_ERR("cannot set non-blocking socket(%llu)", sock);
    return -1;
  }

  while (true) {
    int n = connect(sock, r, r_len);
    if (n == 0) {
      return OC_TCP_SOCKET_STATE_CONNECTED;
    }

    int error = WSAGetLastError();
    if (error == WSAEINTR) {
      continue;
    }
    if (error == WSAEWOULDBLOCK || error == WSAEALREADY) {
      return OC_TCP_SOCKET_STATE_CONNECTING;
    }

    OC_ERR("connect to socket(%llu) failed with error: %d", sock, error);
    return -1;
  }
}

#else /* !_WIN32 */

static int
tcp_create_socket(const oc_endpoint_t *endpoint)
{
  int sock = -1;
  if ((endpoint->flags & IPV6) != 0) {
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#ifdef OC_IPV4
  } else if ((endpoint->flags & IPV4) != 0) {
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
  }

  if (sock < 0) {
    OC_ERR("could not create socket for TCP session");
    return OC_INVALID_SOCKET;
  }
  return sock;
}

static int
tcp_try_connect_nonblocking(int sockfd, const struct sockaddr *r,
                            socklen_t r_len)
{
  if (!oc_fcntl_set_nonblocking(sockfd)) {
    OC_ERR("cannot set non-blocking socket(%d)", sockfd);
    return -1;
  }

  while (true) {
    int n = connect(sockfd, r, r_len);
    if (n == 0) {
      return OC_TCP_SOCKET_STATE_CONNECTED;
    }
    if (errno == EINPROGRESS || errno == EALREADY) {
      return OC_TCP_SOCKET_STATE_CONNECTING;
    }
    if (errno == EINTR || errno == EAGAIN) {
      continue;
    }
    OC_ERR("connect to socket(%d) failed with error: %d", sockfd, (int)errno);
    return -1;
  }
}

#endif /* _WIN32 */

oc_tcp_socket_t
oc_tcp_socket_connect(const oc_endpoint_t *endpoint,
                      const struct sockaddr_storage *receiver)
{
  oc_tcp_socket_t cs = {
    .fd = OC_INVALID_SOCKET,
    .state = -1,
  };
  OC_SOCKET_T sock = tcp_create_socket(endpoint);
  if (sock == OC_INVALID_SOCKET) {
    return cs;
  }

  struct sockaddr_storage rc;
  if (receiver == NULL) {
    rc = oc_socket_get_address(endpoint);
    receiver = &rc;
  }

  OC_ADDRLEN_T size = sizeof(*receiver);
  int ret =
    tcp_try_connect_nonblocking(sock, (const struct sockaddr *)receiver, size);
  if (ret < 0) {
    OC_CLOSE_SOCKET(sock);
    return cs;
  }
  cs.fd = sock;
  cs.state = ret;
  return cs;
}

#ifndef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

static bool
tcp_socket_wait_for_connection(oc_tcp_socket_t *socket, int timeout_s)
{
  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(socket->fd, &wset);
  struct timeval tval = {
    .tv_sec = timeout_s,
    .tv_usec = 0,
  };
  int n =
    select(socket->fd + 1, NULL, &wset, NULL, timeout_s != 0 ? &tval : NULL);
  if (n == 0) {
#ifdef _WIN32
    WSASetLastError(WSAETIMEDOUT);
#else  /* !_WIN32 */
    errno = ETIMEDOUT;
#endif /* _WIN32 */
    return false;
  }

#ifdef _WIN32
  if (n == SOCKET_ERROR) {
    OC_ERR("select error: %d", WSAGetLastError());
    return false;
  }
#else  /* !_WIN32 */
  if (n < 0) {
    OC_ERR("select error: %d", (int)errno);
    return false;
  }
#endif /* _WIN32 */

  if (!FD_ISSET(socket->fd, &wset)) {
    OC_ERR("select error: sockfd not set");
    return false;
  }

#ifndef _WIN32
  int error = 0;
  socklen_t len = sizeof(error);
  if (getsockopt(socket->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
    OC_ERR("get socket options error: %d", (int)errno);
    return false; /* Solaris pending error */
  }
  if (error != 0) {
    OC_ERR("socket error: %d", error);
    return false;
  }
#endif /* !_WIN32 */

  socket->state = OC_TCP_SOCKET_STATE_CONNECTED;
  return true;
}

#if OC_ERR_IS_ENABLED

static int
tcp_last_error(void)
{
#ifdef _WIN32
  return WSAGetLastError();
#else  /* !_WIN32 */
  return errno;
#endif /* _WIN32 */
}

#endif /* OC_ERR_IS_ENABLED */

OC_SOCKET_T
oc_tcp_socket_connect_and_wait(const oc_endpoint_t *endpoint,
                               const struct sockaddr_storage *receiver,
                               int timeout_s)
{
  oc_tcp_socket_t ts = oc_tcp_socket_connect(endpoint, receiver);
  if (ts.state == -1) {
    return OC_INVALID_SOCKET;
  }

  if (ts.state == OC_TCP_SOCKET_STATE_CONNECTED) {
    goto done;
  }

  if (!tcp_socket_wait_for_connection(&ts, timeout_s)) {
    OC_ERR("failed to connect to address (error=%d)", tcp_last_error());
    OC_CLOSE_SOCKET(ts.fd);
    return OC_INVALID_SOCKET;
  }

done:
  if (!oc_fcntl_set_blocking(ts.fd)) {
    OC_ERR("cannot set blocking socket (error=%d)", tcp_last_error());
    OC_CLOSE_SOCKET(ts.fd);
    return OC_INVALID_SOCKET;
  }
  return ts.fd;
}

#endif /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#endif /* OC_TCP */
