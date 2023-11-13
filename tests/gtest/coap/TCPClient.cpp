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

#if defined(OC_TCP)

#include "api/oc_message_internal.h"
#include "api/oc_tcp_internal.h"
#include "port/common/oc_tcp_socket_internal.h"
#include "port/common/posix/oc_fcntl_internal.h"
#include "port/common/posix/oc_socket_internal.h"
#include "TCPClient.h"
#include "util/oc_memb.h"

#include <iostream>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#else /* !_WIN32 */
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif /* _WIN32 */

using namespace std::chrono_literals;

namespace oc::coap {

namespace {

bool
net_init()
{
#ifdef _WIN32
  static bool wsa_init_done = false;
  WSADATA wsaData;
  if (!wsa_init_done) {
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
      return false;

    wsa_init_done = true;
  }
#endif // _WIN32
  return true;
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

bool
wait_for_connection(oc_tcp_socket_t *socket, int timeout_s)
{
  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(socket->fd, &wset);
  timeval tval{};
  tval.tv_sec = timeout_s;
  tval.tv_usec = 0;
  int n;
  if ((n = select(socket->fd + 1, NULL, &wset, NULL,
                  timeout_s != 0 ? &tval : NULL)) == 0) {
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
    OC_ERR("select error: %d", errno);
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
    OC_ERR("get socket options error: %d", errno);
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

#endif // OC_HAS_FEATURE_TCP_ASYNC_CONNECT

} // namespace

TCPClient::TCPClient(OnRead onRead)
  : onRead_(onRead)
  , socket_(OC_INVALID_SOCKET)
  , terminated_(false)
{
}

TCPClient::~TCPClient()
{
  Close();
}

OC_SOCKET_T
TCPClient::ConnectAndWait(const oc_endpoint_t *endpoint)
{
  sockaddr_storage receiver = oc_socket_get_address(endpoint);
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  oc_tcp_socket_t ts = oc_tcp_socket_connect(endpoint, &receiver);
  if (ts.state == -1) {
    return OC_INVALID_SOCKET;
  }

  if (ts.state == OC_TCP_SOCKET_STATE_CONNECTED) {
    goto done;
  }

  if (!wait_for_connection(&ts, 5)) {
    OC_CLOSE_SOCKET(ts.fd);
    return OC_INVALID_SOCKET;
  }

done:
  if (!oc_fcntl_set_blocking(ts.fd)) {
    OC_CLOSE_SOCKET(ts.fd);
    return OC_INVALID_SOCKET;
  }
  return ts.fd;
#else  /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  return oc_tcp_socket_connect_and_wait(endpoint, &receiver, 5);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
}

bool
TCPClient::Connect(const oc_endpoint_t *endpoint)
{
  if (!net_init()) {
    return false;
  }
  auto sock = ConnectAndWait(endpoint);
  if (sock == OC_INVALID_SOCKET) {
    return false;
  }
  endpoint_ = *endpoint;
  endpoint_.next = nullptr;
  socket_ = sock;
  return true;
}

void
TCPClient::Close()
{
  if (socket_ != OC_INVALID_SOCKET) {
    OC_CLOSE_SOCKET(socket_);
    socket_ = OC_INVALID_SOCKET;
  }
}

static bool
wasInterrupted()
{
#ifdef _WIN32
  return WSAGetLastError() == WSAEINTR;
#else  /* !_WIN32 */
  return errno == EINTR;
#endif /* _WIN32 */
}

long
TCPClient::Send(const uint8_t *data, size_t size)
{
  if (socket_ == OC_INVALID_SOCKET) {
    throw std::string("socket is not connected");
  }

  size_t bytes_sent = 0;
  do {
#if defined(__linux__) || defined(__ANDROID__) || defined(ESP_PLATFORM)
    int flags = MSG_NOSIGNAL;
#else  /* !__linux__ && !__ANDROID__ && !ESP_PLATFORM */
    int flags = 0;
#endif /* __linux__ || __ANDROID__ || ESP_PLATFORM */
    // cast to char* to make Windows happy
    ssize_t send_len =
      send(socket_, (const char *)data + bytes_sent, size - bytes_sent, flags);
    if (send_len < 0) {
      if (wasInterrupted()) {
        continue;
      }
      if (bytes_sent == 0) {
        return -1;
      }
      return static_cast<long>(bytes_sent);
    }
    bytes_sent += send_len;
  } while (bytes_sent < size);

  assert(bytes_sent <= LONG_MAX);
  return static_cast<long>(bytes_sent);
}

message::oc_message_unique_ptr
TCPClient::ReceiveMessage()
{
  auto msg = message::AllocateMessage();
  if (msg.get() == nullptr) {
    return msg;
  }

  long size = Receive(msg->data, oc_message_buffer_size());
  if (size < 0) {
    msg.reset();
    return msg;
  }
  msg->length = static_cast<size_t>(size);
  return msg;
}

long
TCPClient::Receive(uint8_t *buffer, size_t size)
{
  size_t total_length = 0;
  size_t want_read =
    COAP_TCP_DEFAULT_HEADER_LEN + COAP_TCP_MAX_EXTENDED_LENGTH_LEN;
  if (size < want_read) {
    return -1;
  }

  size_t written = 0;
  do {
    // cast to char* to make Windows happy
    ssize_t count = recv(socket_, (char *)buffer + written, want_read, 0);
    if (count < 0) {
      if (wasInterrupted()) {
        continue;
      }
      return -1;
    }
    if (count == 0) {
      return -1;
    }
    written += (size_t)count;
    want_read -= (size_t)count;

    if (total_length == 0) {
      long length_from_header = oc_tcp_get_total_length_from_header(
        buffer, size, (endpoint_.flags & SECURED) != 0);
      if (length_from_header < 0) {
        return -1;
      }
      total_length = static_cast<size_t>(length_from_header);
      want_read = total_length - static_cast<size_t>(count);
    }
  } while (total_length > written);

  return static_cast<long>(written);
}

bool
TCPClient::Poll(std::chrono::milliseconds timeout)
{
  if (socket_ == OC_INVALID_SOCKET) {
    throw std::string("socket is not connected");
  }

  fd_set readFDs;
  FD_ZERO(&readFDs);
  FD_SET(socket_, &readFDs);

  timeval tv{};
  if (timeout.count() > 0) {
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
  }

  int ret;
  do {
    ret = select(socket_ + 1, &readFDs, nullptr, nullptr,
                 timeout.count() == 0 ? nullptr : &tv);
  } while (ret < 0 && wasInterrupted());

  return FD_ISSET(socket_, &readFDs);
}

void
TCPClient::Run()
{
  while (!terminated_) {
    if (Poll(100ms)) {
      auto message = ReceiveMessage();
      if (!message) {
        break;
      }
      onRead_(std::move(message));
    }
  }
}

void
TCPClient::Terminate()
{
  terminated_ = true;
}

} // namespace oc::coap

#endif // OC_TCP
