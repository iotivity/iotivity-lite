/*
// Copyright (c) 2019 Kistler Instrumente AG
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

#define WIN32_LEAN_AND_MEAN
#include "tcpadapter.h"
#include "api/oc_session_events_internal.h"
#include "ipcontext.h"
#include "messaging/coap/coap.h"
#include "mutex.h"
#include "network_addresses.h"
#include "oc_endpoint.h"
#include "oc_session_events.h"
#include "port/oc_assert.h"
#include "util/oc_memb.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>

#ifdef OC_TCP

#define OC_TCP_LISTEN_BACKLOG 3

#define TLS_HEADER_SIZE 5

#define DEFAULT_RECEIVE_SIZE                                                   \
  (COAP_TCP_DEFAULT_HEADER_LEN + COAP_TCP_MAX_EXTENDED_LENGTH_LEN)

#define LIMIT_RETRY_CONNECT 5

#define TCP_CONNECT_TIMEOUT 5

typedef struct tcp_session
{
  struct tcp_session *next;
  ip_context_t *dev;
  oc_endpoint_t endpoint;
  SOCKET sock;
  HANDLE sock_event;
  tcp_csm_state_t csm_state;
} tcp_session_t;

OC_LIST(session_list);
OC_LIST(free_session_list_async);
OC_MEMB(tcp_session_s, tcp_session_t, OC_MAX_TCP_PEERS);

static HANDLE mutex;

void
oc_tcp_adapter_mutex_init(void)
{
  mutex = mutex_new();
}

void
oc_tcp_adapter_mutex_destroy(void)
{
  mutex_free(mutex);
}

void
oc_tcp_adapter_mutex_lock(void)
{
  mutex_lock(mutex);
}

void
oc_tcp_adapter_mutex_unlock(void)
{
  mutex_unlock(mutex);
}

static int
configure_tcp_socket(SOCKET sock, struct sockaddr_storage *sock_info)
{
  if (bind(sock, (struct sockaddr *)sock_info, sizeof(*sock_info)) ==
      SOCKET_ERROR) {
    OC_ERR("binding socket %d", WSAGetLastError());
    return SOCKET_ERROR;
  }
  int reuse = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return SOCKET_ERROR;
  }
  if (listen(sock, OC_TCP_LISTEN_BACKLOG) == SOCKET_ERROR) {
    OC_ERR("listening socket %d", WSAGetLastError());
    return SOCKET_ERROR;
  }

  return 0;
}

static int
get_assigned_tcp_port(SOCKET sock, struct sockaddr_storage *sock_info)
{
  socklen_t socklen = sizeof(*sock_info);
  if (getsockname(sock, (struct sockaddr *)sock_info, &socklen) ==
      SOCKET_ERROR) {
    OC_ERR("obtaining socket information %d", WSAGetLastError());
    return SOCKET_ERROR;
  }

  return 0;
}

static int
get_interface_index(SOCKET sock)
{
  int interface_index = SOCKET_ERROR;

  struct sockaddr_storage addr;
  if (get_assigned_tcp_port(sock, &addr) == SOCKET_ERROR) {
    return SOCKET_ERROR;
  }

  ifaddr_t *ifaddr_list = get_network_addresses();
  ifaddr_t *interface;

  for (interface = ifaddr_list; interface != NULL;
       interface = interface->next) {
    if (addr.ss_family == interface->addr.ss_family) {
      if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&interface->addr;
        struct sockaddr_in6 *b = (struct sockaddr_in6 *)&addr;
        if (memcmp(a->sin6_addr.s6_addr, b->sin6_addr.s6_addr, 16) == 0) {
          interface_index = interface->if_index;
          break;
        }
      }
#ifdef OC_IPV4
      else if (addr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&interface->addr;
        struct sockaddr_in *b = (struct sockaddr_in *)&addr;
        if (a->sin_addr.s_addr == b->sin_addr.s_addr) {
          interface_index = interface->if_index;
          break;
        }
      }
#endif /* OC_IPV4 */
    }
  }

  free_network_addresses(ifaddr_list);
  return interface_index;
}

static void
free_tcp_session_locked(tcp_session_t *session, oc_endpoint_t *endpoint,
                        SOCKET *sock, HANDLE *sock_event)
{
  oc_tcp_adapter_mutex_lock();
  oc_list_remove(session_list, session);
  memcpy_s(endpoint, sizeof(*endpoint), &session->endpoint,
           sizeof(session->endpoint));
  *sock = session->sock;
  *sock_event = session->sock_event;
  oc_memb_free(&tcp_session_s, session);
  oc_tcp_adapter_mutex_unlock();

  OC_DBG("freed TCP session");
}

static void
free_tcp_session(tcp_session_t *session)
{
  oc_endpoint_t endpoint;
  SOCKET sock;
  HANDLE sock_event;
  free_tcp_session_locked(session, &endpoint, &sock, &sock_event);
  WSACloseEvent(sock_event);
  closesocket(sock);
  if (!oc_session_events_is_ongoing()) {
    oc_session_end_event(&endpoint);
  }

  OC_DBG("freed TCP session");
}

static void
free_tcp_session_async_locked(tcp_session_t *session)
{
  oc_list_remove(session_list, session);
  oc_list_add(free_session_list_async, session);

  if (!SetEvent(session->dev->tcp.signal_event)) {
    OC_ERR("could not trigger signal event (%d)\n", GetLastError());
  }
  OC_DBG("free TCP session async");
}

static int
set_socket_block_mode(SOCKET sockfd, u_long nonblock)
{
  int error = ioctlsocket(sockfd, FIONBIO, &nonblock);
  if (error == SOCKET_ERROR) {
    OC_ERR("set socket as blocking(%ul) %d", nonblock, WSAGetLastError());
    return SOCKET_ERROR;
  }
  return 0;
}

static int
add_new_session_locked(SOCKET sock, ip_context_t *dev, oc_endpoint_t *endpoint,
                       tcp_csm_state_t state)
{
  HANDLE sock_event = WSACreateEvent();
  if (WSAEventSelect(sock, sock_event, FD_READ | FD_CLOSE) == SOCKET_ERROR) {
    OC_ERR("creating socket session event %d", WSAGetLastError());
    return SOCKET_ERROR;
  }
  tcp_session_t *session = oc_memb_alloc(&tcp_session_s);
  if (!session) {
    WSACloseEvent(sock_event);
    OC_ERR("could not allocate new TCP session object");
    return SOCKET_ERROR;
  }

  endpoint->interface_index = get_interface_index(sock);
  memcpy(&session->endpoint, endpoint, sizeof(oc_endpoint_t));
  session->dev = dev;
  session->endpoint.next = NULL;
  session->sock = sock;
  session->csm_state = state;
  session->sock_event = sock_event;

  oc_list_add(session_list, session);

  if (!(endpoint->flags & SECURED)) {
    oc_session_start_event((oc_endpoint_t *)endpoint);
  }

  OC_DBG("recorded new TCP session");

  return 0;
}

static int
accept_new_session(ip_context_t *dev, SOCKET fd, oc_endpoint_t *endpoint)
{
  struct sockaddr_storage receive_from;
  socklen_t receive_len = sizeof(receive_from);

  SOCKET new_socket =
    accept(fd, (struct sockaddr *)&receive_from, &receive_len);
  if (new_socket == INVALID_SOCKET) {
    OC_ERR("failed to accept incoming TCP connection %d", WSAGetLastError());
    return SOCKET_ERROR;
  }
  OC_DBG("accepted incomming TCP connection");

  if (endpoint->flags & IPV6) {
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receive_from;
    memcpy(endpoint->addr.ipv6.address, r->sin6_addr.s6_addr,
           sizeof(r->sin6_addr.s6_addr));
    endpoint->addr.ipv6.scope = (uint8_t)r->sin6_scope_id;
    endpoint->addr.ipv6.port = ntohs(r->sin6_port);
#ifdef OC_IPV4
  } else if (endpoint->flags & IPV4) {
    struct sockaddr_in *r = (struct sockaddr_in *)&receive_from;
    memcpy(endpoint->addr.ipv4.address, &r->sin_addr.s_addr,
           sizeof(r->sin_addr.s_addr));
    endpoint->addr.ipv4.port = ntohs(r->sin_port);
#endif /* !OC_IPV4 */
  }

  oc_tcp_adapter_mutex_lock();
  if (add_new_session_locked(new_socket, dev, endpoint, CSM_NONE) < 0) {
    oc_tcp_adapter_mutex_unlock();
    OC_ERR("could not record new TCP session");
    closesocket(new_socket);
    return SOCKET_ERROR;
  }
  oc_tcp_adapter_mutex_unlock();

  if (!SetEvent(dev->tcp.signal_event)) {
    OC_ERR("could not trigger signal event (%d)\n", GetLastError());
    return SOCKET_ERROR;
  }

  return 0;
}

static tcp_session_t *
find_session_by_endpoint_locked(oc_endpoint_t *endpoint)
{
  tcp_session_t *session = oc_list_head(session_list);
  while (session != NULL &&
         oc_endpoint_compare(&session->endpoint, endpoint) != 0) {
    session = session->next;
  }

  if (!session) {
#ifdef OC_DEBUG
    PRINT("could not find ongoing TCP session for endpoint:");
    PRINTipaddr(*endpoint);
    PRINT("\n");
#endif /* OC_DEBUG */
    return NULL;
  }
#ifdef OC_DEBUG
  PRINT("found TCP session for endpoint:");
  PRINTipaddr(*endpoint);
  PRINT("\n");
#endif /* OC_DEBUG */
  return session;
}

static tcp_session_t *
get_ready_to_read_session(fd_set *setfds)
{
  tcp_session_t *session = oc_list_head(session_list);
  while (session != NULL && !FD_ISSET(session->sock, setfds)) {
    session = session->next;
  }

  if (!session) {
    OC_ERR("could not find any open ready-to-read session");
    return NULL;
  }
  return session;
}

static size_t
get_total_length_from_header(oc_message_t *message, oc_endpoint_t *endpoint)
{
  size_t total_length = 0;
  if (endpoint->flags & SECURED) {
    //[3][4] bytes in tls header are tls payload length
    total_length =
      TLS_HEADER_SIZE + (size_t)((message->data[3] << 8) | message->data[4]);
  } else {
    total_length = coap_tcp_get_packet_size(message->data);
  }

  return total_length;
}

void
oc_tcp_end_session(oc_endpoint_t *endpoint)
{
  oc_tcp_adapter_mutex_lock();
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (session) {
    free_tcp_session_async_locked(session);
  }
  oc_tcp_adapter_mutex_unlock();
}

static SOCKET
get_session_socket_locked(oc_endpoint_t *endpoint)
{
  SOCKET sock = INVALID_SOCKET;
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (!session) {
    return INVALID_SOCKET;
  }

  sock = session->sock;
  return sock;
}

static int
connect_nonb(SOCKET sockfd, const struct sockaddr *r, int r_len, int nsec)
{
  if (set_socket_block_mode(sockfd, 1) == SOCKET_ERROR) {
    return SOCKET_ERROR;
  }

  int n = connect(sockfd, (struct sockaddr *)r, r_len);
  if (n == SOCKET_ERROR) {
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
      OC_ERR("connect %d", WSAGetLastError());
      return SOCKET_ERROR;
    }
  }

  /* Do whatever we want while the connect is taking place. */
  if (n == 0) {
    return 0; /* connect completed immediately */
  }

  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(sockfd, &wset);
  struct timeval tval;
  tval.tv_sec = nsec;
  tval.tv_usec = 0;

  if ((n = select((int)sockfd + 1, NULL, &wset, NULL, nsec ? &tval : NULL)) ==
      0) {
    /* timeout */
    WSASetLastError(WSAETIMEDOUT);
    OC_ERR("connect %d", WSAGetLastError());
    return SOCKET_ERROR;
  }
  if (n == SOCKET_ERROR) {
    return SOCKET_ERROR;
  }

  if (FD_ISSET(sockfd, &wset)) {
    if (set_socket_block_mode(sockfd, 0) == SOCKET_ERROR) {
      return SOCKET_ERROR;
    }
    return 0;
  }
  OC_DBG("select error: sockfd not set");
  return SOCKET_ERROR;
}

static SOCKET
initiate_new_session_locked(ip_context_t *dev, oc_endpoint_t *endpoint,
                            const struct sockaddr_storage *receiver)
{
  SOCKET sock = INVALID_SOCKET;
  uint8_t retry_cnt = 0;

  while (retry_cnt < LIMIT_RETRY_CONNECT) {
    if (endpoint->flags & IPV6) {
      sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#ifdef OC_IPV4
    } else if (endpoint->flags & IPV4) {
      sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
    }

    if (sock == INVALID_SOCKET) {
      OC_ERR("could not create socket for new TCP session %d",
             WSAGetLastError());
      return sock;
    }

    socklen_t receiver_size = sizeof(*receiver);
    int ret = 0;
    if ((ret = connect_nonb(sock, (struct sockaddr *)receiver, receiver_size,
                            TCP_CONNECT_TIMEOUT)) == 0) {
      break;
    }

    closesocket(sock);
    retry_cnt++;
    OC_DBG("connect fail with %d. retry(%d)", ret, retry_cnt);
  }

  if (retry_cnt >= LIMIT_RETRY_CONNECT) {
    OC_ERR("could not initiate TCP connection - retry exhausted");
    return INVALID_SOCKET;
  }

  OC_DBG("successfully initiated TCP connection");

  if (add_new_session_locked(sock, dev, endpoint, CSM_SENT) < 0) {
    OC_ERR("could not record new TCP session");
    closesocket(sock);
    return INVALID_SOCKET;
  }

  if (!SetEvent(dev->tcp.signal_event)) {
    OC_ERR("could not trigger signal event (%d)\n", GetLastError());
  }

  OC_DBG("signaled network event thread to monitor the newly added session\n");

  return sock;
}

int
oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                   const struct sockaddr_storage *receiver)
{
  oc_tcp_adapter_mutex_lock();
  SOCKET send_sock = get_session_socket_locked(&message->endpoint);
  int bytes_sent = 0;

  if (send_sock == INVALID_SOCKET) {
    if ((send_sock = initiate_new_session_locked(dev, &message->endpoint,
                                                 receiver)) == INVALID_SOCKET) {
      OC_ERR("could not initiate new TCP session");
      goto oc_tcp_send_buffer_done;
    }
  }

  do {
    int send_len = send(send_sock, (const char *)message->data + bytes_sent,
                        (int)message->length - bytes_sent, 0);
    if (send_len == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) {
        continue;
      }
      OC_WRN("send() returned error %d", err);
      goto oc_tcp_send_buffer_done;
    }
    bytes_sent += send_len;
  } while (bytes_sent < (int)message->length);

  OC_DBG("Sent %d bytes", bytes_sent);
oc_tcp_send_buffer_done:
  oc_tcp_adapter_mutex_unlock();

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
}

static int
recv_message_with_tcp_session(tcp_session_t *session, oc_message_t *message)
{
  size_t total_length = 0;
  size_t want_read = DEFAULT_RECEIVE_SIZE;
  message->length = 0;
  do {
    int count = recv(session->sock, (char *)message->data + message->length,
                     (int)want_read, 0);
    if (count == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) {
        continue;
      }
      OC_ERR("recv error! %d", err);
      free_tcp_session(session);
      return ADAPTER_STATUS_ERROR;
    } else if (count == 0) {
      OC_DBG("peer closed TCP session\n");
      free_tcp_session(session);
      return ADAPTER_STATUS_NONE;
    }

    OC_DBG("recv(): %d bytes.", count);
    message->length += (size_t)count;
    want_read -= (size_t)count;

    if (total_length == 0) {
      total_length = get_total_length_from_header(message, &session->endpoint);
      if (total_length >
          (unsigned)(OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE)) {
        OC_ERR("total receive length(%zu) is bigger than max pdu size(%zu)",
               total_length,
               (size_t)(OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE));
        OC_ERR("It may occur buffer overflow.");
        return ADAPTER_STATUS_ERROR;
      }
      OC_DBG("tcp packet total length : %zu bytes.", total_length);

      want_read = (int)total_length - count;
    }
  } while (total_length > message->length);

  memcpy(&message->endpoint, &session->endpoint, sizeof(oc_endpoint_t));
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
    message->encrypted = 1;
  }
#endif /* OC_SECURITY */

  return ADAPTER_STATUS_RECEIVE;
}

static void
recv_message(SOCKET s, void *ctx)
{
  (void)s;
  tcp_session_t *session = (tcp_session_t *)ctx;
  WSANETWORKEVENTS network_events;
  if (WSAEnumNetworkEvents(session->sock, session->sock_event,
                           &network_events) == SOCKET_ERROR) {
    OC_ERR("enumerate network event %d", WSAGetLastError());
    free_tcp_session(session);
    return;
  }
  if (!(network_events.lNetworkEvents & (FD_READ | FD_CLOSE))) {
    return;
  }
  oc_message_t *message = oc_allocate_message();
  if (!message) {
    return;
  }
  int ret = recv_message_with_tcp_session(session, message);
  if (ret != ADAPTER_STATUS_RECEIVE) {
    oc_message_unref(message);
    return;
  }

#ifdef OC_DEBUG
  PRINT("Incoming message of size %zd bytes from ", message->length);
  PRINTipaddr(message->endpoint);
  PRINT("\n\n");
#endif /* OC_DEBUG */
  oc_network_event(message);
}

static void
accept_socket(SOCKET s, void *ctx)
{
  ip_context_t *dev = (ip_context_t *)ctx;
  oc_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  WSANETWORKEVENTS network_events;
  if (s == dev->tcp.server_sock) {
    if (WSAEnumNetworkEvents(dev->tcp.server_sock, dev->tcp.server_event,
                             &network_events) == SOCKET_ERROR) {
      OC_ERR("enumerate network event %d", WSAGetLastError());
      return;
    }
    if (!(network_events.lNetworkEvents & (FD_ACCEPT | FD_CLOSE))) {
      return;
    }
    endpoint.flags = IPV6 | TCP;
    if (accept_new_session(dev, dev->tcp.server_sock, &endpoint) ==
        SOCKET_ERROR) {
      OC_ERR("accept new tcp session fail");
    }
    return;
#ifdef OC_SECURITY
  } else if (s == dev->tcp.secure_sock) {
    if (WSAEnumNetworkEvents(dev->tcp.secure_sock, dev->tcp.secure_event,
                             &network_events) == SOCKET_ERROR) {
      OC_ERR("enumerate network event %d", WSAGetLastError());
      return;
    }
    if (!(network_events.lNetworkEvents & (FD_ACCEPT | FD_CLOSE))) {
      return;
    }
    endpoint.flags = IPV6 | SECURED | TCP;
    if (accept_new_session(dev, dev->tcp.secure_sock, &endpoint) ==
        SOCKET_ERROR) {
      OC_ERR("accept new tcp secure session fail");
    }
    return;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  } else if (s == dev->tcp.server4_sock) {
    if (WSAEnumNetworkEvents(dev->tcp.server4_sock, dev->tcp.server4_event,
                             &network_events) == SOCKET_ERROR) {
      OC_ERR("enumerate network event %d", WSAGetLastError());
      return;
    }
    if (!(network_events.lNetworkEvents & (FD_ACCEPT | FD_CLOSE))) {
      return;
    }
    endpoint.flags = IPV4 | TCP;
    if (accept_new_session(dev, dev->tcp.server4_sock, &endpoint) ==
        SOCKET_ERROR) {
      OC_ERR("accept new tcp4 session fail");
    }
    return;
#ifdef OC_SECURITY
  } else if (s == dev->tcp.secure4_sock) {
    if (WSAEnumNetworkEvents(dev->tcp.secure4_sock, dev->tcp.secure4_event,
                             &network_events) == SOCKET_ERROR) {
      OC_ERR("enumerate network event %d", WSAGetLastError());
      return;
    }
    if (!(network_events.lNetworkEvents & (FD_ACCEPT | FD_CLOSE))) {
      return;
    }
    endpoint.flags = IPV4 | SECURED | TCP;
    if (accept_new_session(dev, dev->tcp.secure4_sock, &endpoint) ==
        SOCKET_ERROR) {
      OC_ERR("accept new tcp4 secure session fail");
    }
    return;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  }
  OC_ERR("invalid socket %ld", (long)s);
  return;
}

static void
process_signal(SOCKET s, void *ctx)
{
  (void)ctx;
  (void)s;
  OC_DBG("process signal");
  tcp_session_t *session = NULL;
  do {
    oc_tcp_adapter_mutex_lock();
    session = (tcp_session_t *)oc_list_pop(free_session_list_async);
    oc_tcp_adapter_mutex_unlock();
    if (session != NULL) {
      free_tcp_session(session);
    }
  } while (session != NULL);
}

typedef void (*socket_handler_t)(SOCKET, void *);

typedef struct sockets_handler_t
{
  HANDLE handlers[MAXIMUM_WAIT_OBJECTS];
  socket_handler_t cbks[MAXIMUM_WAIT_OBJECTS];
  void *ctxs[MAXIMUM_WAIT_OBJECTS];
  SOCKET sockets[MAXIMUM_WAIT_OBJECTS];
} sockets_handler_t;

static DWORD
fill_sockets_handlers(ip_context_t *dev, sockets_handler_t *s)
{
  DWORD n = 0;
  s->handlers[n] = dev->tcp.signal_event;
  s->cbks[n] = process_signal;
  s->ctxs[n] = dev;
  s->sockets[n] = INVALID_SOCKET;
  n++;
  s->handlers[n] = dev->tcp.server_event;
  s->cbks[n] = accept_socket;
  s->ctxs[n] = dev;
  s->sockets[n] = dev->tcp.server_sock;
  n++;
#ifdef OC_IPV4
  s->handlers[n] = dev->tcp.server4_event;
  s->cbks[n] = accept_socket;
  s->ctxs[n] = dev;
  s->sockets[n] = dev->tcp.server4_sock;
  n++;
#endif // OC_IPV4
#ifdef OC_SECURITY
  s->handlers[n] = dev->tcp.secure_event;
  s->cbks[n] = accept_socket;
  s->ctxs[n] = dev;
  s->sockets[n] = dev->tcp.secure_sock;
  n++;
#ifdef OC_IPV4
  s->handlers[n] = dev->tcp.secure4_event;
  s->cbks[n] = accept_socket;
  s->ctxs[n] = dev;
  s->sockets[n] = dev->tcp.secure4_sock;
  n++;
#endif // OC_IPV4
#endif // OC_SECURITY
  oc_tcp_adapter_mutex_lock();
  tcp_session_t *session = (tcp_session_t *)oc_list_head(session_list);
  while (session != NULL && n < MAXIMUM_WAIT_OBJECTS) {
    if (session->endpoint.device == dev->device) {
      s->handlers[n] = session->sock_event;
      s->cbks[n] = recv_message;
      s->ctxs[n] = session;
      s->sockets[n] = session->sock;
      n++;
    }
    session = session->next;
  }
  oc_tcp_adapter_mutex_unlock();
  return n;
}

static void *
network_event_thread(void *data)
{
  ip_context_t *dev = (ip_context_t *)data;
  sockets_handler_t socks;
  while (!dev->terminate) {
    DWORD size = fill_sockets_handlers(dev, &socks);
    DWORD idx = WaitForMultipleObjects(size, socks.handlers, FALSE, INFINITE);
    if (idx == WAIT_FAILED) {
      OC_ERR("cannot wait for multiple objects: error_code(%d)",
             GetLastError());
    } else if (idx - WAIT_OBJECT_0 >= 0 && idx - WAIT_OBJECT_0 < size) {
      idx = idx - WAIT_OBJECT_0;
      socks.cbks[idx](socks.sockets[idx], socks.ctxs[idx]);
    } else {
      oc_abort("err in network event thread");
    }
  }

  return NULL;
}

#ifdef OC_IPV4
static int
tcp_connectivity_ipv4_init(ip_context_t *dev)
{
  OC_DBG("Initializing TCP adapter IPv4 for device %zd", dev->device);

  memset(&dev->tcp.server4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *l = (struct sockaddr_in *)&dev->tcp.server4;
  l->sin_family = AF_INET;
  l->sin_addr.s_addr = INADDR_ANY;
  l->sin_port = 0;

  dev->tcp.server4_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.server4_sock == INVALID_SOCKET) {
    OC_ERR("creating TCP server socket %d", WSAGetLastError());
    return SOCKET_ERROR;
  }
  if (configure_tcp_socket(dev->tcp.server4_sock, &dev->tcp.server4) ==
      SOCKET_ERROR) {
    closesocket(dev->tcp.server4_sock);
    OC_ERR("set socket option in server socket");
    return SOCKET_ERROR;
  }
  if (get_assigned_tcp_port(dev->tcp.server4_sock, &dev->tcp.server4) ==
      SOCKET_ERROR) {
    closesocket(dev->tcp.server4_sock);
    OC_ERR("get port for server socket");
    return SOCKET_ERROR;
  }

  dev->tcp.port4 = ntohs(((struct sockaddr_in *)&dev->tcp.server4)->sin_port);
  dev->tcp.server4_event = WSACreateEvent();
  if (WSAEventSelect(dev->tcp.server4_sock, dev->tcp.server4_event,
                     FD_READ | FD_ACCEPT) == SOCKET_ERROR) {
    OC_ERR("creating TCP server socket event %d", WSAGetLastError());
    WSACloseEvent(dev->tcp.server4_event);
    closesocket(dev->tcp.server4_sock);
    return SOCKET_ERROR;
  }

#ifdef OC_SECURITY
  memset(&dev->tcp.secure4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *sm = (struct sockaddr_in *)&dev->tcp.secure4;
  sm->sin_family = AF_INET;
  sm->sin_addr.s_addr = INADDR_ANY;
  sm->sin_port = 0;

  dev->tcp.secure4_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.secure4_sock == INVALID_SOCKET) {
    OC_ERR("creating TCP secure socket %d", WSAGetLastError());
    closesocket(dev->tcp.server4_sock);
    WSACloseEvent(dev->tcp.server4_event);
    closesocket(dev->tcp.server4_sock);
    return SOCKET_ERROR;
  }

  if (configure_tcp_socket(dev->tcp.secure4_sock, &dev->tcp.secure4) ==
      SOCKET_ERROR) {
    OC_ERR("set socket option in secure socket");
    closesocket(dev->tcp.server4_sock);
    WSACloseEvent(dev->tcp.server4_event);
    closesocket(dev->tcp.server4_sock);
    return SOCKET_ERROR;
  }

  if (get_assigned_tcp_port(dev->tcp.secure4_sock, &dev->tcp.secure4) ==
      SOCKET_ERROR) {
    OC_ERR("get port for secure socket");
    closesocket(dev->tcp.server4_sock);
    WSACloseEvent(dev->tcp.server4_event);
    closesocket(dev->tcp.server4_sock);
    return SOCKET_ERROR;
  }
  dev->tcp.tls4_port =
    ntohs(((struct sockaddr_in *)&dev->tcp.secure4)->sin_port);
  dev->tcp.secure4_event = WSACreateEvent();
  if (WSAEventSelect(dev->tcp.secure4_sock, dev->tcp.secure4_event,
                     FD_READ | FD_ACCEPT) == SOCKET_ERROR) {
    OC_ERR("creating TCP secure socket event %d", WSAGetLastError());
    WSACloseEvent(dev->tcp.secure4_event);
    closesocket(dev->tcp.secure4_sock);
    WSACloseEvent(dev->tcp.server4_event);
    closesocket(dev->tcp.server4_sock);
    return SOCKET_ERROR;
  }
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized TCP adapter IPv4 for device %zd",
         dev->device);

  return 0;
}
#endif /* OC_IPV4 */

int
oc_tcp_connectivity_init(ip_context_t *dev)
{
  OC_DBG("Initializing TCP adapter for device %zd", dev->device);

  dev->tcp.signal_event = CreateEvent(NULL,  // default security attributes
                                      FALSE, // manual-reset event
                                      FALSE, // initial state is nonsignaled
                                      NULL);

  memset(&dev->tcp.server, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->tcp.server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;

  dev->tcp.server_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.server_sock == SOCKET_ERROR) {
    OC_ERR("creating TCP server socket %d", WSAGetLastError());
    return -1;
  }

  if (configure_tcp_socket(dev->tcp.server_sock, &dev->tcp.server) < 0) {
    OC_ERR("set socket option in server socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.server_sock, &dev->tcp.server) < 0) {
    OC_ERR("get port for server socket");
    return -1;
  }
  dev->tcp.port = ntohs(((struct sockaddr_in *)&dev->tcp.server)->sin_port);
  dev->tcp.server_event = WSACreateEvent();
  if (WSAEventSelect(dev->tcp.server_sock, dev->tcp.server_event,
                     FD_READ | FD_ACCEPT) == SOCKET_ERROR) {
    OC_ERR("creating TCP server socket event %d", WSAGetLastError());
    WSACloseEvent(dev->tcp.server_event);
    closesocket(dev->tcp.server_sock);
    return -1;
  }

#ifdef OC_SECURITY
  memset(&dev->tcp.secure, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&dev->tcp.secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_addr = in6addr_any;
  sm->sin6_port = 0;

  dev->tcp.secure_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.secure_sock == SOCKET_ERROR) {
    OC_ERR("creating TCP secure socket %d", WSAGetLastError());
    WSACloseEvent(dev->tcp.server_event);
    closesocket(dev->tcp.server_sock);
    return -1;
  }

  if (configure_tcp_socket(dev->tcp.secure_sock, &dev->tcp.secure) < 0) {
    OC_ERR("set socket option in secure socket");
    closesocket(dev->tcp.secure_sock);
    WSACloseEvent(dev->tcp.server_event);
    closesocket(dev->tcp.server_sock);
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.secure_sock, &dev->tcp.secure) < 0) {
    OC_ERR("get port for secure socket");
    closesocket(dev->tcp.secure_sock);
    WSACloseEvent(dev->tcp.server_event);
    closesocket(dev->tcp.server_sock);
    return -1;
  }
  dev->tcp.tls_port = ntohs(((struct sockaddr_in *)&dev->tcp.secure)->sin_port);
  dev->tcp.secure_event = WSACreateEvent();
  if (WSAEventSelect(dev->tcp.secure_sock, dev->tcp.secure_event,
                     FD_READ | FD_ACCEPT) == SOCKET_ERROR) {
    OC_ERR("creating TCP secure socket event %d", WSAGetLastError());
    WSACloseEvent(dev->tcp.secure_event);
    closesocket(dev->tcp.secure_sock);
    WSACloseEvent(dev->tcp.server_event);
    closesocket(dev->tcp.server_sock);
    return -1;
  }
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (tcp_connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4 for TCP");
    WSACloseEvent(dev->tcp.server_event);
    closesocket(dev->tcp.server_sock);
#ifdef OC_SECURITY
    WSACloseEvent(dev->tcp.secure_event);
    closesocket(dev->tcp.secure_sock);
#endif /* OC_SECURITY */
    return -1;
  }
#endif /* OC_IPV4 */

  OC_DBG("=======tcp port info.========");
  OC_DBG("  ipv6 port   : %u", dev->tcp.port);
#ifdef OC_SECURITY
  OC_DBG("  ipv6 secure : %u", dev->tcp.tls_port);
#endif
#ifdef OC_IPV4
  OC_DBG("  ipv4 port   : %u", dev->tcp.port4);
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %u", dev->tcp.tls4_port);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */

  dev->tcp.event_thread_handle =
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network_event_thread, dev, 0,
                 &dev->tcp.event_thread);
  if (dev->tcp.event_thread_handle == NULL) {
    OC_ERR("creating tcp network polling thread %d", GetLastError());
    WSACloseEvent(dev->tcp.server_event);
    closesocket(dev->tcp.server_sock);
#ifdef OC_SECURITY
    WSACloseEvent(dev->tcp.secure_event);
    closesocket(dev->tcp.secure_sock);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
    WSACloseEvent(dev->tcp.server4_event);
    closesocket(dev->tcp.server4_sock);
#ifdef OC_SECURITY
    WSACloseEvent(dev->tcp.secure4_event);
    closesocket(dev->tcp.secure4_sock);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
    return -1;
  }

  OC_DBG("Successfully initialized TCP adapter for device %zd", dev->device);
  return 0;
}

void
oc_tcp_connectivity_shutdown(ip_context_t *dev)
{
  if (!SetEvent(dev->tcp.signal_event)) {
    OC_ERR("could not trigger signal event (%d)\n", GetLastError());
  }
  WaitForSingleObject(dev->tcp.event_thread_handle, INFINITE);
  TerminateThread(dev->tcp.event_thread_handle, 0);

  process_signal(INVALID_SOCKET, dev);

  WSACloseEvent(dev->tcp.server_event);
  closesocket(dev->tcp.server_sock);

#ifdef OC_IPV4
  WSACloseEvent(dev->tcp.server4_event);
  closesocket(dev->tcp.server4_sock);
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  WSACloseEvent(dev->tcp.secure_event);
  closesocket(dev->tcp.secure_sock);
#ifdef OC_IPV4
  WSACloseEvent(dev->tcp.secure4_event);
  closesocket(dev->tcp.secure4_sock);
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

  oc_tcp_adapter_mutex_lock();
  tcp_session_t *session = (tcp_session_t *)oc_list_head(session_list), *next;
  while (session != NULL) {
    next = session->next;
    if (session->dev->device == dev->device) {
      oc_endpoint_t endpoint;
      SOCKET sock;
      HANDLE sock_event;
      free_tcp_session_locked(session, &endpoint, &sock, &sock_event);
      WSACloseEvent(sock_event);
      closesocket(sock);
      if (!oc_session_events_is_ongoing()) {
        oc_session_end_event(&endpoint);
      }
      OC_DBG("freed TCP session");
    }
    session = next;
  }
  oc_tcp_adapter_mutex_unlock();

  CloseHandle(dev->tcp.signal_event);

  OC_DBG("oc_tcp_connectivity_shutdown for device %zd", dev->device);
}

tcp_csm_state_t
oc_tcp_get_csm_state(oc_endpoint_t *endpoint)
{
  if (!endpoint) {
    return CSM_ERROR;
  }

  oc_tcp_adapter_mutex_lock();
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (!session) {
    oc_tcp_adapter_mutex_unlock();
    return CSM_NONE;
  }
  tcp_csm_state_t state = session->csm_state;
  oc_tcp_adapter_mutex_unlock();

  return state;
}

int
oc_tcp_update_csm_state(oc_endpoint_t *endpoint, tcp_csm_state_t csm)
{
  if (!endpoint) {
    return -1;
  }

  oc_tcp_adapter_mutex_lock();
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (!session) {
    oc_tcp_adapter_mutex_unlock();
    return -1;
  }
  session->csm_state = csm;
  oc_tcp_adapter_mutex_unlock();

  return 0;
}

#endif /* OC_TCP */
