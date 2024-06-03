/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "util/oc_features.h"

#ifdef OC_TCP

#include "api/oc_endpoint_internal.h"
#include "api/oc_message_internal.h"
#include "api/oc_network_events_internal.h"
#include "api/oc_session_events_internal.h"
#include "api/oc_tcp_internal.h"
#include "ipadapter.h"
#include "ipcontext.h"
#include "messaging/coap/coap_internal.h"
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "oc_session_events.h"
#include "port/common/posix/oc_socket_internal.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_fcntl_internal.h"
#include "port/oc_tcp_socket_internal.h"
#include "tcpsession.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct tcp_session_t
{
  struct tcp_session_t *next;
  ip_context_t *dev;
  oc_endpoint_t endpoint;
  int sock;
  tcp_csm_state_t csm_state;
  bool notify_session_end;
} tcp_session_t;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
OC_LIST(g_session_list); ///< opened sessions; guarded by g_mutex
OC_LIST(
  g_free_session_list_async); ///< sessions to be closed; guarded by g_mutex
OC_MEMB(g_tcp_session_s, tcp_session_t, OC_MAX_TCP_PEERS);

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

typedef struct queued_message_t
{
  struct queued_message_t *next;
  oc_message_t *message;
} queued_message_t;

OC_MEMB(g_queued_message_s, queued_message_t,
        OC_MAX_TCP_PEERS); // guarded by g_mutex

typedef struct tcp_waiting_session_t
{
  struct tcp_waiting_session_t *next;
  ip_context_t *dev;
  oc_endpoint_t endpoint;
  int sock;
  struct
  {
    oc_clock_time_t start;
    uint8_t count;
    uint8_t force;
    int error;
  } retry;
  OC_LIST_STRUCT(messages);
  on_tcp_connect_t on_tcp_connect;
  void *on_tcp_connect_data;
  bool notify_session_end;
} tcp_waiting_session_t;

OC_LIST(g_waiting_session_list); ///< sessions waiting to open a connection,
                                 /// guarded by g_mutex
OC_LIST(g_free_waiting_session_list_async); ///< waiting sessions to be closed,
                                            /// guarded by g_mutex
OC_MEMB(g_tcp_waiting_session_s, tcp_waiting_session_t,
        OC_MAX_TCP_PEERS); ///< guarded by g_mutex

static oc_tcp_connect_retry_t g_connect_retry = {
  .max_count = OC_TCP_CONNECT_RETRY_MAX_COUNT,
  .timeout = OC_TCP_CONNECT_RETRY_TIMEOUT,
}; // guarded by g_mutex

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

static void
signal_network_thread(const tcp_context_t *tcp)
{
  ssize_t len = 0;
  do {
    uint8_t dummy_value = 0xef;
    len = write(tcp->connect_pipe[1], &dummy_value, 1);
  } while (len < 0 && errno == EINTR);
#if OC_ERR_IS_ENABLED || OC_WRN_IS_ENABLED
  if (len < 0) {
    if (errno != ENOSPC) {
      OC_ERR("failed to signal wake up to network thread: %d", (int)errno);
    }
#if OC_WRN_IS_ENABLED
    else {
      OC_WRN("network thread is exhausted, because connect pipe is full");
    }
#endif /* OC_WRN_IS_ENABLED */
  }
#endif /* OC_ERR_IS_ENABLED || OC_WRN_IS_ENABLED */
}

static bool
is_matching_address(const struct sockaddr *first, const struct sockaddr *second)
{
  if (first->sa_family != second->sa_family) {
    return false;
  }
  CLANG_IGNORE_WARNING_START
  CLANG_IGNORE_WARNING("-Wcast-align")
  if (first->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)first;
    const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)second;
    return memcmp(a->sin6_addr.s6_addr, b->sin6_addr.s6_addr, 16) == 0;
  }
#ifdef OC_IPV4
  if (first->sa_family == AF_INET) {
    const struct sockaddr_in *a = (const struct sockaddr_in *)first;
    const struct sockaddr_in *b = (const struct sockaddr_in *)second;
    return a->sin_addr.s_addr == b->sin_addr.s_addr;
  }
#endif /* OC_IPV4 */
  CLANG_IGNORE_WARNING_END
  return false;
}

static long
get_interface_index(int sock)
{
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  socklen_t socklen = sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &socklen) == -1) {
    OC_ERR("failed obtaining socket information %d", errno);
    return -1;
  }

  struct ifaddrs *ifs = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("failed querying interfaces: %d", errno);
    return -1;
  }

  for (struct ifaddrs *interface = ifs; interface != NULL;
       interface = interface->ifa_next) {
    if ((interface->ifa_flags & IFF_UP) == 0 ||
        (interface->ifa_flags & IFF_LOOPBACK) != 0 ||
        interface->ifa_addr == NULL) {
      continue;
    }

    if (is_matching_address(interface->ifa_addr, (struct sockaddr *)&addr)) {
      unsigned if_index = if_nametoindex(interface->ifa_name);
      if (if_index == 0) {
        OC_ERR("failed obtaining interface index for %s (error=%d)",
               interface->ifa_name, (int)errno);
        freeifaddrs(ifs);
        return -1;
      }
      freeifaddrs(ifs);
      return if_index;
    }
  }

  freeifaddrs(ifs);
  return 0;
}

#if OC_DBG_IS_ENABLED
static void
log_new_session(oc_endpoint_t *endpoint, int sock, bool is_connected)
{
  // GCOVR_EXCL_START
  oc_string64_t ep;
  const char *addr = "";
  if (oc_endpoint_to_string64(endpoint, &ep)) {
    addr = oc_string(ep);
  }
  OC_DBG("new TCP session endpoint: %s, endpoint interface: %d, sock: %d, "
         "connected: %d, session_id: %u",
         addr, endpoint->interface_index, sock, (int)is_connected,
         (unsigned)endpoint->session_id);
  // GCOVR_EXCL_STOP
}

static void
log_free_session(oc_endpoint_t *endpoint, int sock)
{
  // GCOVR_EXCL_START
  oc_string64_t ep;
  const char *addr = "";
  if (oc_endpoint_to_string64(endpoint, &ep)) {
    addr = oc_string(ep);
  }
  OC_DBG("free TCP session endpoint: %s, endpoint interface: %d, sock: %d, "
         "session_id: %u",
         addr, endpoint->interface_index, sock, (unsigned)endpoint->session_id);
  // GCOVR_EXCL_STOP
}

#endif /* OC_DBG_IS_ENABLED */

static tcp_session_t *
add_new_session_locked(int sock, ip_context_t *dev, oc_endpoint_t *endpoint,
                       uint32_t session_id, tcp_csm_state_t state)
{
  long if_index = get_interface_index(sock);
  if (if_index < 0) {
    OC_ERR("could not obtain interface index for TCP session");
    return NULL;
  }

  tcp_session_t *session = oc_memb_alloc(&g_tcp_session_s);
  if (session == NULL) {
    OC_ERR("could not allocate new TCP session object");
    return NULL;
  }
  OC_DBG("new TCP session(%p, fd=%d)", (void *)session, sock);

  session->dev = dev;
  endpoint->interface_index = (unsigned)if_index;
  if (session_id == 0) {
    session_id = oc_tcp_get_new_session_id();
  }
  endpoint->session_id = session_id;
  memcpy(&session->endpoint, endpoint, sizeof(oc_endpoint_t));
  session->endpoint.next = NULL;
  session->endpoint.interface_index = (unsigned)if_index;
  session->sock = sock;
  session->csm_state = state;
  session->notify_session_end = true;

  oc_list_add(g_session_list, session);

  if ((session->endpoint.flags & SECURED) == 0) {
    oc_session_start_event(&session->endpoint);
  }
#if OC_DBG_IS_ENABLED
  log_new_session(&session->endpoint, sock, true);
#endif /* OC_DBG_IS_ENABLED */
  return session;
}

static int
accept_new_session_locked(ip_context_t *dev, int fd, fd_set *setfds,
                          oc_endpoint_t *endpoint)
{
  struct sockaddr_storage receive_from;
  memset(&receive_from, 0, sizeof(receive_from));
  socklen_t receive_len = sizeof(receive_from);

  int new_socket = accept(fd, (struct sockaddr *)&receive_from, &receive_len);
  if (new_socket < 0) {
    OC_ERR("failed to accept incoming TCP connection");
    return -1;
  }
  OC_DBG("accepted incoming TCP connection (fd=%d)", new_socket);
  FD_CLR(fd, setfds);

  if ((endpoint->flags & IPV6) != 0) {
    const struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receive_from;
    memcpy(endpoint->addr.ipv6.address, r->sin6_addr.s6_addr,
           sizeof(r->sin6_addr.s6_addr));
    assert(r->sin6_scope_id < UINT8_MAX);
    endpoint->addr.ipv6.scope = (uint8_t)r->sin6_scope_id;
    endpoint->addr.ipv6.port = ntohs(r->sin6_port);
#ifdef OC_IPV4
  } else if ((endpoint->flags & IPV4) != 0) {
    const struct sockaddr_in *r = (struct sockaddr_in *)&receive_from;
    memcpy(endpoint->addr.ipv4.address, &r->sin_addr.s_addr,
           sizeof(r->sin_addr.s_addr));
    endpoint->addr.ipv4.port = ntohs(r->sin_port);
#endif /* !OC_IPV4 */
  }

  if (add_new_session_locked(new_socket, dev, endpoint,
                             /*session_id*/ 0, CSM_NONE) == NULL) {
    OC_ERR("could not record new TCP session");
    close(new_socket);
    return -1;
  }

  ip_context_rfds_fd_set(dev, new_socket);
  return 0;
}

static void
free_session_locked(tcp_session_t *session, bool signal)
{
  oc_list_remove(g_session_list, session);
  oc_list_remove(g_free_session_list_async, session);

  if (!oc_session_events_disconnect_is_ongoing() &&
      session->notify_session_end) {
    oc_session_end_event(&session->endpoint);
  }

  ip_context_rfds_fd_clr(session->dev, session->sock);

  if (signal) {
    signal_network_thread(&session->dev->tcp);
  }
  close(session->sock);
#if OC_DBG_IS_ENABLED
  log_free_session(&session->endpoint, session->sock);
#endif /* OC_DBG_IS_ENABLED */
  oc_memb_free(&g_tcp_session_s, session);
}

static void
free_session_for_device_locked(size_t device)
{
  tcp_session_t *session = (tcp_session_t *)oc_list_head(g_session_list);
  while (session != NULL) {
    tcp_session_t *next = session->next;
    if (session->endpoint.device == device) {
      free_session_locked(session, false);
    }
    session = next;
  }
}

static adapter_receive_state_t
tcp_receive_server_message_locked(ip_context_t *dev, fd_set *fds,
                                  oc_message_t *message)
{
  if (oc_sock_listener_fd_isset(&dev->tcp.server, fds)) {
    OC_DBG("tcp receive server_sock(fd=%d)", dev->tcp.server.sock);
    FD_CLR(dev->tcp.server.sock, fds);
    message->endpoint.flags = IPV6 | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.server.sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      return ADAPTER_STATUS_ERROR;
    }
    return ADAPTER_STATUS_ACCEPT;
  }
#ifdef OC_SECURITY
  if (oc_sock_listener_fd_isset(&dev->tcp.secure, fds)) {
    OC_DBG("tcp receive secure_sock(fd=%d)", dev->tcp.secure.sock);
    FD_CLR(dev->tcp.secure.sock, fds);
    message->endpoint.flags = IPV6 | SECURED | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.secure.sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      return ADAPTER_STATUS_ERROR;
    }
    return ADAPTER_STATUS_ACCEPT;
  }
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  if (oc_sock_listener_fd_isset(&dev->tcp.server4, fds)) {
    OC_DBG("tcp receive server4_sock(fd=%d)", dev->tcp.server4.sock);
    FD_CLR(dev->tcp.server4.sock, fds);
    message->endpoint.flags = IPV4 | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.server4.sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      return ADAPTER_STATUS_ERROR;
    }
    return ADAPTER_STATUS_ACCEPT;
  }
#ifdef OC_SECURITY
  if (oc_sock_listener_fd_isset(&dev->tcp.secure4, fds)) {
    OC_DBG("tcp receive secure4_sock(fd=%d)", dev->tcp.secure4.sock);
    FD_CLR(dev->tcp.secure4.sock, fds);
    message->endpoint.flags = IPV4 | SECURED | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.secure4.sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      return ADAPTER_STATUS_ERROR;
    }
    return ADAPTER_STATUS_ACCEPT;
  }
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  return ADAPTER_STATUS_NONE;
}

static tcp_session_t *
get_ready_to_read_session_locked(const fd_set *setfds)
{
  tcp_session_t *session = oc_list_head(g_session_list);
  while (session != NULL && !FD_ISSET(session->sock, setfds)) {
    session = session->next;
  }
  return session;
}

static adapter_receive_state_t
tcp_session_receive_message_locked(tcp_session_t *session,
                                   oc_message_t *message)
{
  size_t total_length = 0;
  size_t want_read = OC_TCP_DEFAULT_RECEIVE_SIZE;
  message->length = 0;
  do {
    ssize_t count =
      recv(session->sock, message->data + message->length, want_read, 0);
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      OC_ERR("recv error! %d", (int)errno);
      free_session_locked(session, true);
      return ADAPTER_STATUS_ERROR;
    }
    if (count == 0) {
      OC_DBG("peer closed TCP session\n");
      free_session_locked(session, true);
      return ADAPTER_STATUS_NONE;
    }

    OC_DBG("recv(): %zu bytes.", (size_t)count);
    message->length += (size_t)count;
    want_read -= (size_t)count;
    OC_DBG("written message buffer from=%p to=%p", (void *)message->data,
           (void *)(message->data + message->length));

    if (total_length == 0) {
      memcpy(&message->endpoint, &session->endpoint, sizeof(oc_endpoint_t));
#ifdef OC_SECURITY
      if ((message->endpoint.flags & SECURED) != 0) {
        message->encrypted = 1;
      }
#endif /* OC_SECURITY */

      long length_from_header =
        oc_tcp_get_total_length_from_message_header(message);
      if (length_from_header < 0) {
        OC_ERR("invalid message size in header");
        free_session_locked(session, true);
        return ADAPTER_STATUS_ERROR;
      }

      total_length = (size_t)length_from_header;
      // check to avoid buffer overflow
      if (total_length > oc_message_buffer_size(message)) {
        OC_ERR(
          "total receive length(%zu) is bigger than message buffer size(%zu)",
          total_length, oc_message_buffer_size(message));
        free_session_locked(session, true);
        return ADAPTER_STATUS_ERROR;
      }
      OC_DBG("tcp packet total length : %zu bytes.", total_length);

      want_read = total_length - (size_t)count;
    }
  } while (total_length > message->length);

  if (!oc_tcp_is_valid_message(message)) {
    free_session_locked(session, true);
    return ADAPTER_STATUS_ERROR;
  }

  return ADAPTER_STATUS_RECEIVE;
}

adapter_receive_state_t
tcp_receive_message(ip_context_t *dev, fd_set *fds, oc_message_t *message)
{
  pthread_mutex_lock(&g_mutex);
  message->endpoint.device = dev->device;

  adapter_receive_state_t ret =
    tcp_receive_server_message_locked(dev, fds, message);
  if (ret != ADAPTER_STATUS_NONE) {
    goto tcp_receive_message_done;
  }

  // find session.
  tcp_session_t *session = get_ready_to_read_session_locked(fds);
  if (session == NULL) {
    OC_DBG("could not find TCP session socket in fd set");
    ret = ADAPTER_STATUS_NONE;
    goto tcp_receive_message_done;
  }
  OC_DBG("tcp receive session(fd=%d)", session->sock);
  FD_CLR(session->sock, fds);

  ret = tcp_session_receive_message_locked(session, message);
  if (ret != ADAPTER_STATUS_RECEIVE) {
    goto tcp_receive_message_done;
  }

tcp_receive_message_done:
  pthread_mutex_unlock(&g_mutex);
  return ret;
}

#if OC_DBG_IS_ENABLED
static void
log_tcp_session(const void *session, const oc_endpoint_t *endpoint,
                bool is_connected)
{
  if (session == NULL) {
    OC_DBG("could not find %s TCP session for",
           is_connected ? "ongoing" : "waiting");
    OC_LOGipaddr(*endpoint);
    OC_DBG("%s", "");
    return;
  }
  OC_DBG("found %s TCP session for", is_connected ? "ongoing" : "waiting");
  OC_LOGipaddr(*endpoint);
  OC_DBG("%s", "");
}
#endif /* OC_DBG_IS_ENABLED */

static tcp_session_t *
find_session_by_endpoint_locked(const oc_endpoint_t *endpoint)
{
  tcp_session_t *session = oc_list_head(g_session_list);
  while (session != NULL &&
         oc_endpoint_compare(&session->endpoint, endpoint) != 0) {
    session = session->next;
  }
#if OC_DBG_IS_ENABLED
  log_tcp_session(session, endpoint, true);
#endif /* OC_DBG_IS_ENABLED */
  return session;
}

static tcp_session_t *
find_session_by_id_locked(uint32_t session_id)
{
  tcp_session_t *session = oc_list_head(g_session_list);
  while (session != NULL && session->endpoint.session_id != session_id) {
    session = session->next;
  }
  return session;
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

static tcp_session_t *
tcp_create_session_locked(int sock, ip_context_t *dev, oc_endpoint_t *endpoint,
                          uint32_t session_id, bool signal)
{
  tcp_session_t *session =
    add_new_session_locked(sock, dev, endpoint, session_id, CSM_SENT);
  if (session == NULL) {
    OC_ERR("could not record new TCP session");
    return NULL;
  }

  ip_context_rfds_fd_set(dev, sock);
  if (signal) {
    signal_network_thread(&dev->tcp);
  }
  OC_DBG("signaled network event thread to monitor the newly added session");
  return session;
}

static tcp_waiting_session_t *
find_waiting_session_by_endpoint_locked(const oc_endpoint_t *endpoint)
{
  tcp_waiting_session_t *ws =
    (tcp_waiting_session_t *)oc_list_head(g_waiting_session_list);
  while (ws != NULL && oc_endpoint_compare(&ws->endpoint, endpoint) != 0) {
    ws = ws->next;
  }
#if OC_DBG_IS_ENABLED
  log_tcp_session(ws, endpoint, false);
#endif /* OC_DBG_IS_ENABLED */
  return ws;
}

static tcp_waiting_session_t *
find_waiting_session_by_id_locked(uint32_t session_id)
{
  tcp_waiting_session_t *ws =
    (tcp_waiting_session_t *)oc_list_head(g_waiting_session_list);
  while (ws != NULL && ws->endpoint.session_id != session_id) {
    ws = ws->next;
  }
  return ws;
}

static tcp_waiting_session_t *
add_new_waiting_session_locked(int sock, ip_context_t *dev,
                               const oc_endpoint_t *endpoint,
                               on_tcp_connect_t on_tcp_connect,
                               void *on_tcp_connect_data)
{
  tcp_waiting_session_t *ws = oc_memb_alloc(&g_tcp_waiting_session_s);
  if (ws == NULL) {
    OC_ERR("could not allocate new TCP waiting session object");
    return NULL;
  }
  OC_DBG("new waiting TCP session(%p, fd=%d)", (void *)ws, sock);

  ws->dev = dev;
  memcpy(&ws->endpoint, endpoint, sizeof(oc_endpoint_t));
  ws->endpoint.session_id = oc_tcp_get_new_session_id();
  ws->endpoint.next = NULL;
  ws->sock = sock;
  OC_LIST_STRUCT_INIT(ws, messages);
  ws->retry.start = oc_clock_time_monotonic();
  ws->retry.count = 0;
  ws->on_tcp_connect = on_tcp_connect;
  ws->on_tcp_connect_data = on_tcp_connect_data;
  ws->notify_session_end = true;

#if OC_DBG_IS_ENABLED
  log_new_session(&ws->endpoint, sock, false);
#endif /* OC_DBG_IS_ENABLED */

  oc_list_add(g_waiting_session_list, ws);
  return ws;
}

static void
tcp_waiting_session_set_socked_locked(tcp_context_t *tcp, int sock)
{
  if (sock > 0) {
    tcp_context_cfds_fd_set(tcp, sock);
  }
  signal_network_thread(tcp);
  OC_DBG(
    "signaled network event thread to monitor the newly added session(fd=%d) "
    "waiting for connect",
    sock);
}

static tcp_waiting_session_t *
tcp_create_waiting_session_locked(int sock, ip_context_t *dev,
                                  const oc_endpoint_t *endpoint,
                                  on_tcp_connect_t on_tcp_connect,
                                  void *on_tcp_connect_data)
{
  tcp_waiting_session_t *ws = add_new_waiting_session_locked(
    sock, dev, endpoint, on_tcp_connect, on_tcp_connect_data);
  if (ws == NULL) {
    OC_ERR("could not record new waiting TCP session");
    return NULL;
  }
  tcp_waiting_session_set_socked_locked(&dev->tcp, sock);
  return ws;
}

typedef struct
{
  tcp_session_t *session;
  tcp_waiting_session_t *waiting_session;
  bool created;
} tcp_connect_result_t;

static tcp_connect_result_t
tcp_connect_locked(ip_context_t *dev, oc_endpoint_t *endpoint,
                   const struct sockaddr_storage *receiver,
                   on_tcp_connect_t on_tcp_connect, void *on_tcp_connect_data)
{
  tcp_connect_result_t res = {
    .session = NULL,
    .waiting_session = NULL,
    .created = false,
  };
  tcp_session_t *s = find_session_by_endpoint_locked(endpoint);
  if (s != NULL) {
    res.session = s;
    return res;
  }
  if ((endpoint->flags & ACCEPTED) != 0) {
    OC_ERR("connection was closed");
    return res;
  }
  tcp_waiting_session_t *ws = find_waiting_session_by_endpoint_locked(endpoint);
  if (ws != NULL) {
    res.waiting_session = ws;
    return res;
  }

  oc_tcp_socket_t cs = oc_tcp_socket_connect(endpoint, receiver);
  if (cs.state == OC_TCP_SOCKET_STATE_CONNECTED) {
    OC_DBG("successfully initiated TCP connection");
    s = tcp_create_session_locked(cs.fd, dev, endpoint, /*session_id*/ 0, true);
    if (s != NULL) {
      res.session = s;
      res.created = true;
      return res;
    }
  } else if (cs.state == OC_TCP_SOCKET_STATE_CONNECTING) {
    ws = tcp_create_waiting_session_locked(cs.fd, dev, endpoint, on_tcp_connect,
                                           on_tcp_connect_data);
    if (ws != NULL) {
      res.waiting_session = ws;
      res.created = true;
      return res;
    }
  }
  if (cs.fd >= 0) {
    close(cs.fd);
  }
  OC_ERR("cannot create session");
  return res;
}

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

static void
free_session_async_locked(tcp_session_t *s, bool notify_session_end)
{
  oc_list_remove(g_session_list, s);
  oc_list_add(g_free_session_list_async, s);
  s->notify_session_end = notify_session_end;

  signal_network_thread(&s->dev->tcp);
  OC_DBG("signaled network event thread to monitor that the session needs to "
         "be removed");
  OC_DBG("free TCP session async");
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
static void
free_waiting_session_async_locked(tcp_waiting_session_t *ws,
                                  bool notify_session_end)
{
  oc_list_remove(g_waiting_session_list, ws);
  oc_list_add(g_free_waiting_session_list_async, ws);
  ws->notify_session_end = notify_session_end;

  signal_network_thread(&ws->dev->tcp);
  OC_DBG("signaled network event thread to monitor that the session needs to "
         "be removed");
  OC_DBG("free waiting TCP session async");
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

bool
tcp_end_session(const oc_endpoint_t *endpoint, bool notify_session_end,
                oc_endpoint_t *session_endpoint)
{
  pthread_mutex_lock(&g_mutex);
  tcp_session_t *s = find_session_by_endpoint_locked(endpoint);
  if (s != NULL) {
    free_session_async_locked(s, notify_session_end);
    if (session_endpoint) {
      memcpy(session_endpoint, &s->endpoint, sizeof(oc_endpoint_t));
    }
    pthread_mutex_unlock(&g_mutex);
    return true;
  }

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  tcp_waiting_session_t *ws = find_waiting_session_by_endpoint_locked(endpoint);
  if (ws != NULL) {
    free_waiting_session_async_locked(ws, notify_session_end);
    if (session_endpoint) {
      memcpy(session_endpoint, &ws->endpoint, sizeof(oc_endpoint_t));
    }
    pthread_mutex_unlock(&g_mutex);
    return true;
  }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

  pthread_mutex_unlock(&g_mutex);
  return false;
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
static void
free_waiting_session_locked(tcp_waiting_session_t *session, bool has_expired,
                            bool signal)
{
  oc_list_remove(g_waiting_session_list, session);
  oc_list_remove(g_free_waiting_session_list_async, session);

  queued_message_t *qm = (queued_message_t *)oc_list_pop(session->messages);
  while (qm != NULL) {
    OC_DBG("queued tcp session message(%p) discarded", (void *)qm->message);
    oc_message_unref(qm->message);
    oc_memb_free(&g_queued_message_s, qm);
    qm = oc_list_pop(session->messages);
  }

  if (signal) {
    signal_network_thread(&session->dev->tcp);
  }
  if (session->sock >= 0) {
    tcp_context_cfds_fd_clr(&session->dev->tcp, session->sock);
    close(session->sock);
  }

  if (session->on_tcp_connect != NULL) {
    oc_tcp_on_connect_event_t *event = oc_tcp_on_connect_event_create(
      &session->endpoint,
      has_expired ? OC_TCP_SOCKET_ERROR_TIMEOUT : OC_TCP_SOCKET_ERROR,
      session->on_tcp_connect, session->on_tcp_connect_data);
    if (event == NULL) {
      oc_abort("cannot send on TCP connect event: insufficient memory");
    }
    oc_network_tcp_connect_event(event);
  }

  OC_DBG("freed waiting TCP session(%p, fd=%d)", (void *)session,
         session->sock);
  oc_memb_free(&g_tcp_waiting_session_s, session);
}

static void
free_waiting_session_for_device_locked(size_t device)
{
  tcp_waiting_session_t *session =
    (tcp_waiting_session_t *)oc_list_head(g_waiting_session_list);
  while (session != NULL) {
    tcp_waiting_session_t *next = session->next;
    if (session->endpoint.device == device) {
      free_waiting_session_locked(session, false, false);
    }
    session = next;
  }
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

static void
tcp_process_async_sessions_locked(void)
{
  while (true) {
    tcp_session_t *s = (tcp_session_t *)oc_list_pop(g_free_session_list_async);
    if (s == NULL) {
      break;
    }
    free_session_locked(s, true);
  }

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  while (true) {
    tcp_waiting_session_t *ws =
      (tcp_waiting_session_t *)oc_list_pop(g_free_waiting_session_list_async);
    if (ws == NULL) {
      break;
    }
    free_waiting_session_locked(ws, false, true);
  }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
}

void
tcp_session_shutdown(const ip_context_t *dev)
{
  pthread_mutex_lock(&g_mutex);
  free_session_for_device_locked(dev->device);
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  free_waiting_session_for_device_locked(dev->device);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  tcp_process_async_sessions_locked();
  pthread_mutex_unlock(&g_mutex);
}

int
oc_tcp_connection_state(const oc_endpoint_t *endpoint)
{
  pthread_mutex_lock(&g_mutex);
  const tcp_session_t *s = find_session_by_endpoint_locked(endpoint);
  if (s != NULL) {
    pthread_mutex_unlock(&g_mutex);
    return OC_TCP_SOCKET_STATE_CONNECTED;
  }

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  const tcp_waiting_session_t *ws =
    find_waiting_session_by_endpoint_locked(endpoint);
  if (ws != NULL) {
    pthread_mutex_unlock(&g_mutex);
    return OC_TCP_SOCKET_STATE_CONNECTING;
  }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  pthread_mutex_unlock(&g_mutex);
  return -1;
}

int
oc_tcp_session_state(uint32_t session_id)
{
  pthread_mutex_lock(&g_mutex);
  if (find_session_by_id_locked(session_id) != NULL) {
    pthread_mutex_unlock(&g_mutex);
    return OC_TCP_SOCKET_STATE_CONNECTED;
  }
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  if (find_waiting_session_by_id_locked(session_id) != NULL) {
    pthread_mutex_unlock(&g_mutex);
    return OC_TCP_SOCKET_STATE_CONNECTING;
  }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  pthread_mutex_unlock(&g_mutex);
  return -1;
}

static int
tcp_send_message(int sockfd, const oc_message_t *message)
{
  size_t bytes_sent = 0;
  do {
    ssize_t send_len = send(sockfd, message->data + bytes_sent,
                            message->length - bytes_sent, MSG_NOSIGNAL);
    if (send_len < 0) {
      if (errno == EINTR) {
        continue;
      }
      OC_WRN("send() returned errno %d", (int)errno);
      if (bytes_sent == 0) {
        return -1;
      }
      return (int)bytes_sent;
    }
    bytes_sent += send_len;
  } while (bytes_sent < message->length);

  OC_DBG("Sent %zu bytes", bytes_sent);
  assert(bytes_sent <= INT_MAX);
  return (int)bytes_sent;
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
static bool
add_message_to_waiting_session_locked(tcp_waiting_session_t *session,
                                      oc_message_t *message)
{
  assert(session != NULL);
  queued_message_t *qm = oc_memb_alloc(&g_queued_message_s);
  if (qm == NULL) {
    OC_ERR("could not allocate new queued message");
    return false;
  }

  OC_DBG("message added to waiting session queue(%p)", (void *)message);
  oc_message_add_ref(message);
  qm->message = message;
  oc_list_add(session->messages, qm);
  return true;
}

static int
tcp_connect_and_send_buffer_locked(ip_context_t *dev, oc_message_t *message,
                                   const struct sockaddr_storage *receiver)
{
  if (message->length == OC_SEND_MESSAGE_QUEUED) {
    return -1;
  }

  tcp_connect_result_t res =
    tcp_connect_locked(dev, &message->endpoint, receiver, NULL, NULL);

  if (res.session != NULL) {
    return tcp_send_message(res.session->sock, message);
  }

  if (res.waiting_session != NULL) {
    if (add_message_to_waiting_session_locked(res.waiting_session, message)) {
      return OC_SEND_MESSAGE_QUEUED;
    }
    OC_ERR("cannot queue message");
    return -1;
  }
  OC_ERR("cannot create TCP session");
  return -1;
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

int
oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                   const struct sockaddr_storage *receiver)
{
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  pthread_mutex_lock(&g_mutex);
  int bytes_sent = tcp_connect_and_send_buffer_locked(dev, message, receiver);
  pthread_mutex_unlock(&g_mutex);
  return bytes_sent;
#else  /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  (void)dev;
  (void)receiver;
  return oc_tcp_send_buffer2(message, false);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
}

int
oc_tcp_send_buffer2(oc_message_t *message, bool queue)
{
  const oc_endpoint_t *ep = &message->endpoint;
  pthread_mutex_lock(&g_mutex);
  const tcp_session_t *s = find_session_by_endpoint_locked(ep);
  if (s != NULL) {
    int ret = tcp_send_message(s->sock, message);
    pthread_mutex_unlock(&g_mutex);
    return ret;
  }

  if ((ep->flags & ACCEPTED) != 0) {
    OC_ERR("connection was closed");
    pthread_mutex_unlock(&g_mutex);
    return -1;
  }

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  if (queue) {
    tcp_waiting_session_t *ws = find_waiting_session_by_endpoint_locked(ep);
    if (ws != NULL && add_message_to_waiting_session_locked(ws, message)) {
      pthread_mutex_unlock(&g_mutex);
      return OC_SEND_MESSAGE_QUEUED;
    }
  }
#else  /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  (void)queue;
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

  pthread_mutex_unlock(&g_mutex);
  OC_ERR("no TCP session found");
  return OC_TCP_SOCKET_ERROR_NOT_CONNECTED;
}

void
tcp_session_handle_signal(void)
{
  pthread_mutex_lock(&g_mutex);
  tcp_process_async_sessions_locked();
  pthread_mutex_unlock(&g_mutex);
}

tcp_csm_state_t
oc_tcp_get_csm_state(const oc_endpoint_t *endpoint)
{
  if (endpoint == NULL) {
    return CSM_ERROR;
  }

  pthread_mutex_lock(&g_mutex);
  const tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (session == NULL) {
    pthread_mutex_unlock(&g_mutex);
    return CSM_NONE;
  }

  tcp_csm_state_t csm_state = session->csm_state;
  pthread_mutex_unlock(&g_mutex);
  return csm_state;
}

int
oc_tcp_update_csm_state(const oc_endpoint_t *endpoint, tcp_csm_state_t csm)
{
  if (endpoint == NULL) {
    return -1;
  }

  pthread_mutex_lock(&g_mutex);
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (session == NULL) {
    pthread_mutex_unlock(&g_mutex);
    return -1;
  }

  session->csm_state = csm;
  pthread_mutex_unlock(&g_mutex);
  return 0;
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
void
oc_tcp_set_connect_retry(uint8_t max_count, uint16_t timeout)
{
  pthread_mutex_lock(&g_mutex);
  g_connect_retry.max_count = max_count;
  g_connect_retry.timeout = timeout;
  pthread_mutex_unlock(&g_mutex);
  OC_DBG("tcp connect retry configuration: max_count=%u timeout=%u",
         (unsigned)max_count, (unsigned)timeout);
}

static void
tcp_send_waiting_messages_locked(tcp_waiting_session_t *ws,
                                 const tcp_session_t *s)
{
  assert(s != NULL);
  queued_message_t *qm = (queued_message_t *)oc_list_pop(ws->messages);
  while (qm != NULL) {
    if (s != NULL) {
      qm->message->endpoint.interface_index = s->endpoint.interface_index;
      if (tcp_send_message(s->sock, qm->message) < -1) {
        OC_WRN("failed to send queued message");
      }
    }
    oc_message_unref(qm->message);
    oc_memb_free(&g_queued_message_s, qm);
    qm = oc_list_pop(ws->messages);
  }
}

static bool
tcp_cleanup_connected_waiting_session_locked(tcp_waiting_session_t *ws,
                                             const tcp_session_t *s)
{
  if (ws->on_tcp_connect != NULL) {
    oc_tcp_on_connect_event_t *event = oc_tcp_on_connect_event_create(
      &ws->endpoint, OC_TCP_SOCKET_STATE_CONNECTED, ws->on_tcp_connect,
      ws->on_tcp_connect_data);
    if (event == NULL) {
      return false;
    }
    oc_network_tcp_connect_event(event);
  }

  oc_list_remove(g_waiting_session_list, ws);
  tcp_send_waiting_messages_locked(ws, s);
  signal_network_thread(&ws->dev->tcp);
  oc_memb_free(&g_tcp_waiting_session_s, ws);
  return true;
}

static bool
tcp_try_connect_waiting_session_locked(tcp_waiting_session_t *ws, int *err)
{
  assert(ws != NULL && ws->sock != -1);
  int error = 0;
  socklen_t len = sizeof(error);
  if (getsockopt(ws->sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
    OC_ERR("get socket options error: %d", (int)errno);
    return false; /* Solaris pending error */
  }
  if (error != 0) {
    *err = error;
    OC_ERR("socket error: %d", error);
    return false;
  }

  if (!oc_fcntl_set_blocking(ws->sock)) {
    OC_ERR("cannot set blocking socket(%d)", ws->sock);
    return false;
  }

  tcp_session_t *s = tcp_create_session_locked(ws->sock, ws->dev, &ws->endpoint,
                                               ws->endpoint.session_id, false);
  if (s == NULL) {
    return false;
  }
  tcp_context_cfds_fd_clr(&ws->dev->tcp, ws->sock);
  ws->sock = -1; // socket was taken by the ongoing session

  if (!tcp_cleanup_connected_waiting_session_locked(ws, s)) {
    free_session_locked(s, false);
    return false;
  }

  return true;
}

typedef enum {
  TCP_WAITING_SESSION_STATE_VALID,
  TCP_WAITING_SESSION_STATE_RETRY,
  TCP_WAITING_SESSION_STATE_EXPIRED,
  TCP_WAITING_SESSION_STATE_ERROR,
} tcp_waiting_session_state_t;

typedef struct
{
  tcp_waiting_session_state_t state;
  oc_clock_time_t expires_in;
} tcp_waiting_session_check_result_t;

static tcp_waiting_session_check_result_t
tcp_waiting_session_check(const tcp_waiting_session_t *session,
                          oc_clock_time_t now_mt,
                          oc_tcp_connect_retry_t connect_retry)
{
  tcp_waiting_session_check_result_t result = { TCP_WAITING_SESSION_STATE_ERROR,
                                                0 };
  if (session->retry.error != 0) {
    return result;
  }
  bool retry = session->retry.force != 0;
  if (!retry) {
    oc_clock_time_t timeout_ticks =
      (oc_clock_time_t)connect_retry.timeout * OC_CLOCK_SECOND;
    oc_clock_time_t elapsed = now_mt - session->retry.start;
    retry = elapsed >= timeout_ticks;
    if (!retry) {
      result.state = TCP_WAITING_SESSION_STATE_VALID;
      result.expires_in = timeout_ticks - elapsed;
      return result;
    }
  }
  if (session->retry.count >= connect_retry.max_count) {
    result.state = TCP_WAITING_SESSION_STATE_EXPIRED;
    return result;
  }
  result.state = TCP_WAITING_SESSION_STATE_RETRY;
  return result;
}

static int
tcp_retry_waiting_session_locked(tcp_waiting_session_t *ws,
                                 oc_clock_time_t now_mt)
{
  OC_DBG("try connect waiting session(%p, fd=%d): %u", (void *)ws, ws->sock,
         (unsigned)ws->retry.count);
  if (ws->sock >= 0) {
    tcp_context_cfds_fd_clr(&ws->dev->tcp, ws->sock);
    OC_DBG("close waiting session socket(fd=%d)", ws->sock);
    close(ws->sock);
    ws->sock = -1;
  }

  oc_tcp_socket_t cs = oc_tcp_socket_connect(&ws->endpoint, NULL);
  if (cs.state == OC_TCP_SOCKET_STATE_CONNECTED) {
    OC_DBG("successfully initiated TCP connection");
    tcp_session_t *s = tcp_create_session_locked(
      cs.fd, ws->dev, &ws->endpoint, ws->endpoint.session_id, false);
    if (s == NULL) {
      OC_ERR("cannot allocate ongoing TCP connection");
      return -1;
    }
    if (!tcp_cleanup_connected_waiting_session_locked(ws, s)) {
      free_session_locked(s, false);
      return -1;
    }
    return OC_TCP_SOCKET_STATE_CONNECTED;
  }

  if (cs.state == OC_TCP_SOCKET_STATE_CONNECTING) {
    ++ws->retry.count;
    ws->retry.start = now_mt;
    ws->retry.force = 0;
    ws->sock = cs.fd;
    tcp_waiting_session_set_socked_locked(&ws->dev->tcp, ws->sock);
    return OC_TCP_SOCKET_STATE_CONNECTING;
  }
  return -1;
}

oc_clock_time_t
tcp_check_expiring_sessions(oc_clock_time_t now_mt)
{
  oc_clock_time_t expires_in = 0;
  pthread_mutex_lock(&g_mutex);
  oc_tcp_connect_retry_t connect_retry = g_connect_retry; // copy under lock
  for (tcp_waiting_session_t *ws =
         (tcp_waiting_session_t *)oc_list_head(g_waiting_session_list);
       ws != NULL;) {
    tcp_waiting_session_t *ws_next = ws->next;
    tcp_waiting_session_check_result_t check =
      tcp_waiting_session_check(ws, now_mt, connect_retry);
    switch (check.state) {
    case TCP_WAITING_SESSION_STATE_RETRY: {
      int state = tcp_retry_waiting_session_locked(ws, now_mt);
      if (state == OC_TCP_SOCKET_STATE_CONNECTED) {
        break;
      }
      if (state == OC_TCP_SOCKET_STATE_CONNECTING) {
        expires_in = (oc_clock_time_t)connect_retry.timeout * OC_CLOCK_SECOND;
        break;
      }
      free_waiting_session_locked(ws, true, false);
      break;
    }
    case TCP_WAITING_SESSION_STATE_VALID:
      if (expires_in == 0 || check.expires_in < expires_in) {
        expires_in = check.expires_in;
      }
      break;
    case TCP_WAITING_SESSION_STATE_ERROR:
      free_waiting_session_locked(ws, false, false);
      break;
    case TCP_WAITING_SESSION_STATE_EXPIRED:
      free_waiting_session_locked(ws, true, false);
      break;
    }
    ws = ws_next;
  }
  pthread_mutex_unlock(&g_mutex);
  return expires_in;
}

static void
tcp_process_waiting_session_locked(tcp_waiting_session_t *ws)
{
  int error = 0;
  if (!tcp_try_connect_waiting_session_locked(ws, &error)) {
    OC_DBG("failed to connect session(%p, fd=%d)", (void *)ws, ws->sock);
    if (ws->sock >= 0) {
      tcp_context_cfds_fd_clr(&ws->dev->tcp, ws->sock);
      close(ws->sock);
      ws->sock = -1;
    }
    if (error == 0) {
      ws->retry.force = 1;
      ws->retry.error = 0;
    } else {
      // close the connection
      ws->retry.error = 1;
    }
  }
}

bool
tcp_process_waiting_sessions(fd_set *fds)
{
  bool ret = false;
  pthread_mutex_lock(&g_mutex);
  for (tcp_waiting_session_t *ws =
         (tcp_waiting_session_t *)oc_list_head(g_waiting_session_list);
       ws != NULL; ws = ws->next) {
    if (ws->sock == -1 || !FD_ISSET(ws->sock, fds)) {
      continue;
    }

    OC_DBG("tcp session(%p) connect (fd=%d): %u", (void *)ws, ws->sock,
           (unsigned)ws->retry.count);
    FD_CLR(ws->sock, fds);
    ret = true;
    tcp_process_waiting_session_locked(ws);
    break;
  }
  pthread_mutex_unlock(&g_mutex);
  return ret;
}

static oc_tcp_connect_result_t
tcp_connect_to_endpoint(ip_context_t *dev, oc_endpoint_t *endpoint,
                        on_tcp_connect_t on_tcp_connect,
                        void *on_tcp_connect_data)
{
  struct sockaddr_storage receiver = oc_socket_get_address(endpoint);
  pthread_mutex_lock(&g_mutex);
  tcp_connect_result_t res = tcp_connect_locked(
    dev, endpoint, &receiver, on_tcp_connect, on_tcp_connect_data);
  bool is_connected = false;
  uint32_t session_id = 0;
  if (res.session != NULL) {
    is_connected = true;
    session_id = res.session->endpoint.session_id;
  } else if (res.waiting_session != NULL) {
    session_id = res.waiting_session->endpoint.session_id;
  }
  pthread_mutex_unlock(&g_mutex);
  if (session_id == 0) {
    return (oc_tcp_connect_result_t){
      .error = OC_TCP_SOCKET_ERROR,
    };
  }
  if (!res.created) {
    oc_tcp_socket_error_t err = is_connected
                                  ? OC_TCP_SOCKET_ERROR_EXISTS_CONNECTED
                                  : OC_TCP_SOCKET_ERROR_EXISTS_CONNECTING;
    return (oc_tcp_connect_result_t){
      .session_id = session_id,
      .error = err,
    };
  }

  oc_tcp_socket_state_t state = is_connected ? OC_TCP_SOCKET_STATE_CONNECTED
                                             : OC_TCP_SOCKET_STATE_CONNECTING;
  return (oc_tcp_connect_result_t){
    .state = state,
    .session_id = session_id,
  };
}

oc_tcp_connect_result_t
oc_tcp_connect_to_endpoint(oc_endpoint_t *endpoint,
                           on_tcp_connect_t on_tcp_connect,
                           void *on_tcp_connect_data)
{
  assert((endpoint->flags & TCP) != 0);
  ip_context_t *dev = oc_get_ip_context_for_device(endpoint->device);
  if (dev == NULL) {
    OC_ERR("cannot find ip-context for device(%zu)", endpoint->device);
    return (oc_tcp_connect_result_t){
      .error = -1,
    };
  }
  return tcp_connect_to_endpoint(dev, endpoint, on_tcp_connect,
                                 on_tcp_connect_data);
}

int
oc_tcp_connect(oc_endpoint_t *endpoint, on_tcp_connect_t on_tcp_connect,
               void *on_tcp_connect_data)
{
  oc_tcp_connect_result_t ret =
    oc_tcp_connect_to_endpoint(endpoint, on_tcp_connect, on_tcp_connect_data);
  if (ret.session_id != 0) {
    endpoint->session_id = ret.session_id;
  }
  return ret.error != 0 ? ret.error : (int)ret.state;
}

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#endif /* OC_TCP */
