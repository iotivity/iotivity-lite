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

#include "api/oc_message_internal.h"
#include "api/oc_session_events_internal.h"
#include "api/oc_tcp_internal.h"
#include "ipcontext.h"
#include "messaging/coap/coap_internal.h"
#include "oc_endpoint.h"
#include "oc_session_events.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_tcp_socket_internal.h"
#include "tcpadapter.h"
#include "util/oc_memb.h"
#include "vfs_pipe.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <esp_netif.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef OC_TCP

#define OC_TCP_LISTEN_BACKLOG 3

#define LIMIT_RETRY_CONNECT 5

#define TCP_CONNECT_TIMEOUT 5

typedef struct tcp_session
{
  struct tcp_session *next;
  ip_context_t *dev;
  oc_endpoint_t endpoint;
  int sock;
  tcp_csm_state_t csm_state;
} tcp_session_t;

OC_LIST(session_list);
OC_MEMB(tcp_session_s, tcp_session_t, OC_MAX_TCP_PEERS);

static int
configure_tcp_socket(int sock, struct sockaddr_storage *sock_info)
{
  int reuse = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d", errno);
    return -1;
  }
  if (bind(sock, (struct sockaddr *)sock_info, sizeof(*sock_info)) == -1) {
    OC_ERR("binding socket %d", errno);
    return -1;
  }
  if (listen(sock, OC_TCP_LISTEN_BACKLOG) == -1) {
    OC_ERR("listening socket %d", errno);
    return -1;
  }

  return 0;
}

static int
get_assigned_tcp_port(int sock, struct sockaddr_storage *sock_info)
{

  socklen_t socklen = sizeof(*sock_info);
  if (getsockname(sock, (struct sockaddr *)sock_info, &socklen) == -1) {
    OC_ERR("obtaining socket information %d", errno);
    return -1;
  }

  return 0;
}

static int
get_interface_index(int sock)
{
  struct sockaddr_storage addr;
  socklen_t socklen = sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &socklen) == -1) {
    OC_ERR("obtaining socket information %d", errno);
    return -1;
  }
  for (esp_netif_t *esp_netif = esp_netif_next(NULL); esp_netif;
       esp_netif = esp_netif_next(esp_netif)) {
    if (!esp_netif_is_netif_up(esp_netif)) {
      continue;
    }
    if (addr.ss_family == AF_INET) {
      esp_netif_ip_info_t ip_info;
      if (esp_netif_get_ip_info(esp_netif, &ip_info) != ESP_OK) {
        continue;
      }
      struct sockaddr_in *b = (struct sockaddr_in *)&addr;
      if (b->sin_addr.s_addr == ip_info.ip.addr) {
        return esp_netif_get_netif_impl_index(esp_netif);
      }
    }
    if (addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *b = (struct sockaddr_in6 *)&addr;
      esp_ip6_addr_t if_ip6[LWIP_IPV6_NUM_ADDRESSES];
      int num = esp_netif_get_all_ip6(esp_netif, if_ip6);
      for (int i = 0; i < num; ++i) {

        if (ip6_addr_isany(&if_ip6[i]) || ip6_addr_isloopback(&if_ip6[i])) {
          continue;
        }
        if (memcmp(&if_ip6[i].addr, b->sin6_addr.s6_addr, 16) == 0) {
          return esp_netif_get_netif_impl_index(esp_netif);
        }
      }
    }
  }
  OC_ERR("interface not found");
  return 0;
}

void
oc_tcp_add_socks_to_fd_set(ip_context_t *dev)
{
  FD_SET(dev->tcp.server_sock, &dev->rfds);
#ifdef OC_SECURITY
  FD_SET(dev->tcp.secure_sock, &dev->rfds);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  FD_SET(dev->tcp.server4_sock, &dev->rfds);
#ifdef OC_SECURITY
  FD_SET(dev->tcp.secure4_sock, &dev->rfds);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  FD_SET(dev->tcp.connect_pipe[0], &dev->rfds);
}

static void
free_tcp_session(tcp_session_t *session, bool notify_session_end)
{
  oc_list_remove(session_list, session);

  if (!oc_session_events_disconnect_is_ongoing() && notify_session_end) {
    oc_session_end_event(&session->endpoint);
  }

  FD_CLR(session->sock, &session->dev->rfds);

  ssize_t len = 0;
  do {
    uint8_t dummy_value = 0xef;
    len = write(session->dev->tcp.connect_pipe[1], &dummy_value, 1);
  } while (len == -1 && errno == EINTR);

  close(session->sock);

  oc_memb_free(&tcp_session_s, session);

  OC_DBG("freed TCP session");
}

static int
add_new_session(int sock, ip_context_t *dev, oc_endpoint_t *endpoint,
                uint32_t session_id, tcp_csm_state_t state)
{
  int if_index = get_interface_index(sock);
  if (if_index < 0) {
    OC_ERR("could not get interface index");
    return -1;
  }

  tcp_session_t *session = oc_memb_alloc(&tcp_session_s);
  if (!session) {
    OC_ERR("could not allocate new TCP session object");
    return -1;
  }

  session->dev = dev;
  endpoint->interface_index = (unsigned)if_index;
  if (session_id == 0) {
    session_id = oc_tcp_get_new_session_id();
  }
  endpoint->session_id = session_id;
  memcpy(&session->endpoint, endpoint, sizeof(oc_endpoint_t));
  session->endpoint.next = NULL;
  session->sock = sock;
  session->csm_state = state;

  oc_list_add(session_list, session);

  if ((session->endpoint.flags & SECURED) == 0) {
    oc_session_start_event(&session->endpoint);
  }

  OC_DBG("recorded new TCP session");

  return 0;
}

static int
accept_new_session(ip_context_t *dev, int fd, fd_set *setfds,
                   oc_endpoint_t *endpoint)
{
  struct sockaddr_storage receive_from;
  socklen_t receive_len = sizeof(receive_from);

  int new_socket = accept(fd, (struct sockaddr *)&receive_from, &receive_len);
  if (new_socket < 0) {
    OC_ERR("failed to accept incoming TCP connection");
    return -1;
  }
  OC_DBG("accepted incoming TCP connection");

  if (endpoint->flags & IPV6) {
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receive_from;
    memcpy(endpoint->addr.ipv6.address, r->sin6_addr.s6_addr,
           sizeof(r->sin6_addr.s6_addr));
    endpoint->addr.ipv6.scope = r->sin6_scope_id;
    endpoint->addr.ipv6.port = ntohs(r->sin6_port);
#ifdef OC_IPV4
  } else if (endpoint->flags & IPV4) {
    struct sockaddr_in *r = (struct sockaddr_in *)&receive_from;
    memcpy(endpoint->addr.ipv4.address, &r->sin_addr.s_addr,
           sizeof(r->sin_addr.s_addr));
    endpoint->addr.ipv4.port = ntohs(r->sin_port);
#endif /* !OC_IPV4 */
  }

  FD_CLR(fd, setfds);

  if (add_new_session(new_socket, dev, endpoint, /*session_id*/ 0, CSM_NONE) <
      0) {
    OC_ERR("could not record new TCP session");
    close(new_socket);
    return -1;
  }

  FD_SET(new_socket, &dev->rfds);

  return 0;
}

static tcp_session_t *
find_session_by_endpoint(const oc_endpoint_t *endpoint)
{
  tcp_session_t *session = oc_list_head(session_list);
  while (session != NULL &&
         oc_endpoint_compare(&session->endpoint, endpoint) != 0) {
    session = session->next;
  }

  if (!session) {
    OC_DBG("could not find ongoing TCP session for");
    OC_LOGipaddr(*endpoint);
    OC_DBG("%s", "");
    return NULL;
  }
  OC_DBG("found TCP session for");
  OC_LOGipaddr(*endpoint);
  OC_DBG("%s", "");
  return session;
}

static tcp_session_t *
find_session_by_id(uint32_t session_id)
{
  tcp_session_t *session = oc_list_head(session_list);
  while (session != NULL && session->endpoint.session_id != session_id) {
    session = session->next;
  }

  if (!session) {
    OC_DBG("could not find ongoing TCP session for session id %d", session_id);
    return NULL;
  }
  OC_DBG("found TCP session for session id %d", session_id);
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

adapter_receive_state_t
oc_tcp_receive_message(ip_context_t *dev, fd_set *fds, oc_message_t *message)
{
  pthread_mutex_lock(&dev->tcp.mutex);

#define ret_with_code(status)                                                  \
  ret = status;                                                                \
  goto oc_tcp_receive_message_done

  adapter_receive_state_t ret = ADAPTER_STATUS_ERROR;
  message->endpoint.device = dev->device;

  if (FD_ISSET(dev->tcp.server_sock, fds)) {
    message->endpoint.flags = IPV6 | TCP | ACCEPTED;
    if (accept_new_session(dev, dev->tcp.server_sock, fds, &message->endpoint) <
        0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#ifdef OC_SECURITY
  } else if (FD_ISSET(dev->tcp.secure_sock, fds)) {
    message->endpoint.flags = IPV6 | SECURED | TCP | ACCEPTED;
    if (accept_new_session(dev, dev->tcp.secure_sock, fds, &message->endpoint) <
        0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  } else if (FD_ISSET(dev->tcp.server4_sock, fds)) {
    message->endpoint.flags = IPV4 | TCP | ACCEPTED;
    if (accept_new_session(dev, dev->tcp.server4_sock, fds,
                           &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#ifdef OC_SECURITY
  } else if (FD_ISSET(dev->tcp.secure4_sock, fds)) {
    message->endpoint.flags = IPV4 | SECURED | TCP | ACCEPTED;
    if (accept_new_session(dev, dev->tcp.secure4_sock, fds,
                           &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  } else if (FD_ISSET(dev->tcp.connect_pipe[0], fds)) {
    ssize_t len = read(dev->tcp.connect_pipe[0], message->data, OC_PDU_SIZE);
    OC_DBG("oc_tcp_receive_message select: dev->tcp.connect_pipe[0]: %d",
           (int)len);
    if (len < 0) {
      OC_ERR("read error! %d", errno);
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    FD_CLR(dev->tcp.connect_pipe[0], fds);
    ret_with_code(ADAPTER_STATUS_NONE);
  }

  // find session.
  tcp_session_t *session = get_ready_to_read_session(fds);
  if (!session) {
    OC_DBG("could not find TCP session socket in fd set");
    ret_with_code(ADAPTER_STATUS_NONE);
  }

  // receive message.
  size_t total_length = 0;
  size_t want_read = OC_TCP_DEFAULT_RECEIVE_SIZE;
  message->length = 0;
  do {
    int count =
      recv(session->sock, message->data + message->length, want_read, 0);
    if (count < 0) {
      OC_ERR("recv error! %d", errno);

      free_tcp_session(session, true);

      ret_with_code(ADAPTER_STATUS_ERROR);
    } else if (count == 0) {
      OC_DBG("peer closed TCP session\n");

      free_tcp_session(session, true);

      ret_with_code(ADAPTER_STATUS_NONE);
    }

    OC_DBG("recv(): %d bytes.", count);
    message->length += (size_t)count;
    want_read -= (size_t)count;

    if (total_length == 0) {
      memcpy(&message->endpoint, &session->endpoint, sizeof(oc_endpoint_t));
#ifdef OC_SECURITY
      if (message->endpoint.flags & SECURED) {
        message->encrypted = 1;
      }
#endif /* OC_SECURITY */

      long length_from_header =
        oc_tcp_get_total_length_from_message_header(message);
      if (length_from_header < 0) {
        OC_ERR("invalid message size in header");
        free_tcp_session(session, true);
        ret_with_code(ADAPTER_STATUS_ERROR);
      }

      total_length = (size_t)length_from_header;
      // check to avoid buffer overflow
      if (total_length > oc_message_buffer_size(message)) {
        OC_ERR(
          "total receive length(%zu) is bigger than message buffer size(%zu)",
          total_length, oc_message_buffer_size(message));
        free_tcp_session(session, true);
        ret_with_code(ADAPTER_STATUS_ERROR);
      }
      OC_DBG("tcp packet total length : %zu bytes.", total_length);

      want_read = total_length - (size_t)count;
    }
  } while (total_length > message->length);

  if (!oc_tcp_is_valid_message(message)) {
    free_tcp_session(session, true);
    ret_with_code(ADAPTER_STATUS_ERROR);
  }

  FD_CLR(session->sock, fds);
  ret = ADAPTER_STATUS_RECEIVE;

oc_tcp_receive_message_done:
  pthread_mutex_unlock(&dev->tcp.mutex);
#undef ret_with_code
  return ret;
}

bool
oc_tcp_end_session(ip_context_t *dev, const oc_endpoint_t *endpoint,
                   bool notify_session_end, oc_endpoint_t *session_endpoint)
{
  pthread_mutex_lock(&dev->tcp.mutex);
  tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (session) {
    if (session_endpoint) {
      memcpy(session_endpoint, &session->endpoint, sizeof(oc_endpoint_t));
    }
    free_tcp_session(session, notify_session_end);
  }
  pthread_mutex_unlock(&dev->tcp.mutex);
  return session != NULL;
}

static int
get_session_socket(const oc_endpoint_t *endpoint)
{
  int sock = -1;
  const tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (!session) {
    return -1;
  }

  sock = session->sock;
  return sock;
}

static int
initiate_new_session(ip_context_t *dev, oc_endpoint_t *endpoint,
                     uint32_t session_id,
                     const struct sockaddr_storage *receiver)
{
  int sock = -1;
  uint8_t retry_cnt = 0;

  while (retry_cnt < LIMIT_RETRY_CONNECT) {
    sock =
      oc_tcp_socket_connect_and_wait(endpoint, receiver, TCP_CONNECT_TIMEOUT);
    if (sock >= 0) {
      break;
    }
    retry_cnt++;
    OC_DBG("connect failed, retry(%d)", retry_cnt);
  }

  if (retry_cnt >= LIMIT_RETRY_CONNECT) {
    OC_ERR("could not initiate TCP connection");
    return -1;
  }

  OC_DBG("successfully initiated TCP connection");

  if (add_new_session(sock, dev, endpoint, session_id, CSM_SENT) < 0) {
    OC_ERR("could not record new TCP session");
    close(sock);
    return -1;
  }

  FD_SET(sock, &dev->rfds);

  ssize_t len = 0;
  do {
    uint8_t dummy_value = 0xef;
    len = write(dev->tcp.connect_pipe[1], &dummy_value, 1);
  } while (len == -1 && errno == EINTR);

  OC_DBG("signaled network event thread to monitor the newly added session\n");

  return sock;
}

int
oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                   const struct sockaddr_storage *receiver)
{
  pthread_mutex_lock(&dev->tcp.mutex);
  int send_sock = get_session_socket(&message->endpoint);

  size_t bytes_sent = 0;
  if (send_sock < 0) {
    if (message->endpoint.flags & ACCEPTED) {
      OC_ERR("connection was closed");
      goto oc_tcp_send_buffer_done;
    }
    if ((send_sock =
           initiate_new_session(dev, &message->endpoint,
                                message->endpoint.session_id, receiver)) < 0) {
      OC_ERR("could not initiate new TCP session");
      goto oc_tcp_send_buffer_done;
    }
  }

  send_sock = get_session_socket(&message->endpoint);
  if (send_sock < 0) {
    goto oc_tcp_send_buffer_done;
  }

  do {
    ssize_t send_len = send(send_sock, message->data + bytes_sent,
                            message->length - bytes_sent, MSG_NOSIGNAL);
    if (send_len < 0) {
      OC_WRN("send() returned errno %d", errno);
      goto oc_tcp_send_buffer_done;
    }
    bytes_sent += send_len;
  } while (bytes_sent < message->length);

  OC_DBG("Sent %zd bytes", bytes_sent);
oc_tcp_send_buffer_done:
  pthread_mutex_unlock(&dev->tcp.mutex);

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
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

#ifdef OC_SECURITY
  memset(&dev->tcp.secure4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *sm = (struct sockaddr_in *)&dev->tcp.secure4;
  sm->sin_family = AF_INET;
  sm->sin_addr.s_addr = INADDR_ANY;
  sm->sin_port = 0;
#endif /* OC_SECURITY */

  dev->tcp.server4_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (dev->tcp.server4_sock < 0) {
    OC_ERR("creating TCP server socket");
    return -1;
  }

#ifdef OC_SECURITY
  dev->tcp.secure4_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.secure4_sock < 0) {
    OC_ERR("creating TCP secure socket");
    return -1;
  }
#endif /* OC_SECURITY */

  if (configure_tcp_socket(dev->tcp.server4_sock, &dev->tcp.server4) < 0) {
    OC_ERR("set socket option in server socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.server4_sock, &dev->tcp.server4) < 0) {
    OC_ERR("get port for server socket");
    return -1;
  }
  dev->tcp.port4 = ntohs(((struct sockaddr_in *)&dev->tcp.server4)->sin_port);

#ifdef OC_SECURITY
  if (configure_tcp_socket(dev->tcp.secure4_sock, &dev->tcp.secure4) < 0) {
    OC_ERR("set socket option in secure socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.secure4_sock, &dev->tcp.secure4) < 0) {
    OC_ERR("get port for secure socket");
    return -1;
  }
  dev->tcp.tls4_port =
    ntohs(((struct sockaddr_in *)&dev->tcp.secure4)->sin_port);
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

  if (pthread_mutex_init(&dev->tcp.mutex, NULL) != 0) {
    oc_abort("error initializing TCP adapter mutex");
  }
  memset(&dev->tcp.server, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->tcp.server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;

#ifdef OC_SECURITY
  memset(&dev->tcp.secure, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&dev->tcp.secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_addr = in6addr_any;
  sm->sin6_port = 0;
#endif /* OC_SECURITY */

  dev->tcp.server_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

  if (dev->tcp.server_sock < 0) {
    OC_ERR("creating TCP server socket");
    return -1;
  }

#ifdef OC_SECURITY
  dev->tcp.secure_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.secure_sock < 0) {
    OC_ERR("creating TCP secure socket");
    return -1;
  }
#endif /* OC_SECURITY */

  if (configure_tcp_socket(dev->tcp.server_sock, &dev->tcp.server) < 0) {
    OC_ERR("set socket option in server socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.server_sock, &dev->tcp.server) < 0) {
    OC_ERR("get port for server socket");
    return -1;
  }
  dev->tcp.port = ntohs(((struct sockaddr_in *)&dev->tcp.server)->sin_port);

#ifdef OC_SECURITY
  if (configure_tcp_socket(dev->tcp.secure_sock, &dev->tcp.secure) < 0) {
    OC_ERR("set socket option in secure socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.secure_sock, &dev->tcp.secure) < 0) {
    OC_ERR("get port for secure socket");
    return -1;
  }
  dev->tcp.tls_port = ntohs(((struct sockaddr_in *)&dev->tcp.secure)->sin_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (tcp_connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4 for TCP");
  }
#endif /* OC_IPV4 */

  if (vfs_pipe(dev->tcp.connect_pipe) < 0) {
    OC_ERR("Could not initialize connection pipe");
  }

  OC_DBG("=======tcp port info.========");
  OC_DBG("  ipv6 port   : %u", dev->tcp.port);
#ifdef OC_SECURITY
  OC_DBG("  ipv6 secure : %u", dev->tcp.tls_port);
#endif
#ifdef OC_IPV4
  OC_DBG("  ipv4 port   : %u", dev->tcp.port4);
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %u", dev->tcp.tls4_port);
#endif
#endif

  OC_DBG("Successfully initialized TCP adapter for device %zd", dev->device);

  return 0;
}

void
oc_tcp_connectivity_shutdown(ip_context_t *dev)
{
  close(dev->tcp.server_sock);

#ifdef OC_IPV4
  close(dev->tcp.server4_sock);
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  close(dev->tcp.secure_sock);
#ifdef OC_IPV4
  close(dev->tcp.secure4_sock);
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

  close(dev->tcp.connect_pipe[0]);
  close(dev->tcp.connect_pipe[1]);

  tcp_session_t *session = (tcp_session_t *)oc_list_head(session_list), *next;
  while (session != NULL) {
    next = session->next;
    if (session->endpoint.device == dev->device) {
      free_tcp_session(session, true);
    }
    session = next;
  }

  pthread_mutex_destroy(&dev->tcp.mutex);

  OC_DBG("oc_tcp_connectivity_shutdown for device %zd", dev->device);
}

int
oc_tcp_connection_state(const oc_endpoint_t *endpoint)
{
  if (find_session_by_endpoint(endpoint) != NULL) {
    return OC_TCP_SOCKET_STATE_CONNECTED;
  }
  return -1;
}

int
oc_tcp_session_state(uint32_t session_id)
{
  if (find_session_by_id(session_id) != NULL) {
    return OC_TCP_SOCKET_STATE_CONNECTED;
  }
  return -1;
}

tcp_csm_state_t
oc_tcp_get_csm_state(const oc_endpoint_t *endpoint)
{
  if (!endpoint) {
    return CSM_ERROR;
  }

  tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (!session) {
    return CSM_NONE;
  }

  return session->csm_state;
}

int
oc_tcp_update_csm_state(const oc_endpoint_t *endpoint, tcp_csm_state_t csm)
{
  if (!endpoint) {
    return -1;
  }

  tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (!session) {
    return -1;
  }

  session->csm_state = csm;
  return 0;
}
#endif /* OC_TCP */
