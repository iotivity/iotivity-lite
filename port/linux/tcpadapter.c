/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifdef OC_TCP

#define __USE_GNU

#include "tcpadapter.h"
#include "api/oc_session_events_internal.h"
#include "ipadapter.h"
#include "ipcontext.h"
#include "messaging/coap/coap.h"
#include "oc_endpoint.h"
#include "oc_session_events.h"
#include "port/oc_assert.h"
#include "util/oc_memb.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

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
  int sock;
  tcp_csm_state_t csm_state;
} tcp_session_t;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
OC_LIST(g_session_list);
OC_LIST(g_free_session_list_async);
OC_MEMB(g_tcp_session_s, tcp_session_t, OC_MAX_TCP_PEERS);

static void signal_network_thread(const ip_context_t *dev);

static int
configure_tcp_socket(int sock, struct sockaddr_storage *sock_info)
{
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
  int interface_index = -1;

  struct sockaddr_storage addr;
  socklen_t socklen = sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &socklen) == -1) {
    OC_ERR("obtaining socket information %d", errno);
    return -1;
  }

  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interfaces: %d", errno);
    return -1;
  }

  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    if (!(interface->ifa_flags & IFF_UP) || interface->ifa_flags & IFF_LOOPBACK)
      continue;
    if (interface->ifa_addr &&
        addr.ss_family == interface->ifa_addr->sa_family) {
      if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)interface->ifa_addr;
        struct sockaddr_in6 *b = (struct sockaddr_in6 *)&addr;
        if (memcmp(a->sin6_addr.s6_addr, b->sin6_addr.s6_addr, 16) == 0) {
          interface_index = if_nametoindex(interface->ifa_name);
          break;
        }
      }
#ifdef OC_IPV4
      else if (addr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)interface->ifa_addr;
        struct sockaddr_in *b = (struct sockaddr_in *)&addr;
        if (a->sin_addr.s_addr == b->sin_addr.s_addr) {
          interface_index = if_nametoindex(interface->ifa_name);
          break;
        }
      }
#endif /* OC_IPV4 */
    }
  }

  freeifaddrs(ifs);
  return interface_index;
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
free_tcp_session_async_locked(tcp_session_t *session)
{
  oc_list_remove(g_session_list, session);
  oc_list_add(g_free_session_list_async, session);

  signal_network_thread(session->dev);
  OC_DBG("signaled network event thread to monitor that the session need to be "
         "removed");
  OC_DBG("free TCP session async");
}

static void
free_tcp_session_locked(tcp_session_t *session)
{
  oc_list_remove(g_session_list, session);
  oc_list_remove(g_free_session_list_async, session);

  if (!oc_session_events_is_ongoing()) {
    oc_session_end_event(&session->endpoint);
  }

  ip_context_rfds_fd_clr(session->dev, session->sock);

  ssize_t len = 0;
  do {
    uint8_t dummy_value = 0xef;
    len = write(session->dev->tcp.connect_pipe[1], &dummy_value, 1);
  } while (len == -1 && errno == EINTR);

  close(session->sock);

  oc_memb_free(&g_tcp_session_s, session);

  OC_DBG("freed TCP session");
}

static void
process_free_tcp_session_locked()
{
  while (true) {
    tcp_session_t *session =
      (tcp_session_t *)oc_list_pop(g_free_session_list_async);
    if (session == NULL) {
      return;
    }
    free_tcp_session_locked(session);
  }
}

static tcp_session_t *
add_new_session_locked(int sock, ip_context_t *dev, oc_endpoint_t *endpoint,
                       tcp_csm_state_t state)
{
  tcp_session_t *session = oc_memb_alloc(&g_tcp_session_s);
  if (session == NULL) {
    OC_ERR("could not allocate new TCP session object");
    return NULL;
  }

  endpoint->interface_index = get_interface_index(sock);

  session->dev = dev;
  memcpy(&session->endpoint, endpoint, sizeof(oc_endpoint_t));
  session->endpoint.next = NULL;
  session->sock = sock;
  session->csm_state = state;

  oc_list_add(g_session_list, session);

  if ((endpoint->flags & SECURED) == 0) {
    oc_session_start_event(endpoint);
  }

  OC_DBG("recorded new TCP session");
  return session;
}

static int
accept_new_session_locked(ip_context_t *dev, int fd, fd_set *setfds,
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

  if (add_new_session_locked(new_socket, dev, endpoint, CSM_NONE) == NULL) {
    OC_ERR("could not record new TCP session");
    close(new_socket);
    return -1;
  }

  ip_context_rfds_fd_set(dev, new_socket);

  return 0;
}

static tcp_session_t *
get_ready_to_read_session_locked(fd_set *setfds)
{
  tcp_session_t *session = oc_list_head(g_session_list);
  while (session != NULL && !FD_ISSET(session->sock, setfds)) {
    session = session->next;
  }

  if (session == NULL) {
    OC_ERR("could not find any open ready-to-read session");
    return NULL;
  }
  return session;
}

static size_t
get_total_length_from_header(oc_message_t *message, oc_endpoint_t *endpoint)
{
  if ((endpoint->flags & SECURED) != 0) {
    //[3][4] bytes in tls header are tls payload length
    return TLS_HEADER_SIZE +
           (size_t)((message->data[3] << 8) | message->data[4]);
  }
  return coap_tcp_get_packet_size(message->data);
}

adapter_receive_state_t
oc_tcp_receive_message(ip_context_t *dev, fd_set *fds, oc_message_t *message)
{
  pthread_mutex_lock(&g_mutex);
  process_free_tcp_session_locked();
#define RET_WITH_CODE(status)                                                  \
  ret = status;                                                                \
  goto oc_tcp_receive_message_done

  adapter_receive_state_t ret = ADAPTER_STATUS_ERROR;
  message->endpoint.device = dev->device;

  if (FD_ISSET(dev->tcp.server_sock, fds)) {
    message->endpoint.flags = IPV6 | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.server_sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      RET_WITH_CODE(ADAPTER_STATUS_ERROR);
    }
    RET_WITH_CODE(ADAPTER_STATUS_ACCEPT);
  }
#ifdef OC_SECURITY
  if (FD_ISSET(dev->tcp.secure_sock, fds)) {
    message->endpoint.flags = IPV6 | SECURED | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.secure_sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      RET_WITH_CODE(ADAPTER_STATUS_ERROR);
    }
    RET_WITH_CODE(ADAPTER_STATUS_ACCEPT);
  }
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  if (FD_ISSET(dev->tcp.server4_sock, fds)) {
    message->endpoint.flags = IPV4 | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.server4_sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      RET_WITH_CODE(ADAPTER_STATUS_ERROR);
    }
    RET_WITH_CODE(ADAPTER_STATUS_ACCEPT);
  }
#ifdef OC_SECURITY
  if (FD_ISSET(dev->tcp.secure4_sock, fds)) {
    message->endpoint.flags = IPV4 | SECURED | TCP | ACCEPTED;
    if (accept_new_session_locked(dev, dev->tcp.secure4_sock, fds,
                                  &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      RET_WITH_CODE(ADAPTER_STATUS_ERROR);
    }
    RET_WITH_CODE(ADAPTER_STATUS_ACCEPT);
  }
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  if (FD_ISSET(dev->tcp.connect_pipe[0], fds)) {
    ssize_t len = read(dev->tcp.connect_pipe[0], message->data, OC_PDU_SIZE);
    if (len < 0) {
      OC_ERR("read error! %d", errno);
      RET_WITH_CODE(ADAPTER_STATUS_ERROR);
    }
    FD_CLR(dev->tcp.connect_pipe[0], fds);
    RET_WITH_CODE(ADAPTER_STATUS_NONE);
  }

  // find session.
  tcp_session_t *session = get_ready_to_read_session_locked(fds);
  if (session == NULL) {
    OC_DBG("could not find TCP session socket in fd set");
    RET_WITH_CODE(ADAPTER_STATUS_NONE);
  }

  // receive message.
  size_t total_length = 0;
  size_t want_read = DEFAULT_RECEIVE_SIZE;
  message->length = 0;
  do {
    int count =
      recv(session->sock, message->data + message->length, want_read, 0);
    if (count < 0) {
      OC_ERR("recv error! %d", errno);
      free_tcp_session_locked(session);
      RET_WITH_CODE(ADAPTER_STATUS_ERROR);
    }
    if (count == 0) {
      OC_DBG("peer closed TCP session\n");
      free_tcp_session_locked(session);
      RET_WITH_CODE(ADAPTER_STATUS_NONE);
    }

    OC_DBG("recv(): %d bytes.", count);
    message->length += (size_t)count;
    want_read -= (size_t)count;

    if (total_length == 0) {
      total_length = get_total_length_from_header(message, &session->endpoint);
      if (total_length >
          (unsigned)(OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE)) {
        OC_ERR("total receive length(%ld) is bigger than max pdu size(%ld)",
               total_length, (OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE));
        OC_ERR("It may occur buffer overflow.");
        RET_WITH_CODE(ADAPTER_STATUS_ERROR);
      }
      OC_DBG("tcp packet total length : %ld bytes.", total_length);

      want_read = total_length - (size_t)count;
    }
  } while (total_length > message->length);

  memcpy(&message->endpoint, &session->endpoint, sizeof(oc_endpoint_t));
#ifdef OC_SECURITY
  if ((message->endpoint.flags & SECURED) != 0) {
    message->encrypted = 1;
  }
#endif /* OC_SECURITY */

  FD_CLR(session->sock, fds);
  ret = ADAPTER_STATUS_RECEIVE;

oc_tcp_receive_message_done:
  pthread_mutex_unlock(&g_mutex);
#undef RET_WITH_CODE
  return ret;
}

static tcp_session_t *
find_session_by_endpoint_locked(const oc_endpoint_t *endpoint)
{
  tcp_session_t *session = oc_list_head(g_session_list);
  while (session != NULL &&
         oc_endpoint_compare(&session->endpoint, endpoint) != 0) {
    session = session->next;
  }

  if (session == NULL) {
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

void
oc_tcp_end_session(ip_context_t *dev, oc_endpoint_t *endpoint)
{
  (void)dev;
  pthread_mutex_lock(&g_mutex);
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (session != NULL) {
    free_tcp_session_async_locked(session);
  }
  pthread_mutex_unlock(&g_mutex);
}

static int
get_session_socket_locked(const oc_endpoint_t *endpoint)
{
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (session == NULL) {
    return -1;
  }
  return session->sock;
}

static int
connect_nonb(int sockfd, const struct sockaddr *r, int r_len, int nsec)
{
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return -1;
  }

  int n;
  if ((n = connect(sockfd, r, r_len)) < 0 && (errno != EINPROGRESS)) {
    return -1;
  }

  int error = 0;
  socklen_t len;
  fd_set wset;
  struct timeval tval;
  /* Do whatever we want while the connect is taking place. */
  if (n == 0) {
    goto done; /* connect completed immediately */
  }

  FD_ZERO(&wset);
  FD_SET(sockfd, &wset);
  tval.tv_sec = nsec;
  tval.tv_usec = 0;

  if (select(sockfd + 1, NULL, &wset, NULL, nsec ? &tval : NULL) == 0) {
    /* timeout */
    errno = ETIMEDOUT;
    return -1;
  }

  if (!FD_ISSET(sockfd, &wset)) {
    OC_DBG("select error: sockfd not set");
    return -1;
  }
  len = sizeof(error);
  if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
    return -1; /* Solaris pending error */
  }

done:
  if (error < 0) {
    close(sockfd); /* just in case */
    errno = error;
    return -1;
  }
  error = fcntl(sockfd, F_SETFL, flags); /* restore file status flags */
  if (error < 0) {
    return -1;
  }
  return 0;
}

static void
signal_network_thread(const ip_context_t *dev)
{
  ssize_t len = 0;
  do {
    uint8_t dummy_value = 0xef;
    len = write(dev->tcp.connect_pipe[1], &dummy_value, 1);
  } while (len == -1 && errno == EINTR);
}

static int
initiate_new_session_locked(ip_context_t *dev, oc_endpoint_t *endpoint,
                            const struct sockaddr_storage *receiver)
{
  int sock = -1;
  uint8_t retry_cnt = 0;

  while (retry_cnt < LIMIT_RETRY_CONNECT) {
    if (endpoint->flags & IPV6) {
      sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#ifdef OC_IPV4
    } else if (endpoint->flags & IPV4) {
      sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
    }

    if (sock < 0) {
      OC_ERR("could not create socket for new TCP session");
      return -1;
    }

    socklen_t receiver_size = sizeof(*receiver);
    int ret;
    if ((ret = connect_nonb(sock, (const struct sockaddr *)receiver,
                            receiver_size, TCP_CONNECT_TIMEOUT)) == 0) {
      break;
    }

    close(sock);
    retry_cnt++;
    OC_DBG("connect fail with %d. retry(%d)", ret, retry_cnt);
    (void)ret;
  }

  if (retry_cnt >= LIMIT_RETRY_CONNECT) {
    OC_ERR("could not initiate TCP connection");
    return -1;
  }

  OC_DBG("successfully initiated TCP connection");

  if (add_new_session_locked(sock, dev, endpoint, CSM_SENT) == NULL) {
    OC_ERR("could not record new TCP session");
    close(sock);
    return -1;
  }

  ip_context_rfds_fd_set(dev, sock);

  signal_network_thread(dev);
  OC_DBG("signaled network event thread to monitor the newly added session");

  return sock;
}

int
oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                   const struct sockaddr_storage *receiver)
{
  pthread_mutex_lock(&g_mutex);
  int send_sock = get_session_socket_locked(&message->endpoint);

  size_t bytes_sent = 0;
  if (send_sock < 0) {
    if ((message->endpoint.flags & ACCEPTED) != 0) {
      OC_ERR("connection was closed");
      goto oc_tcp_send_buffer_done;
    }
    if (initiate_new_session_locked(dev, &message->endpoint, receiver) < 0) {
      OC_ERR("could not initiate new TCP session");
      goto oc_tcp_send_buffer_done;
    }
  }

  send_sock = get_session_socket_locked(&message->endpoint);
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
  pthread_mutex_unlock(&g_mutex);

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
}

int
tcp_create_socket(int domain, struct sockaddr_storage *sock_info)
{
  int sock = socket(domain, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    OC_ERR("failed to create TCP socket");
    return -1;
  }

  if (configure_tcp_socket(sock, sock_info) < 0) {
    OC_ERR("set socket option in socket");
    return -1;
  }

  if (get_assigned_tcp_port(sock, sock_info) < 0) {
    OC_ERR("get port for socket");
    return -1;
  }
  return sock;
}

#ifdef OC_IPV4
static void
tcp_ipv4_addr_init(struct sockaddr_storage *addr)
{
  memset(addr, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *l = (struct sockaddr_in *)addr;
  l->sin_family = AF_INET;
  l->sin_addr.s_addr = INADDR_ANY;
  l->sin_port = 0;
}

static int
tcp_connectivity_ipv4_init(ip_context_t *dev)
{
  OC_DBG("Initializing TCP adapter IPv4 for device %zd", dev->device);

  tcp_ipv4_addr_init(&dev->tcp.server4);
#ifdef OC_SECURITY
  tcp_ipv4_addr_init(&dev->tcp.secure4);
#endif /* OC_SECURITY */

  dev->tcp.server4_sock = tcp_create_socket(AF_INET, &dev->tcp.server4);
  if (dev->tcp.server4_sock < 0) {
    OC_ERR("failed to create TCP IPv4 server socket");
    return -1;
  }
  dev->tcp.port4 = ntohs(((struct sockaddr_in *)&dev->tcp.server4)->sin_port);

#ifdef OC_SECURITY
  dev->tcp.secure4_sock = tcp_create_socket(AF_INET, &dev->tcp.secure4);
  if (dev->tcp.secure4_sock < 0) {
    OC_ERR("failed to create TCP IPv4 secure socket");
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

static void
tcp_addr_init(struct sockaddr_storage *addr)
{
  memset(addr, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *l = (struct sockaddr_in6 *)addr;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;
}

int
oc_tcp_connectivity_init(ip_context_t *dev)
{
  OC_DBG("Initializing TCP adapter for device %zd", dev->device);

  tcp_addr_init(&dev->tcp.server);
#ifdef OC_SECURITY
  tcp_addr_init(&dev->tcp.secure);
#endif /* OC_SECURITY */

  dev->tcp.server_sock = tcp_create_socket(AF_INET6, &dev->tcp.server);
  if (dev->tcp.server_sock < 0) {
    OC_ERR("failed to create TCP IPv6 server socket");
    return -1;
  }
  dev->tcp.port = ntohs(((struct sockaddr_in *)&dev->tcp.server)->sin_port);

#ifdef OC_SECURITY
  dev->tcp.secure_sock = tcp_create_socket(AF_INET6, &dev->tcp.secure);
  if (dev->tcp.secure_sock < 0) {
    OC_ERR("failed to create TCP IPv6 secure socket");
    return -1;
  }
  dev->tcp.tls_port = ntohs(((struct sockaddr_in *)&dev->tcp.secure)->sin_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (tcp_connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4 for TCP");
  }
#endif /* OC_IPV4 */

  if (pipe(dev->tcp.connect_pipe) < 0) {
    OC_ERR("Could not initialize connection pipe");
    return -1;
  }
  if (set_nonblock_socket(dev->tcp.connect_pipe[0]) < 0) {
    OC_ERR("Could not set non-block connect_pipe[0]");
    return -1;
  }

  OC_DBG("=======tcp port info.========");
  OC_DBG("  ipv6 port   : %u", dev->tcp.port);
#ifdef OC_SECURITY
  OC_DBG("  ipv6 secure : %u", dev->tcp.tls_port);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  OC_DBG("  ipv4 port   : %u", dev->tcp.port4);
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %u", dev->tcp.tls4_port);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */

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

  pthread_mutex_lock(&g_mutex);
  tcp_session_t *session = (tcp_session_t *)oc_list_head(g_session_list), *next;
  while (session != NULL) {
    next = session->next;
    if (session->endpoint.device == dev->device) {
      free_tcp_session_locked(session);
    }
    session = next;
  }
  process_free_tcp_session_locked();
  pthread_mutex_unlock(&g_mutex);

  OC_DBG("oc_tcp_connectivity_shutdown for device %zd", dev->device);
}

tcp_csm_state_t
oc_tcp_get_csm_state(oc_endpoint_t *endpoint)
{
  if (endpoint == NULL) {
    return CSM_ERROR;
  }

  pthread_mutex_lock(&g_mutex);
  tcp_session_t *session = find_session_by_endpoint_locked(endpoint);
  if (session == NULL) {
    pthread_mutex_unlock(&g_mutex);
    return CSM_NONE;
  }

  tcp_csm_state_t csm_state = session->csm_state;
  pthread_mutex_unlock(&g_mutex);
  return csm_state;
}

int
oc_tcp_update_csm_state(oc_endpoint_t *endpoint, tcp_csm_state_t csm)
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
#endif /* OC_TCP */
