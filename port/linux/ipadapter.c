/*
// Copyright (c) 2016 Intel Corporation
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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "oc_buffer.h"
#include "port/oc_connectivity.h"

#define OCF_PORT_UNSECURED (5683)
#define ALL_OCF_NODES "FF02::158"

static pthread_t event_thread;
static pthread_mutex_t mutex;

static struct sockaddr_storage mcast, server, client;
static int server_sock = -1, mcast_sock = -1, terminate;

#ifdef OC_SECURITY
static struct sockaddr_storage secure;
static int secure_sock = -1;
static uint16_t dtls_port = 0;

uint16_t
oc_connectivity_get_dtls_port(void)
{
  return dtls_port;
}
#endif /* OC_SECURITY */

void
oc_network_event_handler_mutex_init(void)
{
  if (pthread_mutex_init(&mutex, NULL) != 0) {
    LOG("ERROR initializing network event handler mutex\n");
  }
}

void
oc_network_event_handler_mutex_lock(void)
{
  pthread_mutex_lock(&mutex);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  pthread_mutex_unlock(&mutex);
}

static void *
network_event_thread(void *data)
{
  struct sockaddr_in6 *c = (struct sockaddr_in6 *)&client;
  socklen_t len = sizeof(client);

  fd_set rfds, setfds;

  FD_ZERO(&rfds);
  FD_SET(server_sock, &rfds);
  FD_SET(mcast_sock, &rfds);

#ifdef OC_SECURITY
  FD_SET(secure_sock, &rfds);
#endif

  int i, n;

  while (!terminate) {
    setfds = rfds;
    n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

    for (i = 0; i < n; i++) {
      oc_message_t *message = oc_allocate_message();

      if (!message) {
        break;
      }

      if (FD_ISSET(server_sock, &setfds)) {
        message->length = recvfrom(server_sock, message->data, MAX_PAYLOAD_SIZE,
                                   0, (struct sockaddr *)&client, &len);
        message->endpoint.flags = IP;
        FD_CLR(server_sock, &setfds);
        goto common;
      }

      if (FD_ISSET(mcast_sock, &setfds)) {
        message->length = recvfrom(mcast_sock, message->data, MAX_PAYLOAD_SIZE,
                                   0, (struct sockaddr *)&client, &len);
        message->endpoint.flags = IP;
        FD_CLR(mcast_sock, &setfds);
        goto common;
      }

#ifdef OC_SECURITY
      if (FD_ISSET(secure_sock, &setfds)) {
        message->length = recvfrom(secure_sock, message->data, MAX_PAYLOAD_SIZE,
                                   0, (struct sockaddr *)&client, &len);
        message->endpoint.flags = IP | SECURED;
      }
#endif /* OC_SECURITY */

    common:
      memcpy(message->endpoint.ipv6_addr.address, c->sin6_addr.s6_addr,
             sizeof(c->sin6_addr.s6_addr));
      message->endpoint.ipv6_addr.scope = c->sin6_scope_id;
      message->endpoint.ipv6_addr.port = ntohs(c->sin6_port);

      PRINT("Incoming message from ");
      PRINTipaddr(message->endpoint);
      PRINT("\n");

      oc_network_event(message);
    }
  }

  pthread_exit(NULL);
}

void
oc_send_buffer(oc_message_t *message)
{
  PRINT("Outgoing message to ");
  PRINTipaddr(message->endpoint);
  PRINT("\n");

  struct sockaddr_storage receiver;
  struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receiver;
  memcpy(r->sin6_addr.s6_addr, message->endpoint.ipv6_addr.address,
         sizeof(r->sin6_addr.s6_addr));
  r->sin6_family = AF_INET6;
  r->sin6_port = htons(message->endpoint.ipv6_addr.port);
  r->sin6_scope_id = message->endpoint.ipv6_addr.scope;
  int send_sock = -1;

#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED)
    send_sock = secure_sock;
  else
#endif /* OC_SECURITY */
    send_sock = server_sock;

  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(send_sock, &wfds);

  int n = select(FD_SETSIZE, NULL, &wfds, NULL, NULL);
  if (n > 0) {
    int bytes_sent = 0, x;
    while (bytes_sent < message->length) {
      x = sendto(send_sock, message->data + bytes_sent,
                 message->length - bytes_sent, 0, (struct sockaddr *)&receiver,
                 sizeof(receiver));
      bytes_sent += x;
    }
    PRINT("Sent %d bytes\n", bytes_sent);
  }
}

#ifdef OC_CLIENT
void
oc_send_multicast_message(oc_message_t *message)
{
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    LOG("error querying interfaces: %d\n", errno);
    goto done;
  }
  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    if (!interface->ifa_flags & IFF_UP || interface->ifa_flags & IFF_LOOPBACK)
      continue;
    if (interface->ifa_addr && interface->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)interface->ifa_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        int mif = addr->sin6_scope_id;
        if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mif,
                       sizeof(mif)) == -1) {
          LOG("ERROR setting socket option for default IPV6_MULTICAST_IF: %d\n",
              errno);
          goto done;
        }
        oc_send_buffer(message);
      }
    }
  }
done:
  freeifaddrs(ifs);
}
#endif /* OC_CLIENT */

int
oc_connectivity_init(void)
{
  memset(&mcast, 0, sizeof(struct sockaddr_storage));
  memset(&server, 0, sizeof(struct sockaddr_storage));

  struct sockaddr_in6 *m = (struct sockaddr_in6 *)&mcast;
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(OCF_PORT_UNSECURED);
  m->sin6_addr = in6addr_any;

  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;

#ifdef OC_SECURITY
  memset(&secure, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_port = 0;
  sm->sin6_addr = in6addr_any;
#endif /* OC_SECURITY */

  server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  if (server_sock < 0 || mcast_sock < 0) {
    LOG("ERROR creating server sockets\n");
    return -1;
  }

#ifdef OC_SECURITY
  secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (secure_sock < 0) {
    LOG("ERROR creating secure socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) == -1) {
    LOG("ERROR binding server socket %d\n", errno);
    return -1;
  }

  struct ipv6_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  if (inet_pton(AF_INET6, ALL_OCF_NODES, (void *)&mreq.ipv6mr_multiaddr) != 1) {
    LOG("ERROR setting mcast addr\n");
    return -1;
  }
  mreq.ipv6mr_interface = 0;
  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    LOG("ERROR setting mcast join option %d\n", errno);
    return -1;
  }
  int reuse = 1;
  if (setsockopt(mcast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ==
      -1) {
    LOG("ERROR setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(mcast_sock, (struct sockaddr *)&mcast, sizeof(mcast)) == -1) {
    LOG("ERROR binding mcast socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(secure_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    LOG("ERROR setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(secure_sock, (struct sockaddr *)&secure, sizeof(secure)) == -1) {
    LOG("ERROR binding smcast socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(secure);
  if (getsockname(secure_sock, (struct sockaddr *)&secure, &socklen) == -1) {
    LOG("ERROR obtaining secure socket information %d\n", errno);
    return -1;
  }

  dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */

  if (pthread_create(&event_thread, NULL, &network_event_thread, NULL) != 0) {
    LOG("ERROR creating network polling thread\n");
    return -1;
  }

  LOG("Successfully initialized connectivity\n");

  return 0;
}

void
oc_connectivity_shutdown(void)
{
  terminate = 1;

  close(server_sock);
  close(mcast_sock);

#ifdef OC_SECURITY
  close(secure_sock);
#endif /* OC_SECURITY */

  pthread_cancel(event_thread);

  LOG("oc_connectivity_shutdown\n");
}
