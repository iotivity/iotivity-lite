/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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

#include "netsocket.h"

#include "port/oc_log_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#ifdef OC_IPV4
#define ALL_COAP_NODES_V4 (0xe00001bb)
#endif /* OC_IPV4 */

static const uint8_t ALL_OCF_NODES_LL[] = {
  0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
static const uint8_t ALL_OCF_NODES_RL[] = {
  0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
static const uint8_t ALL_OCF_NODES_SL[] = {
  0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};

#ifdef OC_WKCORE
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
#endif /* OC_WKCORE */

#ifdef OC_IPV4
bool
oc_netsocket_add_sock_to_ipv4_mcast_group(int sock, const struct in_addr *local,
                                          int interface_index)
{
  assert(sock != -1);
  struct ip_mreqn mreq;
  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
  mreq.imr_ifindex = interface_index;
  memcpy(&mreq.imr_address, local, sizeof(struct in_addr));

  (void)setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

  if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ==
      -1) {
    OC_ERR("failed joining IPv4 multicast group: %d", (int)errno);
    return false;
  }
  return true;
}
#endif /* OC_IPV4 */

static bool
netsocket_add_sock_to_ipv6_mcast_group(int sock, int interface_index,
                                       const uint8_t addr[], size_t addr_size)
{
  assert(addr_size == 16);
  struct ipv6_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, addr, addr_size);
  mreq.ipv6mr_interface = interface_index;

  (void)setsockopt(sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("failed joining IPv6 multicast group: %d", (int)errno);
    return false;
  }
  return true;
}

bool
oc_netsocket_add_sock_to_ipv6_mcast_group(int sock, int interface_index)
{
  assert(sock != -1);
  /* Link-local scope */
  if (!netsocket_add_sock_to_ipv6_mcast_group(
        sock, interface_index, ALL_OCF_NODES_LL,
        OC_ARRAY_SIZE(ALL_OCF_NODES_LL))) {
    OC_ERR("failed joining link-local IPv6 multicast group: %d", (int)errno);
    return false;
  }

  /* Realm-local scope */
  if (!netsocket_add_sock_to_ipv6_mcast_group(
        sock, interface_index, ALL_OCF_NODES_RL,
        OC_ARRAY_SIZE(ALL_OCF_NODES_RL))) {
    OC_ERR("failed joining realm-local IPv6 multicast group: %d", (int)errno);
    return false;
  }

  /* Site-local scope */
  if (!netsocket_add_sock_to_ipv6_mcast_group(
        sock, interface_index, ALL_OCF_NODES_SL,
        OC_ARRAY_SIZE(ALL_OCF_NODES_SL))) {
    OC_ERR("failed joining site-local IPv6 multicast group: %d", (int)errno);
    return false;
  }

#ifdef OC_WKCORE
  OC_DBG("Adding all CoAP Nodes");
  /* Link-local scope ALL COAP nodes  */
  if (!netsocket_add_sock_to_ipv6_mcast_group(
        sock, interface_index, ALL_COAP_NODES_LL,
        OC_ARRAY_SIZE(ALL_COAP_NODES_LL))) {
    OC_ERR("failed joining link-local CoAP IPv6 multicast group: %d",
           (int)errno);
    return false;
  }

  /* Realm-local scope ALL COAP nodes  */
  if (!netsocket_add_sock_to_ipv6_mcast_group(
        sock, interface_index, ALL_COAP_NODES_RL,
        OC_ARRAY_SIZE(ALL_COAP_NODES_RL))) {
    OC_ERR("failed joining realm-local CoAP IPv6 multicast group: %d",
           (int)errno);
    return false;
  }

  /* Site-local scope ALL COAP nodes */
  if (!netsocket_add_sock_to_ipv6_mcast_group(
        sock, interface_index, ALL_COAP_NODES_SL,
        OC_ARRAY_SIZE(ALL_COAP_NODES_SL))) {
    OC_ERR("failed joining site-local CoAP IPv6 multicast group: %d",
           (int)errno);
    return false;
  }
#endif /* OC_WKCORE */
  return true;
}

static bool
netsocket_configure_mcast(int mcast_sock, int sa_family)
{
  assert(mcast_sock != -1);

  struct ifaddrs *ifs = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR(
      "cannot configure multicast socket: failed querying interface addrs: %d",
      (int)errno);
    return false;
  }
  for (struct ifaddrs *interface = ifs; interface != NULL;
       interface = interface->ifa_next) {
    /* Ignore interfaces that are down and the loopback interface */
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }
    /* Ignore interfaces not belonging to the address family under consideration
     */
    if (interface->ifa_addr && interface->ifa_addr->sa_family != sa_family) {
      continue;
    }
    /* Obtain interface index for this address */
    int if_index = if_nametoindex(interface->ifa_name);
    /* Accordingly handle IPv6/IPv4 addresses */
    if (sa_family == AF_INET6) {
      CLANG_IGNORE_WARNING_START
      CLANG_IGNORE_WARNING("-Wcast-align")
      const struct sockaddr_in6 *addr =
        (struct sockaddr_in6 *)interface->ifa_addr;
      CLANG_IGNORE_WARNING_END
      if (addr == NULL || !IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        continue;
      }
      if (!oc_netsocket_add_sock_to_ipv6_mcast_group(mcast_sock, if_index)) {
        return false;
      }
      continue;
    }
#ifdef OC_IPV4
    if (sa_family == AF_INET) {
      CLANG_IGNORE_WARNING_START
      CLANG_IGNORE_WARNING("-Wcast-align")
      const struct sockaddr_in *addr =
        (struct sockaddr_in *)interface->ifa_addr;
      CLANG_IGNORE_WARNING_END
      if (addr == NULL) {
        continue;
      }
      if (!oc_netsocket_add_sock_to_ipv4_mcast_group(
            mcast_sock, &addr->sin_addr, if_index)) {
        return false;
      }
      continue;
    }
#endif /* OC_IPV4 */
  }
  freeifaddrs(ifs);
  return true;
}

static int
netsocket_create_ipv6(uint16_t port, bool multicast)
{

  struct sockaddr_storage sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&sockaddr;
  sa->sin6_family = AF_INET6;
  sa->sin6_addr = in6addr_any;
  sa->sin6_port = htons(port);
  int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    OC_ERR("failed creating IPv6 datagram socket: %d", (int)errno);
    return -1;
  }

  if (multicast) {
    if (!netsocket_configure_mcast(sock, AF_INET6)) {
      goto error;
    }
    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
      OC_ERR("failed setting reuseaddr option: %d", (int)errno);
      goto error;
    }
  }

  int on = 1;
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == -1) {
    OC_ERR("failed setting recvpktinfo option: %d", (int)errno);
    goto error;
  }
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1) {
    OC_ERR("failed setting sock option: %d", (int)errno);
    goto error;
  }
#ifdef IPV6_ADDR_PREFERENCES
  int prefer = 2;
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, &prefer,
                 sizeof(prefer)) == -1) {
    OC_ERR("failed setting src addr preference: %d", (int)errno);
    goto error;
  }
#endif /* IPV6_ADDR_PREFERENCES */

  if (bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
    OC_ERR("failed binding IPv6 socket %d", (int)errno);
    goto error;
  }
  return sock;

error:
  close(sock);
  return -1;
}

int
oc_netsocket_create_ipv6(uint16_t port)
{
  return netsocket_create_ipv6(port, false);
}

int
oc_netsocket_create_mcast_ipv6(uint16_t port)
{
  return netsocket_create_ipv6(port, true);
}

#ifdef OC_IPV4

static int
netsocket_create_ipv4(uint16_t port, bool multicast)
{
  struct sockaddr_storage sockaddr;
  memset(&sockaddr, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *sa = (struct sockaddr_in *)&sockaddr;
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = INADDR_ANY;
  sa->sin_port = htons(port);
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    OC_ERR("failed creating IPv4 datagram socket: %d", (int)errno);
    return -1;
  }

  if (multicast) {
    if (!netsocket_configure_mcast(sock, AF_INET)) {
      goto error;
    }
    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
      OC_ERR("failed setting reuseaddr IPv4 option: %d", (int)errno);
      goto error;
    }
  }

  int on = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == -1) {
    OC_ERR("failed setting pktinfo IPv4 option: %d", (int)errno);
    goto error;
  }
  if (bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
    OC_ERR("failed binding IPv4 socket: %d", (int)errno);
    goto error;
  }
  return sock;

error:
  close(sock);
  return -1;
}

int
oc_netsocket_create_ipv4(uint16_t port)
{
  return netsocket_create_ipv4(port, false);
}

int
oc_netsocket_create_mcast_ipv4(uint16_t port)
{
  return netsocket_create_ipv4(port, true);
}

#endif /* OC_IPV4 */
