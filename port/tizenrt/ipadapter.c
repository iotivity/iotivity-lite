/*
// Copyright (c) 2018 Samsung Electronics France SAS
// Copyright (c) 2018 Intel Corporation
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

#include "ipcontext.h"
#ifdef OC_TCP
#include "tcpadapter.h"
#endif
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
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
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* Some outdated toolchains do not define IFA_FLAGS.
   Note: Requires Linux kernel 3.14 or later. */
#ifndef IFA_FLAGS
#define IFA_FLAGS (IFA_MULTICAST+1)
#endif

#define OCF_PORT_UNSECURED (5683)
static const uint8_t ALL_OCF_NODES_LL[] = {
  0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
static const uint8_t ALL_OCF_NODES_RL[] = {
  0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
static const uint8_t ALL_OCF_NODES_SL[] = {
  0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
#define ALL_COAP_NODES_V4 0xe00001bb

static pthread_mutex_t mutex;

#ifdef OC_NETLINK
struct sockaddr_nl ifchange_nl;
int ifchange_sock;
bool ifchange_initialized;
#endif
#ifdef OC_DYNAMIC_ALLOCATION
OC_LIST(ip_contexts);
#else /* OC_DYNAMIC_ALLOCATION */
static ip_context_t devices[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_network_event_handler_mutex_init(void)
{
  if (pthread_mutex_init(&mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex\n");
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

void oc_network_event_handler_mutex_destroy(void) {
#ifdef OC_NETLINK
  close(ifchange_sock);
#endif
  pthread_mutex_destroy(&mutex);
}

static ip_context_t *get_ip_context_for_device(int device) {
#ifdef OC_DYNAMIC_ALLOCATION
  ip_context_t *dev = oc_list_head(ip_contexts);
  while (dev != NULL && dev->device != device) {
    dev = dev->next;
  }
  if (!dev) {
    return NULL;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  ip_context_t *dev = &devices[device];
#endif /* !OC_DYNAMIC_ALLOCATION */
  return dev;
}

#ifdef OC_IPV4
static int add_mcast_sock_to_ipv4_mcast_group(int mcast_sock,
                                              const struct in_addr *local,
                                              int interface_index) {
  struct ip_mreqn mreq;

  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
  mreq.imr_ifindex = interface_index;
  memcpy(&mreq.imr_address, local, sizeof(struct in_addr));

  (void)setsockopt(mcast_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining IPv4 multicast group %d\n", errno);
    return -1;
  }

  return 0;
}
#endif /* OC_IPV4 */

#ifdef OC_IPV6
static int add_mcast_sock_to_ipv6_mcast_group(int mcast_sock,
                                              int interface_index) {
  struct ipv6_mreq mreq;

  /* Link-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_LL, 16);
  mreq.ipv6mr_interface = interface_index;

  (void)setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining link-local IPv6 multicast group %d\n", errno);
    return -1;
  }

  /* Realm-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_RL, 16);
  mreq.ipv6mr_interface = interface_index;

  (void)setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining realm-local IPv6 multicast group %d\n", errno);
    return -1;
  }

  /* Site-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_SL, 16);
  mreq.ipv6mr_interface = interface_index;

  (void)setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining site-local IPv6 multicast group %d\n", errno);
    return -1;
  }

  return 0;
}
#endif

static int configure_mcast_socket(int mcast_sock, int sa_family) {
  int ret = 0;
  struct ifaddrs *ifs = NULL, *interface = NULL;
#ifdef TODO_IS_DONE
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interface addrs\n");
    return -1;
  }
#endif
  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    /* Ignore interfaces that are down and the loopback interface */
    if ((!interface->ifa_flags) & IFF_UP || interface->ifa_flags & IFF_LOOPBACK) {
      OC_ERR("add_mcast_sock_to_ipv4_mcast_group skip for %s\n", interface->ifa_name );
      continue;
    }
    /* Ignore interfaces not belonging to the address family under consideration
     */
    if (interface->ifa_addr->sa_family != sa_family) {
      continue;
    }

    OC_ERR("add_mcast_sock_to_ipv4_mcast_group for %s\n", interface->ifa_name );

    /* Obtain interface index for this address */
    int if_index = if_nametoindex(interface->ifa_name);
    /* Accordingly handle IPv6/IPv4 addresses */
#ifdef OC_IPV6
    if (sa_family == AF_INET6) {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *)interface->ifa_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)) {
        ret += add_mcast_sock_to_ipv6_mcast_group(mcast_sock, if_index);
      }
    }
#endif
#ifdef OC_IPV4
#ifdef OC_IPV6
    else if (sa_family == AF_INET)
#else
    if (sa_family == AF_INET)
#endif
    {
      struct sockaddr_in *a = (struct sockaddr_in *)interface->ifa_addr;
      ret += add_mcast_sock_to_ipv4_mcast_group(mcast_sock, &a->sin_addr,
                                                if_index);
    }
#endif /* OC_IPV4 */
  }
  return ret;
}

#ifdef OC_NETLINK
/* Called after network interface up/down events.
 * This function reconfigures IPv6/v4 multicast sockets for
 * all logical devices.
 */
static int process_interface_change_event(void) {
  int ret = 0, i, num_devices = oc_core_get_num_devices();
  struct nlmsghdr *response = NULL;

  int guess = 512, response_len;
  do {
    guess <<= 1;
    uint8_t dummy[guess];
    response_len = recv(ifchange_sock, dummy, guess, MSG_PEEK);
    if (response_len < 0) {
      OC_ERR("reading payload size from netlink interface\n");
      return -1;
    }
  } while (response_len == guess);

  uint8_t buffer[response_len];
  response_len = recv(ifchange_sock, buffer, response_len, 0);
  if (response_len < 0) {
    OC_ERR("reading payload from netlink interface\n");
    return -1;
  }

  response = (struct nlmsghdr *)buffer;
  if (response->nlmsg_type == NLMSG_ERROR) {
    OC_ERR("caught NLMSG_ERROR in payload from netlink interface\n");
    return -1;
  }

  while (NLMSG_OK(response, response_len)) {
    if (response->nlmsg_type == RTM_NEWADDR) {
      struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (ifa) {
        struct rtattr *attr = (struct rtattr *)IFA_RTA(ifa);
        int att_len = IFA_PAYLOAD(response);
        while (RTA_OK(attr, att_len)) {
          if (attr->rta_type == IFA_ADDRESS) {
#ifdef OC_IPV4
            if (ifa->ifa_family == AF_INET) {
              for (i = 0; i < num_devices; i++) {
                ip_context_t *dev = get_ip_context_for_device(i);
                ret += add_mcast_sock_to_ipv4_mcast_group(
                    dev->mcast4_sock, RTA_DATA(attr), ifa->ifa_index);
              }
            }
#endif /* OC_IPV4 */
#ifdef OC_IPV6
                if (ifa->ifa_family == AF_INET6 &&
                    ifa->ifa_scope == RT_SCOPE_LINK) {
              for (i = 0; i < num_devices; i++) {
                ip_context_t *dev = get_ip_context_for_device(i);
                ret += add_mcast_sock_to_ipv6_mcast_group(dev->mcast_sock,
                                                          ifa->ifa_index);
              }
            }
#endif
          }
          attr = RTA_NEXT(attr, att_len);
        }
      }
    }
    response = NLMSG_NEXT(response, response_len);
  }

  return ret;
}

#endif

static void *network_event_thread(void *data) {
  struct sockaddr_storage client;
  memset(&client, 0, sizeof(struct sockaddr_storage));
#ifdef OC_IPV6
  struct sockaddr_in6 *c = (struct sockaddr_in6 *)&client;
#endif
  socklen_t len = sizeof(client);

#ifdef OC_IPV4
  struct sockaddr_in *c4 = (struct sockaddr_in *)&client;
#endif

  ip_context_t *dev = (ip_context_t *)data;

  fd_set rfds, setfds;
  FD_ZERO(&rfds);

#ifdef OC_NETLINK
  /* Monitor network interface changes on the platform from only the 0th logical
   * device
   */
  if (dev->device == 0) {
    FD_SET(ifchange_sock, &rfds);
  }
#endif

#ifdef OC_IPV6
  FD_SET(dev->server_sock, &rfds);
  FD_SET(dev->mcast_sock, &rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure_sock, &rfds);
#endif /* OC_SECURITY */
#endif /* OC_IPV6 */

#ifdef OC_IPV4
  FD_SET(dev->server4_sock, &rfds);
  FD_SET(dev->mcast4_sock, &rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure4_sock, &rfds);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */

  int i, n;

  while (dev->terminate != 1) {
    len = sizeof(client);
    setfds = rfds;
    n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

    for (i = 0; i < n; i++) {
#ifdef OC_NETLINK
      if (dev->device == 0) {
        if (FD_ISSET(ifchange_sock, &setfds)) {
          if (process_interface_change_event() < 0) {
            OC_WRN("caught errors while handling a network interface change\n");
          }
          FD_CLR(ifchange_sock, &setfds);
          continue;
        }
      }
#endif

      len = sizeof(client);
      oc_message_t *message = oc_allocate_message();

      if (!message) {
        break;
      }

#ifdef OC_IPV6
      if (FD_ISSET(dev->server_sock, &setfds)) {
        int count = recvfrom(dev->server_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6;
        message->endpoint.device = dev->device;
        FD_CLR(dev->server_sock, &setfds);
        goto common;
      }

      if (FD_ISSET(dev->mcast_sock, &setfds)) {
        int count = recvfrom(dev->mcast_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6 | MULTICAST;
        message->endpoint.device = dev->device;
        FD_CLR(dev->mcast_sock, &setfds);
        goto common;
      }
#endif

#ifdef OC_IPV4
      if (FD_ISSET(dev->server4_sock, &setfds)) {
        int count = recvfrom(dev->server4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV4;
        message->endpoint.device = dev->device;
        FD_CLR(dev->server4_sock, &setfds);
        goto common;
      }

      if (FD_ISSET(dev->mcast4_sock, &setfds)) {
        int count = recvfrom(dev->mcast4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV4 | MULTICAST;
        message->endpoint.device = dev->device;
        FD_CLR(dev->mcast4_sock, &setfds);
        goto common;
      }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
#ifdef OC_IPV6
      if (FD_ISSET(dev->secure_sock, &setfds)) {
        int count = recvfrom(dev->secure_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6 | SECURED;
        message->endpoint.device = dev->device;
        FD_CLR(dev->secure_sock, &setfds);
      }
#endif
#ifdef OC_IPV4
      if (FD_ISSET(dev->secure4_sock, &setfds)) {
        int count = recvfrom(dev->secure4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV4 | SECURED;
        message->endpoint.device = dev->device;
        FD_CLR(dev->secure4_sock, &setfds);
      }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */
    common:
#ifdef OC_IPV4
      if (message->endpoint.flags & IPV4) {
        memcpy(message->endpoint.addr.ipv4.address, &c4->sin_addr.s_addr,
               sizeof(c4->sin_addr.s_addr));
        message->endpoint.addr.ipv4.port = ntohs(c4->sin_port);
      }
#endif /* !OC_IPV4 */
#ifdef OC_IPV6
      if (message->endpoint.flags & IPV6) {
        memcpy(message->endpoint.addr.ipv6.address, c->sin6_addr.s6_addr,
               sizeof(c->sin6_addr.s6_addr));
        message->endpoint.addr.ipv6.scope = c->sin6_scope_id;
        message->endpoint.addr.ipv6.port = ntohs(c->sin6_port);
      }
#endif
#ifdef OC_DEBUG
      PRINT("Incoming message of size %d bytes from ", message->length);
      PRINTipaddr(message->endpoint);
      PRINT("\n\n");
#endif /* OC_DEBUG */

      oc_network_event(message);
    }
  }
  pthread_exit(NULL);
}

static void
get_interface_addresses(unsigned char family, uint16_t port, bool secure)
{
   struct sockaddr_in addr;
   oc_endpoint_t ep;
   OC_DBG("get_interface_addresses : in");
   memset(&ep, 0, sizeof(oc_endpoint_t));

   OC_DBG("get_interface_addresses ");

   ep.addr.ipv4.port = port;
   ep.flags = IPV4 | SECURED;

   netlib_get_ipv4addr("en1", &addr.sin_addr);
  memcpy(ep.addr.ipv4.address, &addr.sin_addr.s_addr,
          sizeof(addr.sin_addr.s_addr));

   if (oc_add_endpoint_to_list(&ep) == -1)
   {

   }
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  OC_DBG("oc_connectivity_get_endpoints : in");
  oc_init_endpoint_list();
  ip_context_t *dev = get_ip_context_for_device(device);
#ifdef OC_IPV6
  get_interface_addresses(AF_INET6, dev->port, false);
#ifdef OC_SECURITY
  get_interface_addresses(AF_INET6, dev->dtls_port, true);
#endif /* OC_SECURITY */
#endif

#ifdef OC_IPV4
  get_interface_addresses(AF_INET, dev->port4, false);
#ifdef OC_SECURITY
  get_interface_addresses(AF_INET, dev->dtls4_port, true);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  return oc_get_endpoint_list();
}

void oc_send_buffer(oc_message_t *message) {
#ifdef OC_DEBUG
  PRINT("Outgoing message of size %d bytes to ", message->length);
  PRINTipaddr(message->endpoint);
  PRINT("\n\n");
#endif /* OC_DEBUG */

  struct sockaddr_storage receiver;
  memset(&receiver, 0, sizeof(struct sockaddr_storage));
#ifdef OC_IPV4
  if (message->endpoint.flags & IPV4) {
    struct sockaddr_in *r = (struct sockaddr_in *)&receiver;
    memcpy(&r->sin_addr.s_addr, message->endpoint.addr.ipv4.address,
           sizeof(r->sin_addr.s_addr));
    r->sin_family = AF_INET;
    r->sin_port = htons(message->endpoint.addr.ipv4.port);
  }
#endif
#ifdef OC_IPV6
  if (message->endpoint.flags & IPV6) {
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receiver;
    memcpy(r->sin6_addr.s6_addr, message->endpoint.addr.ipv6.address,
           sizeof(r->sin6_addr.s6_addr));
    r->sin6_family = AF_INET6;
    r->sin6_port = htons(message->endpoint.addr.ipv6.port);
    r->sin6_scope_id = message->endpoint.addr.ipv6.scope;
  }
#endif
  int send_sock = -1;

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED)
  {
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
      send_sock = dev->secure4_sock;
    }
#endif
#ifdef OC_IPV6
    if (message->endpoint.flags & IPV6) {
      send_sock = dev->secure_sock;
    }
#endif
  }
  else
  {
#ifdef OC_IPV4
  if (message->endpoint.flags & IPV4) {
    send_sock = dev->server4_sock;
  }
#endif
#ifdef OC_IPV6
  if (message->endpoint.flags & IPV6) {
    send_sock = dev->server_sock;
  }
#endif
  }

#else /* OC_SECURITY */

#ifdef OC_IPV4
  if (message->endpoint.flags & IPV4) {
    send_sock = dev->server4_sock;
  }
#endif
#ifdef OC_IPV6
  if (message->endpoint.flags & IPV6) {
    send_sock = dev->server_sock;
  }
#endif

#endif /* OC_SECURITY */

  int bytes_sent = 0, x;
  while (bytes_sent < (int)message->length) {
    x = sendto(send_sock, message->data + bytes_sent,
        message->length - bytes_sent, 0, (struct sockaddr *)&receiver,
        sizeof(receiver));
    if (x < 0) {
      OC_WRN("sendto() returned errno %d\n", errno);
      return;
    }
    bytes_sent += x;
  }
  OC_DBG("Sent %d bytes\n", bytes_sent);
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  struct ifaddrs *ifs = NULL, *interface = NULL;
#ifdef TODO_IS_DONE
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interfaces: %d\n", errno);
    goto done;
  }
#endif
  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    if (!interface->ifa_flags & IFF_UP || interface->ifa_flags & IFF_LOOPBACK)
      continue;
#ifdef OC_IPV6
    if (message->endpoint.flags & IPV6 && interface->ifa_addr &&
        interface->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)interface->ifa_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        int mif = addr->sin6_scope_id;
        if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mif,
                       sizeof(mif)) == -1) {
          OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d\n",
                 errno);
          goto done;
        }
        message->endpoint.addr.ipv6.scope = mif;
        oc_send_buffer(message);
      }
    }
#endif
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4 && interface->ifa_addr &&
               interface->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)interface->ifa_addr;
      if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_MULTICAST_IF,
                     &addr->sin_addr, sizeof(addr->sin_addr)) == -1) {
        OC_ERR("setting socket option for default IP_MULTICAST_IF: %d\n",
               errno);
        goto done;
      }
      oc_send_buffer(message);
    }
#endif /* !OC_IPV4 */
  }
done:
  OC_DBG("TODO: freeifaddrs(ifs)");
}
#endif /* OC_CLIENT */

#ifdef OC_IPV4
static int
connectivity_ipv4_init(ip_context_t *dev)
{

  OC_DBG("Initializing IPv4 connectivity for device %d\n", dev->device);
  memset(&dev->mcast4, 0, sizeof(struct sockaddr_storage));
  memset(&dev->server4, 0, sizeof(struct sockaddr_storage));

  struct sockaddr_in *m = (struct sockaddr_in *)&dev->mcast4;
  m->sin_family = AF_INET;
  m->sin_port = htons(OCF_PORT_UNSECURED);
  m->sin_addr.s_addr = INADDR_ANY;

  struct sockaddr_in *l = (struct sockaddr_in *)&dev->server4;
  l->sin_family = AF_INET;
  l->sin_addr.s_addr = INADDR_ANY;
  l->sin_port = 0;

#ifdef OC_SECURITY
  memset(&dev->secure4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *sm = (struct sockaddr_in *)&dev->secure4;
  sm->sin_family = AF_INET;
  sm->sin_port = 0;
  sm->sin_addr.s_addr = INADDR_ANY;

  dev->secure4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure4_sock < 0) {
    OC_ERR("creating secure IPv4 socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  dev->server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server4_sock < 0 || dev->mcast4_sock < 0) {
    OC_ERR("creating IPv4 server sockets\n");
    return -1;
  }

  if (bind(dev->server4_sock, (struct sockaddr *)&dev->server4,
           sizeof(dev->server4)) == -1) {
    OC_ERR("binding server4 socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server4);
  if (getsockname(dev->server4_sock, (struct sockaddr *)&dev->server4,
                  &socklen) == -1) {
    OC_ERR("obtaining server4 socket information %d\n", errno);
    return -1;
  }

  dev->port4 = ntohs(l->sin_port);

  if (configure_mcast_socket(dev->mcast4_sock, AF_INET) < 0) {
    OC_ERR("configure_mcast_socket IPv4 failed\n");
    return -1;
  }

  int reuse = 1;
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }
  if (bind(dev->mcast4_sock, (struct sockaddr *)&dev->mcast4,
           sizeof(dev->mcast4)) == -1) {
    OC_ERR("binding mcast IPv4 socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure4_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }

  if (bind(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
           sizeof(dev->secure4)) == -1) {
    OC_ERR("binding IPv4 secure socket %d\n", errno);
    return -1;
  }

  socklen = sizeof(dev->secure4);
  if (getsockname(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
                  &socklen) == -1) {
    OC_ERR("obtaining DTLS4 socket information %d\n", errno);
    return -1;
  }

  dev->dtls4_port = ntohs(sm->sin_port);
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized IPv4 connectivity for device %d\n",
         dev->device);

  return 0;
}
#endif

int oc_connectivity_init(int device) {
  OC_DBG("Initializing connectivity for device %d\n", device);
#ifdef OC_DYNAMIC_ALLOCATION
  ip_context_t *dev = (ip_context_t *)calloc(1, sizeof(ip_context_t));
  if (!dev) {
    oc_abort("Insufficient memory");
  }
  oc_list_add(ip_contexts, dev);
#else  /* OC_DYNAMIC_ALLOCATION */
  ip_context_t *dev = &devices[device];
#endif /* !OC_DYNAMIC_ALLOCATION */
  dev->device = device;

#ifdef OC_IPV6
  memset(&dev->mcast, 0, sizeof(struct sockaddr_storage));
  memset(&dev->server, 0, sizeof(struct sockaddr_storage));

  struct sockaddr_in6 *m = (struct sockaddr_in6 *)&dev->mcast;
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(OCF_PORT_UNSECURED);
  m->sin6_addr = in6addr_any;

  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;

#ifdef OC_SECURITY
  memset(&dev->secure, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&dev->secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_port = 0;
  sm->sin6_addr = in6addr_any;
#endif /* OC_SECURITY */

  dev->server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server_sock < 0 || dev->mcast_sock < 0) {
    OC_ERR("creating server sockets\n");
    return -1;
  }

#ifdef OC_SECURITY
  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock < 0) {
    OC_ERR("creating secure socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  int opt = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
                 sizeof(opt)) == -1) {
    OC_ERR("setting sock option %d\n", errno);
    return -1;
  }

  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == -1) {
    OC_ERR("binding server socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == -1) {
    OC_ERR("obtaining server socket information %d\n", errno);
    return -1;
  }

  dev->port = ntohs(l->sin6_port);

  if (configure_mcast_socket(dev->mcast_sock, AF_INET6) < 0) {
    return -1;
  }

  int reuse = 1;
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast,
           sizeof(dev->mcast)) == -1) {
    OC_ERR("binding mcast socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure,
           sizeof(dev->secure)) == -1) {
    OC_ERR("binding IPv6 secure socket %d\n", errno);
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure,
                  &socklen) == -1) {
    OC_ERR("obtaining secure socket information %d\n", errno);
    return -1;
  }

  dev->dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */
#endif


#ifdef OC_IPV4
  if (connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4\n");
  }
#endif /* OC_IPV4 */


#ifdef OC_NETLINK
  /* Netlink socket to listen for network interface changes.
   * Only initialized once, and change events are captured by only
   * the network event thread for the 0th logical device.
   */
  if (!ifchange_initialized) {
    memset(&ifchange_nl, 0, sizeof(struct sockaddr_nl));
    ifchange_nl.nl_family = AF_NETLINK;
    ifchange_nl.nl_groups =
        RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    ifchange_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (ifchange_sock < 0) {
      OC_ERR(
          "creating netlink socket to monitor network interface changes %d\n",
          errno);
      return -1;
    }
    if (bind(ifchange_sock, (struct sockaddr *)&ifchange_nl,
             sizeof(ifchange_nl)) == -1) {
      OC_ERR("binding netlink socket %d\n", errno);
      return -1;
    }
    ifchange_initialized = true;
  }

#endif

  if (pthread_create(&dev->event_thread, NULL, &network_event_thread, dev) !=
      0) {
    OC_ERR("creating network polling thread\n");
    return -1;
  }

  OC_DBG("Successfully initialized connectivity for device %d\n", device);

  return 0;
}

void
oc_connectivity_shutdown(int device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  dev->terminate = 1;

#ifdef OC_IPV6
  close(dev->server_sock);
  close(dev->mcast_sock);
#endif

#ifdef OC_IPV4
  close(dev->server4_sock);
  close(dev->mcast4_sock);
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
#ifdef OC_IPV6
  close(dev->secure_sock);
#endif
#ifdef OC_IPV4
  close(dev->secure4_sock);
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

  pthread_cancel(dev->event_thread);
  pthread_join(dev->event_thread, NULL);

#ifdef OC_DYNAMIC_ALLOCATION
  oc_list_remove(ip_contexts, dev);
  free(dev);
#endif /* OC_DYNAMIC_ALLOCATION */

  OC_DBG("oc_connectivity_shutdown for device %d\n", device);
}
