/*
// Copyright (c) 2016 Intel Corporation
// Copyright (c) 2017 Lynx Technology
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

#define __USE_GNU
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
#include <netinet/in_var.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

#define OCF_IF_FLAGS (IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST)

// for Apple Mac
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP

typedef struct ip_context_t
{
  struct ip_context_t *next;
  // Bind will fail on Mac when using sockaddr_storage for IPv6.
  struct sockaddr_in6 mcast;
  struct sockaddr_in6 server;
  int mcast_sock;
  int server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  struct sockaddr_in6 secure;
  int secure_sock;
  uint16_t dtls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  struct sockaddr_in mcast4;
  struct sockaddr_in server4;
  int mcast4_sock;
  int server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  struct sockaddr_in secure4;
  int secure4_sock;
  uint16_t dtls4_port;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  pthread_t event_thread;
  int terminate;
  int device;
} ip_context_t;

#ifdef OC_DYNAMIC_ALLOCATION
OC_LIST(ip_contexts);
#else /* OC_DYNAMIC_ALLOCATION */
static ip_context_t devices[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_network_event_handler_mutex_init(void)
{
  if (pthread_mutex_init(&mutex, NULL) != 0) {
    OC_ERR("initializing network event handler mutex\n");
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

static ip_context_t *
get_ip_context_for_device(int device)
{
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

static void *
network_event_thread(void *data)
{
  struct sockaddr_in6 client6 = { 0 };

#ifdef OC_IPV4
  struct sockaddr_in client4 = { 0 };
#endif

  ip_context_t *dev = (ip_context_t *)data;

  fd_set rfds, setfds;
  FD_ZERO(&rfds);
  FD_SET(dev->server_sock, &rfds);
  FD_SET(dev->mcast_sock, &rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure_sock, &rfds);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  FD_SET(dev->server4_sock, &rfds);
  FD_SET(dev->mcast4_sock, &rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure4_sock, &rfds);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */

  int i, n;

  while (dev->terminate != 1) {
    setfds = rfds;
    n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

    for (i = 0; i < n; i++) {
      socklen_t len6 = sizeof(client6);
      oc_message_t *message = oc_allocate_message();

      if (!message) {
        break;
      }

      if (FD_ISSET(dev->server_sock, &setfds)) {
        ssize_t count = recvfrom(dev->server_sock, message->data, OC_PDU_SIZE, 0,
				 (struct sockaddr *)&client6, &len6);
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
        ssize_t count = recvfrom(dev->mcast_sock, message->data, OC_PDU_SIZE, 0,
				 (struct sockaddr *)&client6, &len6);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6;
        message->endpoint.device = dev->device;
        FD_CLR(dev->mcast_sock, &setfds);
        goto common;
      }

#ifdef OC_IPV4
      socklen_t len4 = sizeof(client4);
      if (FD_ISSET(dev->server4_sock, &setfds)) {
        ssize_t count = recvfrom(dev->server4_sock, message->data, OC_PDU_SIZE, 0,
				 (struct sockaddr *)&client4, &len4);
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
        ssize_t count = recvfrom(dev->mcast4_sock, message->data, OC_PDU_SIZE, 0,
				 (struct sockaddr *)&client4, &len4);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV4;
        message->endpoint.device = dev->device;
        FD_CLR(dev->mcast4_sock, &setfds);
        goto common;
      }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
      if (FD_ISSET(dev->secure_sock, &setfds)) {
        ssize_t count = recvfrom(dev->secure_sock, message->data, OC_PDU_SIZE, 0,
				 (struct sockaddr *)&client6, &len6);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6 | SECURED;
        message->endpoint.device = dev->device;
        FD_CLR(dev->secure_sock, &setfds);
      }
#ifdef OC_IPV4
      if (FD_ISSET(dev->secure4_sock, &setfds)) {
        ssize_t count = recvfrom(dev->secure4_sock, message->data, OC_PDU_SIZE, 0,
				 (struct sockaddr *)&client4, &len4);
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
        memcpy(message->endpoint.addr.ipv4.address, &client4.sin_addr.s_addr,
               sizeof(client4.sin_addr.s_addr));
        message->endpoint.addr.ipv4.port = ntohs(client4.sin_port);
      } else if (message->endpoint.flags & IPV6) {
#else  /* OC_IPV4 */
      if (message->endpoint.flags & IPV6) {
#endif /* !OC_IPV4 */
        memcpy(message->endpoint.addr.ipv6.address, &client6.sin6_addr.s6_addr,
               sizeof(client6.sin6_addr.s6_addr));
        message->endpoint.addr.ipv6.scope = client6.sin6_scope_id;
        message->endpoint.addr.ipv6.port = ntohs(client6.sin6_port);
      }

      OC_DBG("Incoming message from ");
      OC_LOGipaddr(message->endpoint);
      OC_DBG("\n");

      oc_network_event(message);
    }
  }
  pthread_exit(NULL);
}

static void
get_interface_addresses(uint16_t port
#ifdef OC_SECURITY
                        , uint16_t dtls_port
#endif /* OC_SECURITY */
#ifdef OC_IPV4
                        , uint16_t port4
#ifdef OC_SECURITY
                        , uint16_t dtls_port4
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
                        )
  {
    struct ifaddrs *ifs = NULL, *interface = NULL;
    int io_socket6 = -1;
    if (getifaddrs(&ifs) < 0) {
      OC_ERR("querying interfaces: %d\n", errno);
      goto done;
    }
    if ((io_socket6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
      OC_ERR("cannot open AF_INET6 socket: %d\n", errno);
      goto done;
    }

    for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
      if (interface->ifa_addr == NULL ||
          (interface->ifa_flags & (OCF_IF_FLAGS | IFF_LOOPBACK)) !=
          OCF_IF_FLAGS) {
        OC_DBG("skipping %s\n", (interface->ifa_name ? interface->ifa_name : "<none>"));
        continue;
      }

      oc_endpoint_t ep = { 0 };

      if (interface->ifa_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)interface->ifa_addr;
        struct in6_ifreq ifreq6 = { 0 };
        strncpy(ifreq6.ifr_name, interface->ifa_name, sizeof(ifreq6.ifr_name));
        ifreq6.ifr_addr = *addr;
        if (ioctl(io_socket6, SIOCGIFAFLAG_IN6, &ifreq6) < 0) {
          OC_ERR("cannot get flags for %s\n", interface->ifa_name);
          continue;
        }
        
        if ((ifreq6.ifr_ifru.ifru_flags6 & IN6_IFF_TEMPORARY) == 0) {
          ep.addr.ipv6.scope = addr->sin6_scope_id;
          memcpy(ep.addr.ipv6.address, &addr->sin6_addr, 16);
          ep.addr.ipv6.port = port;
          ep.flags = IPV6;
          ep.addr.ipv6.port = port;
          if (oc_add_endpoint_to_list(&ep) == -1) {
            goto done;
          }
#ifdef OC_SECURITY
          ep.addr.ipv6.port = dtls_port;
          ep.flags |= SECURED;
          if (oc_add_endpoint_to_list(&ep) == -1) {
            goto done;
          }
#endif /* OC_SECURITY */
        }
#ifdef OC_IPV4
      } else if (interface->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)interface->ifa_addr;
        memcpy(ep.addr.ipv4.address, &addr->sin_addr.s_addr, 4);
        ep.addr.ipv4.port = port4;
        ep.flags = IPV4;
        if (oc_add_endpoint_to_list(&ep) == -1) {
          goto done;
        }
#ifdef OC_SECURITY
        ep.addr.ipv4.port = dtls_port4;
        ep.flags |= SECURED;
        if (oc_add_endpoint_to_list(&ep) == -1) {
          goto done;
        }
#endif /* OC_SECURITY */
      }
#endif  /* OC_IPV4 */
    }

  done:
    freeifaddrs(ifs);
    if (io_socket6 >=0) {
      close(io_socket6);
    }
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  oc_init_endpoint_list();
  ip_context_t *dev = get_ip_context_for_device(device);
  get_interface_addresses(dev->port
#ifdef OC_SECURITY
                          , dev->dtls_port
#endif /* OC_SECURITY */
#ifdef OC_IPV4
                          , dev->port4
#ifdef OC_SECURITY
                          , dev->dtls4_port
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
                          );
  return oc_get_endpoint_list();
}

void
oc_send_buffer(oc_message_t *message)
{
  OC_DBG("Outgoing message to ");
  OC_LOGipaddr(message->endpoint);
  OC_DBG("\n");

  socklen_t receiver_size;
  struct sockaddr *receiver;
  struct sockaddr_in6 receiver6 = {0};

#ifdef OC_IPV4
  struct sockaddr_in receiver4 = {0};
  
  if (message->endpoint.flags & IPV4) {
    receiver = (struct sockaddr*)&receiver4;
    receiver_size = sizeof(receiver4);
    memcpy(&receiver4.sin_addr.s_addr, message->endpoint.addr.ipv4.address,
           sizeof(receiver4.sin_addr.s_addr));
    receiver4.sin_family = AF_INET;
    receiver4.sin_port = htons(message->endpoint.addr.ipv4.port);
  } else {
#else
  {
#endif
    receiver = (struct sockaddr *)&receiver6;
    receiver_size = sizeof(receiver6);
    memcpy(&receiver6.sin6_addr.s6_addr, message->endpoint.addr.ipv6.address,
           sizeof(receiver6.sin6_addr.s6_addr));
    receiver6.sin6_family = AF_INET6;
    receiver6.sin6_port = htons(message->endpoint.addr.ipv6.port);
    receiver6.sin6_scope_id = message->endpoint.addr.ipv6.scope;
  }
  int send_sock = -1;

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
      send_sock = dev->secure4_sock;
    } else {
      send_sock = dev->secure_sock;
    }
#else  /* OC_IPV4 */
    send_sock = dev->secure_sock;
#endif /* !OC_IPV4 */
  } else
#endif /* OC_SECURITY */
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
    send_sock = dev->server4_sock;
  } else {
    send_sock = dev->server_sock;
  }
#else  /* OC_IPV4 */
  {
    send_sock = dev->server_sock;
  }
#endif /* !OC_IPV4 */

  int bytes_sent = 0;
  ssize_t x;
  while (bytes_sent < (int)message->length) {
    x = sendto(send_sock, message->data + bytes_sent,
        message->length - bytes_sent, 0, (struct sockaddr *)receiver,
        receiver_size);
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
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interfaces: %d\n", errno);
    goto done;
  }

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    if ((interface->ifa_flags & (OCF_IF_FLAGS | IFF_LOOPBACK)) !=
        OCF_IF_FLAGS) {
      OC_DBG("skipping %s\n", (interface->ifa_name ? interface->ifa_name : "<none>"));
      continue;
    }
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
        oc_send_buffer(message);
      }
#ifdef OC_IPV4
    } else if (message->endpoint.flags & IPV4 && interface->ifa_addr &&
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
#else  /* OC_IPV4 */
    }
#endif /* !OC_IPV4 */
  }
done:
  freeifaddrs(ifs);
}
#endif /* OC_CLIENT */

#ifdef OC_IPV4
static int
connectivity_ipv4_init(ip_context_t *dev)
{
  OC_DBG("Initializing IPv4 connectivity for device %d\n", dev->device);
  memset(&dev->mcast4, 0, sizeof(dev->mcast4));
  memset(&dev->server4, 0, sizeof(dev->server4));

  struct sockaddr_in *m = (struct sockaddr_in *)&dev->mcast4;
  m->sin_family = AF_INET;
  m->sin_port = htons(OCF_PORT_UNSECURED);
  m->sin_addr.s_addr = INADDR_ANY;

  struct sockaddr_in *l = (struct sockaddr_in *)&dev->server4;
  l->sin_family = AF_INET;
  l->sin_addr.s_addr = INADDR_ANY;
  l->sin_port = 0;

#ifdef OC_SECURITY
  memset(&dev->secure4, 0, sizeof(dev->secure4));
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

  struct ip_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
  if (setsockopt(dev->mcast4_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining IPv4 multicast group %d\n", errno);
    return -1;
  }

  int reuse = 1;
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }
  // Mac requires also an explicit set of re-use port.
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEPORT, &reuse,
		 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseport IPv4 option %d\n", errno);
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
    OC_ERR("setting reuseaddr IPv4 security option %d\n", errno);
    return -1;
  }
  // Mac requires also an explicit set of re-use port.
  if (setsockopt(dev->secure4_sock, SOL_SOCKET, SO_REUSEPORT, &reuse,
		 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseport IPv4 security option %d\n", errno);
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

static int
add_mcast_sock_to_ipv6_multicast_group(int sock, const uint8_t *addr)
{
  struct ipv6_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, addr, 16);
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining IPv6 multicast group %d\n", errno);
    return -1;
  }
  return 0;
}

int
oc_connectivity_init(int device)
{
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

  memset(&dev->mcast, 0, sizeof(dev->mcast));
  memset(&dev->server, 0, sizeof(dev->server));

  struct sockaddr_in6 *m = (struct sockaddr_in6 *)&dev->mcast;
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(OCF_PORT_UNSECURED);
  m->sin6_addr = in6addr_any;

  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;

#ifdef OC_SECURITY
  memset(&dev->secure, 0, sizeof(dev->secure));
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

  if (add_mcast_sock_to_ipv6_multicast_group(dev->mcast_sock,
                                             ALL_OCF_NODES_LL) < 0) {
    return -1;
  }
  if (add_mcast_sock_to_ipv6_multicast_group(dev->mcast_sock,
                                             ALL_OCF_NODES_RL) < 0) {
    return -1;
  }
  if (add_mcast_sock_to_ipv6_multicast_group(dev->mcast_sock,
                                             ALL_OCF_NODES_SL) < 0) {
    return -1;
  }

  int reuse = 1;
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
		 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv6 option %d\n", errno);
    return -1;
  }
  // Mac requires also an explicit set of re-use port.
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEPORT, &reuse,
		 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseport IPv6 option %d\n", errno);
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
    OC_ERR("setting reuseaddr IPv6 security option %d\n", errno);
    return -1;
  }
  // Mac requires also an explicit set of re-use port.
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEPORT, &reuse,
		 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseport IPv6 security option %d\n", errno);
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

#ifdef OC_IPV4
  if (connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4\n");
  }
#endif /* OC_IPV4 */

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

  close(dev->server_sock);
  close(dev->mcast_sock);

#ifdef OC_IPV4
  close(dev->server4_sock);
  close(dev->mcast4_sock);
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  close(dev->secure_sock);
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
