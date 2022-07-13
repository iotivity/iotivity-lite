/*
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

#define _GNU_SOURCE
#include "ipadapter.h"
#include "ipcontext.h"
#include "oc_config.h"
#ifdef OC_TCP
#include "tcpadapter.h"
#endif
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "util/oc_atomic.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/un.h>
#include <unistd.h>

/* Some outdated toolchains do not define IFA_FLAGS.
   Note: Requires Linux kernel 3.14 or later. */
#ifndef IFA_FLAGS
#define IFA_FLAGS (IFA_MULTICAST + 1)
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

#ifdef OC_WKCORE
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
#endif

#define ALL_COAP_NODES_V4 0xe00001bb

static pthread_mutex_t mutex;
struct sockaddr_nl ifchange_nl;
int ifchange_sock;
bool ifchange_initialized;

OC_LIST(ip_contexts);
OC_MEMB(ip_context_s, ip_context_t, OC_MAX_NUM_DEVICES);

OC_MEMB(device_eps, oc_endpoint_t, 8 * OC_MAX_NUM_DEVICES); // fix

#ifdef OC_NETWORK_MONITOR
/**
 * Structure to manage interface list.
 */
typedef struct ip_interface
{
  struct ip_interface *next;
  int if_index;
} ip_interface_t;

OC_LIST(ip_interface_list);
OC_MEMB(ip_interface_s, ip_interface_t, OC_MAX_IP_INTERFACES);

OC_LIST(oc_network_interface_cb_list);
OC_MEMB(oc_network_interface_cb_s, oc_network_interface_cb_t,
        OC_MAX_NETWORK_INTERFACE_CBS);

static ip_interface_t *
get_ip_interface(int target_index)
{
  ip_interface_t *if_item = oc_list_head(ip_interface_list);
  while (if_item != NULL && if_item->if_index != target_index) {
    if_item = if_item->next;
  }
  return if_item;
}

static bool
add_ip_interface(int target_index)
{
  if (get_ip_interface(target_index))
    return false;

  ip_interface_t *new_if = oc_memb_alloc(&ip_interface_s);
  if (!new_if) {
    OC_ERR("interface item alloc failed");
    return false;
  }
  new_if->if_index = target_index;
  oc_list_add(ip_interface_list, new_if);
  OC_DBG("New interface added: %d", new_if->if_index);
  return true;
}

static bool
check_new_ip_interfaces(void)
{
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interface address");
    return false;
  }
  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    /* Ignore interfaces that are down and the loopback interface */
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }
    /* Obtain interface index for this address */
    int if_index = if_nametoindex(interface->ifa_name);

    add_ip_interface(if_index);
  }
  freeifaddrs(ifs);
  return true;
}

static bool
remove_ip_interface(int target_index)
{
  ip_interface_t *if_item = get_ip_interface(target_index);
  if (!if_item) {
    return false;
  }

  oc_list_remove(ip_interface_list, if_item);
  oc_memb_free(&ip_interface_s, if_item);
  OC_DBG("Removed from ip interface list: %d", target_index);
  return true;
}

static void
remove_all_ip_interface(void)
{
  ip_interface_t *if_item = oc_list_head(ip_interface_list), *next;
  while (if_item != NULL) {
    next = if_item->next;
    oc_list_remove(ip_interface_list, if_item);
    oc_memb_free(&ip_interface_s, if_item);
    if_item = next;
  }
}

static void
remove_all_network_interface_cbs(void)
{
  oc_network_interface_cb_t *cb_item =
                              oc_list_head(oc_network_interface_cb_list),
                            *next;
  while (cb_item != NULL) {
    next = cb_item->next;
    oc_list_remove(oc_network_interface_cb_list, cb_item);
    oc_memb_free(&oc_network_interface_cb_s, cb_item);
    cb_item = next;
  }
}
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SESSION_EVENTS
OC_LIST(oc_session_event_cb_list);
OC_MEMB(oc_session_event_cb_s, oc_session_event_cb_t, OC_MAX_SESSION_EVENT_CBS);

static void
remove_all_session_event_cbs(void)
{
  oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list),
                        *next;
  while (cb_item != NULL) {
    next = cb_item->next;
    oc_list_remove(oc_session_event_cb_list, cb_item);
    oc_memb_free(&oc_session_event_cb_s, cb_item);
    cb_item = next;
  }
}

#endif /* OC_SESSION_EVENTS */

void
oc_network_event_handler_mutex_init(void)
{
  if (pthread_mutex_init(&mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex");
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

void
oc_network_event_handler_mutex_destroy(void)
{
  ifchange_initialized = false;
  close(ifchange_sock);
#ifdef OC_NETWORK_MONITOR
  remove_all_ip_interface();
  remove_all_network_interface_cbs();
#endif /* OC_NETWORK_MONITOR */
#ifdef OC_SESSION_EVENTS
  remove_all_session_event_cbs();
#endif /* OC_SESSION_EVENTS */
  pthread_mutex_destroy(&mutex);
}

static ip_context_t *
get_ip_context_for_device(size_t device)
{
  ip_context_t *dev = oc_list_head(ip_contexts);
  while (dev != NULL && dev->device != device) {
    dev = dev->next;
  }
  if (!dev) {
    return NULL;
  }
  return dev;
}

#ifdef OC_IPV4
static int
add_mcast_sock_to_ipv4_mcast_group(int mcast_sock, const struct in_addr *local,
                                   int interface_index)
{
  struct ip_mreqn mreq;

  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
  mreq.imr_ifindex = interface_index;
  memcpy(&mreq.imr_address, local, sizeof(struct in_addr));

  (void)setsockopt(mcast_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining IPv4 multicast group %d", errno);
    return -1;
  }

  return 0;
}
#endif /* OC_IPV4 */

static int
add_mcast_sock_to_ipv6_mcast_group(int mcast_sock, int interface_index)
{
  struct ipv6_mreq mreq;

  /* Link-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_LL, 16);
  mreq.ipv6mr_interface = interface_index;

  (void)setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining link-local IPv6 multicast group %d", errno);
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
    OC_ERR("joining realm-local IPv6 multicast group %d", errno);
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
    OC_ERR("joining site-local IPv6 multicast group %d", errno);
    return -1;
  }

#ifdef OC_WKCORE

  OC_DBG("Adding all CoAP Nodes");
  /* Link-local scope ALL COAP NODES */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_LL, 16);
  mreq.ipv6mr_interface = interface_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining link-local IPv6 multicast group %d", errno);
    return -1;
  }

  /* Realm-local scope ALL COAP nodes  */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_RL, 16);
  mreq.ipv6mr_interface = interface_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining realm-local IPv6 multicast group %d", errno);
    return -1;
  }

  /* Site-local scope ALL COAP nodes */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_SL, 16);
  mreq.ipv6mr_interface = interface_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining site-local IPv6 multicast group %d", errno);
    return -1;
  }
#endif

  return 0;
}

static int
configure_mcast_socket(int mcast_sock, int sa_family)
{
  int ret = 0;
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interface addrs");
    return -1;
  }
  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
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
      struct sockaddr_in6 *a = (struct sockaddr_in6 *)interface->ifa_addr;
      if (a && IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)) {
        ret += add_mcast_sock_to_ipv6_mcast_group(mcast_sock, if_index);
      }
    }
#ifdef OC_IPV4
    else if (sa_family == AF_INET) {
      struct sockaddr_in *a = (struct sockaddr_in *)interface->ifa_addr;
      if (a)
        ret += add_mcast_sock_to_ipv4_mcast_group(mcast_sock, &a->sin_addr,
                                                  if_index);
    }
#endif /* OC_IPV4 */
  }
  freeifaddrs(ifs);
  return ret;
}

static void
get_interface_addresses(ip_context_t *dev, unsigned char family, uint16_t port,
                        bool secure, bool tcp)
{
  struct
  {
    struct nlmsghdr nlhdr;
    struct ifaddrmsg addrmsg;
  } request;
  struct nlmsghdr *response;

  memset(&request, 0, sizeof(request));
  request.nlhdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  request.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  request.nlhdr.nlmsg_type = RTM_GETADDR;
  request.addrmsg.ifa_family = family;

  int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl_sock < 0) {
    return;
  }

  if (send(nl_sock, &request, request.nlhdr.nlmsg_len, 0) < 0) {
    close(nl_sock);
    return;
  }

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(nl_sock, &rfds);

  if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) < 0) {
    close(nl_sock);
    return;
  }

  int prev_interface_index = -1;
  bool done = false;
  while (!done) {
    int guess = 512, response_len;
    do {
      guess <<= 1;
      uint8_t dummy[guess];
      response_len = recv(nl_sock, dummy, guess, MSG_PEEK);
      if (response_len < 0) {
        close(nl_sock);
        return;
      }
    } while (response_len == guess);

    uint8_t buffer[response_len];
    response_len = recv(nl_sock, buffer, response_len, 0);
    if (response_len < 0) {
      close(nl_sock);
      return;
    }

    response = (struct nlmsghdr *)buffer;
    if (response->nlmsg_type == NLMSG_ERROR) {
      close(nl_sock);
      return;
    }

    while (NLMSG_OK(response, response_len)) {
      if (response->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }
      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      bool include = false;
      struct ifaddrmsg *addrmsg = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (addrmsg->ifa_scope < RT_SCOPE_HOST) {
        if ((int)addrmsg->ifa_index == prev_interface_index) {
          goto next_ifaddr;
        }
        ep.interface_index = addrmsg->ifa_index;
        include = true;
        struct rtattr *attr = (struct rtattr *)IFA_RTA(addrmsg);
        int att_len = IFA_PAYLOAD(response);
        while (RTA_OK(attr, att_len)) {
          if (attr->rta_type == IFA_ADDRESS) {
#ifdef OC_IPV4
            if (family == AF_INET) {
              memcpy(ep.addr.ipv4.address, RTA_DATA(attr), 4);
              ep.flags = IPV4;
            } else
#endif /* OC_IPV4 */
              if (family == AF_INET6) {
              memcpy(ep.addr.ipv6.address, RTA_DATA(attr), 16);
              ep.flags = IPV6;
            }
          } else if (attr->rta_type == IFA_FLAGS) {
            if (*(uint32_t *)(RTA_DATA(attr)) & IFA_F_TEMPORARY) {
              include = false;
            }
          }
          attr = RTA_NEXT(attr, att_len);
        }
      }
      if (include) {
        prev_interface_index = addrmsg->ifa_index;
        if (addrmsg->ifa_scope == RT_SCOPE_LINK && family == AF_INET6) {
          ep.addr.ipv6.scope = addrmsg->ifa_index;
        }
        if (secure) {
          ep.flags |= SECURED;
        }
#ifdef OC_IPV4
        if (family == AF_INET) {
          ep.addr.ipv4.port = port;
        } else
#endif /* OC_IPV4 */
          if (family == AF_INET6) {
          ep.addr.ipv6.port = port;
        }
#ifdef OC_TCP
        if (tcp) {
          ep.flags |= TCP;
        }
#else
        (void)tcp;
#endif /* OC_TCP */
        oc_endpoint_t *new_ep = oc_memb_alloc(&device_eps);
        if (!new_ep) {
          close(nl_sock);
          return;
        }
        memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
        oc_list_add(dev->eps, new_ep);
      }

    next_ifaddr:
      response = NLMSG_NEXT(response, response_len);
    }
  }
  close(nl_sock);
}

static void
free_endpoints_list(ip_context_t *dev)
{
  oc_endpoint_t *ep = oc_list_pop(dev->eps);

  while (ep != NULL) {
    oc_memb_free(&device_eps, ep);
    ep = oc_list_pop(dev->eps);
  }
}

static void
refresh_endpoints_list(ip_context_t *dev)
{
  free_endpoints_list(dev);

  get_interface_addresses(dev, AF_INET6, dev->port, false, false);
#ifdef OC_SECURITY
  get_interface_addresses(dev, AF_INET6, dev->dtls_port, true, false);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  get_interface_addresses(dev, AF_INET, dev->port4, false, false);
#ifdef OC_SECURITY
  get_interface_addresses(dev, AF_INET, dev->dtls4_port, true, false);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */

#ifdef OC_TCP
  get_interface_addresses(dev, AF_INET6, dev->tcp.port, false, true);
#ifdef OC_SECURITY
  get_interface_addresses(dev, AF_INET6, dev->tcp.tls_port, true, true);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  get_interface_addresses(dev, AF_INET, dev->tcp.port4, false, true);
#ifdef OC_SECURITY
  get_interface_addresses(dev, AF_INET, dev->tcp.tls4_port, true, true);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#endif /* OC_TCP */
}

oc_endpoint_t *
oc_connectivity_get_endpoints(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);

  if (!dev) {
    return NULL;
  }

  bool refresh = false;
  bool swapped = false;
  int8_t expected = OC_ATOMIC_LOAD8(dev->flags);
  while ((expected & IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST) != 0) {
    int8_t desired = expected & ~IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST;
    OC_ATOMIC_COMPARE_AND_SWAP8(dev->flags, expected, desired, swapped);
    if (swapped) {
      refresh = true;
      break;
    }
  }

  if (refresh || oc_list_length(dev->eps) == 0) {
    refresh_endpoints_list(dev);
  }

  return oc_list_head(dev->eps);
}

/* Called after network interface up/down events.
 * This function reconfigures IPv6/v4 multicast sockets for
 * all logical devices.
 */
static int
process_interface_change_event(void)
{
  int ret = 0, i, num_devices = oc_core_get_num_devices();
  struct nlmsghdr *response = NULL;

  int guess = 512, response_len;
  do {
    guess <<= 1;
    uint8_t dummy[guess];
    response_len = recv(ifchange_sock, dummy, guess, MSG_PEEK);
    if (response_len < 0) {
      OC_ERR("reading payload size from netlink interface");
      return -1;
    }
  } while (response_len == guess);

  uint8_t buffer[response_len];
  response_len = recv(ifchange_sock, buffer, response_len, 0);
  if (response_len < 0) {
    OC_ERR("reading payload from netlink interface");
    return -1;
  }

  response = (struct nlmsghdr *)buffer;
  if (response->nlmsg_type == NLMSG_ERROR) {
    OC_ERR("caught NLMSG_ERROR in payload from netlink interface");
    return -1;
  }

  bool if_state_changed = false;

  while (NLMSG_OK(response, response_len)) {
    if (response->nlmsg_type == RTM_NEWADDR) {
      struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (ifa) {
#ifdef OC_NETWORK_MONITOR
        if (add_ip_interface(ifa->ifa_index)) {
          oc_network_interface_event(NETWORK_INTERFACE_UP);
        }
#endif /* OC_NETWORK_MONITOR */
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
            } else
#endif /* OC_IPV4 */
              if (ifa->ifa_family == AF_INET6 &&
                  ifa->ifa_scope == RT_SCOPE_LINK) {
              for (i = 0; i < num_devices; i++) {
                ip_context_t *dev = get_ip_context_for_device(i);
                ret += add_mcast_sock_to_ipv6_mcast_group(dev->mcast_sock,
                                                          ifa->ifa_index);
              }
            }
          }
          attr = RTA_NEXT(attr, att_len);
        }
      }
      if_state_changed = true;
    } else if (response->nlmsg_type == RTM_DELADDR) {
      struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (ifa) {
#ifdef OC_NETWORK_MONITOR
        if (remove_ip_interface(ifa->ifa_index)) {
          oc_network_interface_event(NETWORK_INTERFACE_DOWN);
        }
#endif /* OC_NETWORK_MONITOR */
      }
      if_state_changed = true;
    }
    response = NLMSG_NEXT(response, response_len);
  }

  if (if_state_changed) {
    for (i = 0; i < num_devices; i++) {
      ip_context_t *dev = get_ip_context_for_device(i);
      if (dev == NULL) {
        continue;
      }
      bool swapped = false;
      int8_t expected = OC_ATOMIC_LOAD8(dev->flags);
      while ((expected & IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST) == 0) {
        int8_t desired = expected | IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST;
        OC_ATOMIC_COMPARE_AND_SWAP8(dev->flags, expected, desired, swapped);
        if (swapped) {
          break;
        }
      }
    }
  }

  return ret;
}

static int
recv_msg(int sock, uint8_t *recv_buf, int recv_buf_size,
         oc_endpoint_t *endpoint, bool multicast)
{
  struct sockaddr_storage client;
  struct iovec iovec[1];
  struct msghdr msg;
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))];

  iovec[0].iov_base = recv_buf;
  iovec[0].iov_len = (size_t)recv_buf_size;

  msg.msg_name = &client;
  msg.msg_namelen = sizeof(client);

  msg.msg_iov = iovec;
  msg.msg_iovlen = 1;

  msg.msg_control = msg_control;
  msg.msg_controllen = sizeof(msg_control);

  msg.msg_flags = 0;

  int ret = recvmsg(sock, &msg, 0);

  if (ret < 0 || (msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
    OC_ERR("recvmsg returned with an error: %d", errno);
    return -1;
  }

  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != 0; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
      if (msg.msg_namelen != sizeof(struct sockaddr_in6)) {
        OC_ERR("anciliary data contains invalid source address");
        return -1;
      }
      /* Set source address of packet in endpoint structure */
      struct sockaddr_in6 *c6 = (struct sockaddr_in6 *)&client;
      memcpy(endpoint->addr.ipv6.address, c6->sin6_addr.s6_addr,
             sizeof(c6->sin6_addr.s6_addr));
      endpoint->addr.ipv6.scope = c6->sin6_scope_id;
      endpoint->addr.ipv6.port = ntohs(c6->sin6_port);

      /* Set receiving network interface index */
      struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
      endpoint->interface_index = pktinfo->ipi6_ifindex;

      /* For a unicast receiving socket, extract the destination address
       * of the UDP packet into the endpoint's addr_local attribute.
       * This would be used to set the source address of a response that
       * results from this message.
       */
      if (!multicast) {
        memcpy(endpoint->addr_local.ipv6.address, pktinfo->ipi6_addr.s6_addr,
               16);
      } else {
        memset(endpoint->addr_local.ipv6.address, 0, 16);
      }
      break;
    }
#ifdef OC_IPV4
    else if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
      if (msg.msg_namelen != sizeof(struct sockaddr_in)) {
        OC_ERR("anciliary data contains invalid source address");
        return -1;
      }
      struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
      struct sockaddr_in *c4 = (struct sockaddr_in *)&client;
      memcpy(endpoint->addr.ipv4.address, &c4->sin_addr.s_addr,
             sizeof(c4->sin_addr.s_addr));
      endpoint->addr.ipv4.port = ntohs(c4->sin_port);
      endpoint->interface_index = pktinfo->ipi_ifindex;
      if (!multicast) {
        memcpy(endpoint->addr_local.ipv4.address, &pktinfo->ipi_addr.s_addr, 4);
      } else {
        memset(endpoint->addr_local.ipv4.address, 0, 4);
      }
      break;
    }
#endif /* OC_IPV4 */
  }

  return ret;
}

static void
oc_udp_add_socks_to_fd_set(ip_context_t *dev)
{
  FD_SET(dev->server_sock, &dev->rfds);
  FD_SET(dev->mcast_sock, &dev->rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure_sock, &dev->rfds);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  FD_SET(dev->server4_sock, &dev->rfds);
  FD_SET(dev->mcast4_sock, &dev->rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure4_sock, &dev->rfds);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
}

static adapter_receive_state_t
oc_udp_receive_message(ip_context_t *dev, fd_set *fds, oc_message_t *message)
{
  if (FD_ISSET(dev->server_sock, fds)) {
    int count = recv_msg(dev->server_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6;
    FD_CLR(dev->server_sock, fds);
    return ADAPTER_STATUS_RECEIVE;
  }

  if (FD_ISSET(dev->mcast_sock, fds)) {
    int count = recv_msg(dev->mcast_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, true);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6 | MULTICAST;
    FD_CLR(dev->mcast_sock, fds);
    return ADAPTER_STATUS_RECEIVE;
  }

#ifdef OC_IPV4
  if (FD_ISSET(dev->server4_sock, fds)) {
    int count = recv_msg(dev->server4_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4;
    FD_CLR(dev->server4_sock, fds);
    return ADAPTER_STATUS_RECEIVE;
  }

  if (FD_ISSET(dev->mcast4_sock, fds)) {
    int count = recv_msg(dev->mcast4_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, true);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | MULTICAST;
    FD_CLR(dev->mcast4_sock, fds);
    return ADAPTER_STATUS_RECEIVE;
  }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  if (FD_ISSET(dev->secure_sock, fds)) {
    int count = recv_msg(dev->secure_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6 | SECURED;
    message->encrypted = 1;
    FD_CLR(dev->secure_sock, fds);
    return ADAPTER_STATUS_RECEIVE;
  }
#ifdef OC_IPV4
  if (FD_ISSET(dev->secure4_sock, fds)) {
    int count = recv_msg(dev->secure4_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | SECURED;
    message->encrypted = 1;
    FD_CLR(dev->secure4_sock, fds);
    return ADAPTER_STATUS_RECEIVE;
  }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

  return ADAPTER_STATUS_NONE;
}

static void *
network_event_thread(void *data)
{
  ip_context_t *dev = (ip_context_t *)data;

  fd_set setfds;
  FD_ZERO(&dev->rfds);
  /* Monitor network interface changes on the platform from only the 0th logical
   * device
   */
  if (dev->device == 0) {
    FD_SET(ifchange_sock, &dev->rfds);
  }
  FD_SET(dev->shutdown_pipe[0], &dev->rfds);

  oc_udp_add_socks_to_fd_set(dev);
#ifdef OC_TCP
  oc_tcp_add_socks_to_fd_set(dev);
#endif /* OC_TCP */

  int i, n;

  while (OC_ATOMIC_LOAD8(dev->terminate) != 1) {
    setfds = ip_context_rfds_fd_copy(dev);
    n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

    if (FD_ISSET(dev->shutdown_pipe[0], &setfds)) {
      char buf;
      // write to pipe shall not block - so read the byte we wrote
      if (read(dev->shutdown_pipe[0], &buf, 1) < 0) {
        // intentionally left blank
      }
    }

    if (OC_ATOMIC_LOAD8(dev->terminate)) {
      break;
    }

    for (i = 0; i < n; i++) {
      if (dev->device == 0) {
        if (FD_ISSET(ifchange_sock, &setfds)) {
          if (process_interface_change_event() < 0) {
            OC_WRN("caught errors while handling a network interface change");
          }
          FD_CLR(ifchange_sock, &setfds);
          continue;
        }
      }

      oc_message_t *message = oc_allocate_message();

      if (!message) {
        break;
      }

      message->endpoint.device = dev->device;

      if (oc_udp_receive_message(dev, &setfds, message) ==
          ADAPTER_STATUS_RECEIVE) {
        goto common;
      }
#ifdef OC_TCP
      if (oc_tcp_receive_message(dev, &setfds, message) ==
          ADAPTER_STATUS_RECEIVE) {
        goto common;
      }
#endif /* OC_TCP */

      oc_message_unref(message);
      continue;

    common:
#ifdef OC_DEBUG
      PRINT("Incoming message of size %zd bytes from ", message->length);
      PRINTipaddr(message->endpoint);
      PRINT("\n\n");
#endif /* OC_DEBUG */

      oc_network_event(message);
    }
  }
  pthread_exit(NULL);
  return NULL;
}

static int
send_msg(int sock, struct sockaddr_storage *receiver, oc_message_t *message)
{
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))];
  struct iovec iovec[1];
  struct msghdr msg;

  memset(&msg, 0, sizeof(struct msghdr));
  msg.msg_name = (void *)receiver;
  msg.msg_namelen = sizeof(struct sockaddr_storage);

  msg.msg_iov = iovec;
  msg.msg_iovlen = 1;

  if (message->endpoint.flags & IPV6) {
    struct cmsghdr *cmsg;
    struct in6_pktinfo *pktinfo;

    msg.msg_control = msg_control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    memset(msg.msg_control, 0, msg.msg_controllen);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(struct in6_pktinfo));

    /* Get the outgoing interface index from message->endpint */
    pktinfo->ipi6_ifindex = message->endpoint.interface_index;
    /* Set the source address of this message using the address
     * from the endpoint's addr_local attribute.
     */
    memcpy(&pktinfo->ipi6_addr, message->endpoint.addr_local.ipv6.address, 16);
  }
#ifdef OC_IPV4
  else if (message->endpoint.flags & IPV4) {
    struct cmsghdr *cmsg;
    struct in_pktinfo *pktinfo;

    msg.msg_control = msg_control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
    memset(msg.msg_control, 0, msg.msg_controllen);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

    pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(struct in_pktinfo));

    pktinfo->ipi_ifindex = message->endpoint.interface_index;
    memcpy(&pktinfo->ipi_spec_dst, message->endpoint.addr_local.ipv4.address,
           4);
  }
#else  /* OC_IPV4 */
  else {
    OC_ERR("invalid endpoint");
    return -1;
  }
#endif /* !OC_IPV4 */

  int bytes_sent = 0, x;
  while (bytes_sent < (int)message->length) {
    iovec[0].iov_base = message->data + bytes_sent;
    iovec[0].iov_len = message->length - (size_t)bytes_sent;
    x = sendmsg(sock, &msg, 0);
    if (x < 0) {
      OC_WRN("sendto() returned errno %d", errno);
      break;
    }
    bytes_sent += x;
  }
  OC_DBG("Sent %d bytes", bytes_sent);

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
}

int
oc_send_buffer(oc_message_t *message)
{
#ifdef OC_DEBUG
  PRINT("Outgoing message of size %zd bytes to ", message->length);
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
  } else {
#else
  {
#endif
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receiver;
    memcpy(r->sin6_addr.s6_addr, message->endpoint.addr.ipv6.address,
           sizeof(r->sin6_addr.s6_addr));
    r->sin6_family = AF_INET6;
    r->sin6_port = htons(message->endpoint.addr.ipv6.port);
    r->sin6_scope_id = message->endpoint.addr.ipv6.scope;
  }
  int send_sock = -1;

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

  if (!dev) {
    return -1;
  }

#ifdef OC_TCP
  if (message->endpoint.flags & TCP) {
    return oc_tcp_send_buffer(dev, message, &receiver);
  }
#endif /* OC_TCP */

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

  return send_msg(send_sock, &receiver, message);
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interfaces: %d", errno);
    goto done;
  }

  memset(&message->endpoint.addr_local, 0,
         sizeof(message->endpoint.addr_local));
  message->endpoint.interface_index = 0;

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

#define IN6_IS_ADDR_MC_REALM_LOCAL(addr)                                       \
  IN6_IS_ADDR_MULTICAST(addr) && ((((const uint8_t *)(addr))[1] & 0x0f) == 0x03)

  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK))
      continue;
    if ((message->endpoint.flags & IPV6) && interface->ifa_addr &&
        interface->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)interface->ifa_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        unsigned int mif = if_nametoindex(interface->ifa_name);
        if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mif,
                       sizeof(mif)) == -1) {
          OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d",
                 errno);
          goto done;
        }
        message->endpoint.interface_index = mif;
        if (IN6_IS_ADDR_MC_LINKLOCAL(message->endpoint.addr.ipv6.address)) {
          message->endpoint.addr.ipv6.scope = mif;
          unsigned int hops = 1;
          setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                     sizeof(hops));
        } else if (IN6_IS_ADDR_MC_REALM_LOCAL(
                     message->endpoint.addr.ipv6.address)) {
          unsigned int hops = 255;
          setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                     sizeof(hops));
          message->endpoint.addr.ipv6.scope = 0;
        } else if (IN6_IS_ADDR_MC_SITELOCAL(
                     message->endpoint.addr.ipv6.address)) {
          unsigned int hops = 255;
          setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                     sizeof(hops));
          message->endpoint.addr.ipv6.scope = 0;
        }
        oc_send_buffer(message);
      }
#ifdef OC_IPV4
    } else if (message->endpoint.flags & IPV4 && interface->ifa_addr &&
               interface->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)interface->ifa_addr;
      if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_MULTICAST_IF,
                     &addr->sin_addr, sizeof(addr->sin_addr)) == -1) {
        OC_ERR("setting socket option for default IP_MULTICAST_IF: %d", errno);
        goto done;
      }
      message->endpoint.interface_index = if_nametoindex(interface->ifa_name);
      oc_send_buffer(message);
    }
#else  /* OC_IPV4 */
    }
#endif /* !OC_IPV4 */
  }
done:
#undef IN6_IS_ADDR_MC_REALM_LOCAL
  freeifaddrs(ifs);
}
#endif /* OC_CLIENT */

#ifdef OC_NETWORK_MONITOR
int
oc_add_network_interface_event_callback(interface_event_handler_t cb)
{
  if (!cb)
    return -1;

  oc_network_interface_cb_t *cb_item =
    oc_memb_alloc(&oc_network_interface_cb_s);
  if (!cb_item) {
    OC_ERR("network interface callback item alloc failed");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_network_interface_cb_list, cb_item);
  return 0;
}

int
oc_remove_network_interface_event_callback(interface_event_handler_t cb)
{
  if (!cb)
    return -1;

  oc_network_interface_cb_t *cb_item =
    oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL && cb_item->handler != cb) {
    cb_item = cb_item->next;
  }
  if (!cb_item) {
    return -1;
  }
  oc_list_remove(oc_network_interface_cb_list, cb_item);

  oc_memb_free(&oc_network_interface_cb_s, cb_item);
  return 0;
}

void
handle_network_interface_event_callback(oc_interface_event_t event)
{
  if (oc_list_length(oc_network_interface_cb_list) > 0) {
    oc_network_interface_cb_t *cb_item =
      oc_list_head(oc_network_interface_cb_list);
    while (cb_item) {
      cb_item->handler(event);
      cb_item = cb_item->next;
    }
  }
}
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SESSION_EVENTS
int
oc_add_session_event_callback(session_event_handler_t cb)
{
  if (!cb)
    return -1;

  oc_session_event_cb_t *cb_item = oc_memb_alloc(&oc_session_event_cb_s);
  if (!cb_item) {
    OC_ERR("session event callback item alloc failed");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_session_event_cb_list, cb_item);
  return 0;
}

int
oc_remove_session_event_callback(session_event_handler_t cb)
{
  if (!cb)
    return -1;

  oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list);
  while (cb_item != NULL && cb_item->handler != cb) {
    cb_item = cb_item->next;
  }
  if (!cb_item) {
    return -1;
  }
  oc_list_remove(oc_session_event_cb_list, cb_item);

  oc_memb_free(&oc_session_event_cb_s, cb_item);
  return 0;
}

void
handle_session_event_callback(const oc_endpoint_t *endpoint,
                              oc_session_state_t state)
{
  if (oc_list_length(oc_session_event_cb_list) > 0) {
    oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list);
    while (cb_item) {
      cb_item->handler(endpoint, state);
      cb_item = cb_item->next;
    }
  }
}
#endif /* OC_SESSION_EVENTS */

#ifdef OC_IPV4
static int
connectivity_ipv4_init(ip_context_t *dev)
{
  OC_DBG("Initializing IPv4 connectivity for device %zd", dev->device);
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
    OC_ERR("creating secure IPv4 socket");
    return -1;
  }
#endif /* OC_SECURITY */

  dev->server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server4_sock < 0 || dev->mcast4_sock < 0) {
    OC_ERR("creating IPv4 server sockets");
    return -1;
  }

  int on = 1;
  if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting pktinfo IPv4 option %d\n", errno);
    return -1;
  }
  if (bind(dev->server4_sock, (struct sockaddr *)&dev->server4,
           sizeof(dev->server4)) == -1) {
    OC_ERR("binding server4 socket %d", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server4);
  if (getsockname(dev->server4_sock, (struct sockaddr *)&dev->server4,
                  &socklen) == -1) {
    OC_ERR("obtaining server4 socket information %d", errno);
    return -1;
  }

  dev->port4 = ntohs(l->sin_port);

  if (configure_mcast_socket(dev->mcast4_sock, AF_INET) < 0) {
    return -1;
  }

  if (setsockopt(dev->mcast4_sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting pktinfo IPv4 option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting reuseaddr IPv4 option %d", errno);
    return -1;
  }
  if (bind(dev->mcast4_sock, (struct sockaddr *)&dev->mcast4,
           sizeof(dev->mcast4)) == -1) {
    OC_ERR("binding mcast IPv4 socket %d", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure4_sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting pktinfo IPV4 option %d\n", errno);
    return -1;
  }
  if (bind(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
           sizeof(dev->secure4)) == -1) {
    OC_ERR("binding IPv4 secure socket %d", errno);
    return -1;
  }

  socklen = sizeof(dev->secure4);
  if (getsockname(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
                  &socklen) == -1) {
    OC_ERR("obtaining DTLS4 socket information %d", errno);
    return -1;
  }

  dev->dtls4_port = ntohs(sm->sin_port);
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized IPv4 connectivity for device %zd",
         dev->device);

  return 0;
}
#endif

int
oc_connectivity_init(size_t device)
{
  OC_DBG("Initializing connectivity for device %zd", device);

  ip_context_t *dev = (ip_context_t *)oc_memb_alloc(&ip_context_s);
  if (!dev) {
    oc_abort("Insufficient memory");
  }
  oc_list_add(ip_contexts, dev);
  dev->device = device;
  OC_LIST_STRUCT_INIT(dev, eps);

  if (pthread_mutex_init(&dev->rfds_mutex, NULL) != 0) {
    oc_abort("error initializing TCP adapter mutex");
  }

  if (pipe(dev->shutdown_pipe) < 0) {
    OC_ERR("shutdown pipe: %d", errno);
    return -1;
  }
  if (set_nonblock_socket(dev->shutdown_pipe[0]) < 0) {
    OC_ERR("Could not set non-block shutdown_pipe[0]");
    return -1;
  }

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
    OC_ERR("creating server sockets");
    return -1;
  }

#ifdef OC_SECURITY
  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock < 0) {
    OC_ERR("creating secure socket");
    return -1;
  }
#endif /* OC_SECURITY */

  int on = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting sock option %d", errno);
    return -1;
  }
#ifdef IPV6_ADDR_PREFERENCES
  int prefer = 2;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, &prefer,
                 sizeof(prefer)) == -1) {
    OC_ERR("setting src addr preference %d", errno);
    return -1;
  }
#endif /* IPV6_ADDR_PREFERENCES */
  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == -1) {
    OC_ERR("binding server socket %d", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == -1) {
    OC_ERR("obtaining server socket information %d", errno);
    return -1;
  }

  dev->port = ntohs(l->sin6_port);

  if (configure_mcast_socket(dev->mcast_sock, AF_INET6) < 0) {
    return -1;
  }

  if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting reuseaddr option %d", errno);
    return -1;
  }
#ifdef IPV6_ADDR_PREFERENCES
  if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, &prefer,
                 sizeof(prefer)) == -1) {
    OC_ERR("setting src addr preference %d", errno);
    return -1;
  }
#endif /* IPV6_ADDR_PREFERENCES */
  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast,
           sizeof(dev->mcast)) == -1) {
    OC_ERR("binding mcast socket %d", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", errno);
    return -1;
  }
#ifdef IPV6_ADDR_PREFERENCES
  if (setsockopt(dev->secure_sock, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, &prefer,
                 sizeof(prefer)) == -1) {
    OC_ERR("setting src addr preference %d", errno);
    return -1;
  }
#endif /* IPV6_ADDR_PREFERENCES */
  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure,
           sizeof(dev->secure)) == -1) {
    OC_ERR("binding IPv6 secure socket %d", errno);
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure,
                  &socklen) == -1) {
    OC_ERR("obtaining secure socket information %d", errno);
    return -1;
  }

  dev->dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4");
  }
#endif /* OC_IPV4 */

  OC_DBG("=======ip port info.========");
  OC_DBG("  ipv6 port   : %u", dev->port);
#ifdef OC_SECURITY
  OC_DBG("  ipv6 secure : %u", dev->dtls_port);
#endif
#ifdef OC_IPV4
  OC_DBG("  ipv4 port   : %u", dev->port4);
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %u", dev->dtls4_port);
#endif
#endif

#ifdef OC_TCP
  if (oc_tcp_connectivity_init(dev) != 0) {
    OC_ERR("Could not initialize TCP adapter");
  }
#endif /* OC_TCP */

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
      OC_ERR("creating netlink socket to monitor network interface changes %d",
             errno);
      return -1;
    }
    if (bind(ifchange_sock, (struct sockaddr *)&ifchange_nl,
             sizeof(ifchange_nl)) == -1) {
      OC_ERR("binding netlink socket %d", errno);
      return -1;
    }
#ifdef OC_NETWORK_MONITOR
    if (!check_new_ip_interfaces()) {
      OC_ERR("checking new IP interfaces failed.");
      return -1;
    }
#endif /* OC_NETWORK_MONITOR */
    ifchange_initialized = true;
  }

  if (pthread_create(&dev->event_thread, NULL, &network_event_thread, dev) !=
      0) {
    OC_ERR("creating network polling thread");
    return -1;
  }

  OC_DBG("Successfully initialized connectivity for device %zd", device);

  return 0;
}

void
oc_connectivity_shutdown(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  OC_ATOMIC_STORE8(dev->terminate, 1);
  if (write(dev->shutdown_pipe[1], "\n", 1) < 0) {
    OC_WRN("cannot wakeup network thread");
  }

  pthread_join(dev->event_thread, NULL);

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

#ifdef OC_TCP
  oc_tcp_connectivity_shutdown(dev);
#endif /* OC_TCP */

  close(dev->shutdown_pipe[1]);
  close(dev->shutdown_pipe[0]);

  pthread_mutex_destroy(&dev->rfds_mutex);

  free_endpoints_list(dev);

  oc_list_remove(ip_contexts, dev);
  oc_memb_free(&ip_context_s, dev);

  OC_DBG("oc_connectivity_shutdown for device %zd", device);
}

#ifdef OC_TCP
void
oc_connectivity_end_session(oc_endpoint_t *endpoint)
{
  if (endpoint->flags & TCP) {
    ip_context_t *dev = get_ip_context_for_device(endpoint->device);
    if (dev) {
      oc_tcp_end_session(dev, endpoint);
    }
  }
}
#endif /* OC_TCP */

#ifdef OC_DNS_LOOKUP
#ifdef OC_DNS_CACHE
typedef struct oc_dns_cache_t
{
  struct oc_dns_cache_t *next;
  oc_string_t domain;
  union dev_addr addr;
} oc_dns_cache_t;

OC_MEMB(dns_s, oc_dns_cache_t, 1);
OC_LIST(dns_cache);

static oc_dns_cache_t *
oc_dns_lookup_cache(const char *domain)
{
  if (oc_list_length(dns_cache) == 0) {
    return NULL;
  }
  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_list_head(dns_cache);
  while (c) {
    if (strlen(domain) == oc_string_len(c->domain) &&
        memcmp(domain, oc_string(c->domain), oc_string_len(c->domain)) == 0) {
      return c;
    }
    c = c->next;
  }
  return NULL;
}

static int
oc_dns_cache_domain(const char *domain, union dev_addr *addr)
{
  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_memb_alloc(&dns_s);
  if (c) {
    oc_new_string(&c->domain, domain, strlen(domain));
    memcpy(&c->addr, addr, sizeof(union dev_addr));
    oc_list_add(dns_cache, c);
    return 0;
  }
  return -1;
}

void
oc_dns_clear_cache(void)
{
  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_list_pop(dns_cache);
  while (c) {
    oc_free_string(&c->domain);
    oc_memb_free(&dns_s, c);
    c = (oc_dns_cache_t *)oc_list_pop(dns_cache);
  }
}
#endif /* OC_DNS_CACHE */

int
oc_dns_lookup(const char *domain, oc_string_t *addr, enum transport_flags flags)
{
  if (!domain || !addr) {
    OC_ERR("Error of input parameters");
    return -1;
  }
  OC_DBG("trying to resolve address %s", domain);
  int ret = -1;
  union dev_addr a;

#ifdef OC_DNS_CACHE
  oc_dns_cache_t *c = oc_dns_lookup_cache(domain);

  if (!c) {
#endif /* OC_DNS_CACHE */
    memset(&a, 0, sizeof(union dev_addr));

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (flags & IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = (flags & TCP) ? SOCK_STREAM : SOCK_DGRAM;
    ret = getaddrinfo(domain, NULL, &hints, &result);

    if (ret == 0) {
      if (flags & IPV6) {
        struct sockaddr_in6 *r = (struct sockaddr_in6 *)result->ai_addr;
        memcpy(a.ipv6.address, r->sin6_addr.s6_addr,
               sizeof(r->sin6_addr.s6_addr));
        a.ipv6.port = ntohs(r->sin6_port);
        a.ipv6.scope = r->sin6_scope_id;
      }
#ifdef OC_IPV4
      else {
        struct sockaddr_in *r = (struct sockaddr_in *)result->ai_addr;
        memcpy(a.ipv4.address, &r->sin_addr.s_addr, sizeof(r->sin_addr.s_addr));
        a.ipv4.port = ntohs(r->sin_port);
      }
#endif /* OC_IPV4 */
#ifdef OC_DNS_CACHE
      oc_dns_cache_domain(domain, &a);
#endif /* OC_DNS_CACHE */
    } else {
      OC_ERR("failed to resolve address with error(%d): %s", ret,
             gai_strerror(ret));
    }
    freeaddrinfo(result);
#ifdef OC_DNS_CACHE
  } else {
    ret = 0;
    memcpy(&a, &c->addr, sizeof(union dev_addr));
  }
#endif /* OC_DNS_CACHE */

  if (ret == 0) {
    char address[INET6_ADDRSTRLEN + 2] = { 0 };
    const char *dest = NULL;
    if (flags & IPV6) {
      address[0] = '[';
      dest = inet_ntop(AF_INET6, (void *)a.ipv6.address, address + 1,
                       INET6_ADDRSTRLEN);
      size_t addr_len = strlen(address);
      address[addr_len] = ']';
      address[addr_len + 1] = '\0';
    }
#ifdef OC_IPV4
    else {
      dest =
        inet_ntop(AF_INET, (void *)a.ipv4.address, address, INET_ADDRSTRLEN);
    }
#endif /* OC_IPV4 */
    if (dest) {
      OC_DBG("%s address is %s", domain, address);
      oc_new_string(addr, address, strlen(address));
    } else {
      OC_ERR("failed to parse address to string: %d", (int)errno);
      ret = -1;
    }
  }

  return ret;
}
#endif /* OC_DNS_LOOKUP */

int
set_nonblock_socket(int sockfd)
{
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

void
ip_context_rfds_fd_set(ip_context_t *dev, int sockfd)
{
  pthread_mutex_lock(&dev->rfds_mutex);
  FD_SET(sockfd, &dev->rfds);
  pthread_mutex_unlock(&dev->rfds_mutex);
}

void
ip_context_rfds_fd_clr(ip_context_t *dev, int sockfd)
{
  pthread_mutex_lock(&dev->rfds_mutex);
  FD_CLR(sockfd, &dev->rfds);
  pthread_mutex_unlock(&dev->rfds_mutex);
}

fd_set
ip_context_rfds_fd_copy(ip_context_t *dev)
{
  fd_set setfds;
  pthread_mutex_lock(&dev->rfds_mutex);
  memcpy(&setfds, &dev->rfds, sizeof(dev->rfds));
  pthread_mutex_unlock(&dev->rfds_mutex);
  return setfds;
}