/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
 * Copyright (c) 2017-2018 Lynx Technology
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

#include <android/api-level.h>
#if !defined(__ANDROID_API__) || __ANDROID_API__ == 10000
#error __ANDROID_API__ not defined
#endif
#include "api/oc_endpoint_internal.h"
#include "api/oc_network_events_internal.h"
#include "ipcontext.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "port/common/posix/oc_socket_internal.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_random.h"
#include "util/oc_macros_internal.h"

#ifdef OC_NETWORK_MONITOR
#include "oc_network_monitor.h"
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SESSION_EVENTS
#include "api/oc_session_events_internal.h"
#endif /* OC_SESSION_EVENTS */

#ifdef OC_TCP
#include "tcpadapter.h"
#endif /* OC_TCP */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

#include <android/api-level.h>
#if !defined(__ANDROID_API__) || __ANDROID_API__ == 10000
#error __ANDROID_API__ not defined
#endif
#if __ANDROID_API__ >= 24
#include <ifaddrs.h>
#define OC_GETIFADDRS getifaddrs
#define OC_FREEIFADDRS freeifaddrs
#else
#include "ifaddrs-android.h"
#define OC_GETIFADDRS android_getifaddrs
#define OC_FREEIFADDRS android_freeifaddrs
#endif /* __ANDROID_API__ >= 24 */

#if __ANDROID_API__ < 30
#define OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE
#endif /* __ANDROID_API__ < 30 */

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

static pthread_mutex_t g_network_event_mutex;

#ifdef OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE
static bool g_ifchange_initialized;
struct sockaddr_nl g_ifchange_nl;
static int g_ifchange_sock;
#endif /* OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE */

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
  unsigned if_index;
} ip_interface_t;

OC_LIST(ip_interface_list);
OC_MEMB(ip_interface_s, ip_interface_t, OC_MAX_IP_INTERFACES);

OC_LIST(oc_network_interface_cb_list);
OC_MEMB(oc_network_interface_cb_s, oc_network_interface_cb_t,
        OC_MAX_NETWORK_INTERFACE_CBS);

static ip_interface_t *
get_ip_interface(unsigned target_index)
{
  ip_interface_t *if_item = oc_list_head(ip_interface_list);
  while (if_item != NULL && if_item->if_index != target_index) {
    if_item = if_item->next;
  }
  return if_item;
}

static bool
add_ip_interface(unsigned target_index)
{
  if (get_ip_interface(target_index)) {
    return false;
  }

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
  struct ifaddrs *ifs = NULL;
  if (OC_GETIFADDRS(&ifs) < 0) {
    OC_ERR("failed querying interface address");
    return false;
  }
  for (struct ifaddrs *interface = ifs; interface != NULL;
       interface = interface->ifa_next) {
    /* Ignore interfaces that are down and the loopback interface */
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }
    /* Obtain interface index for this address */
    unsigned if_index = if_nametoindex(interface->ifa_name);
    if (if_index == 0) {
      OC_ERR("failed obtaining interface(%s) index", interface->ifa_name);
      continue;
    }
    add_ip_interface(if_index);
  }
  OC_FREEIFADDRS(ifs);

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

#define OCF_IF_FLAGS (IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST)

void
oc_network_event_handler_mutex_init(void)
{
  if (pthread_mutex_init(&g_network_event_mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex");
  }
}

void
oc_network_event_handler_mutex_lock(void)
{
  pthread_mutex_lock(&g_network_event_mutex);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  pthread_mutex_unlock(&g_network_event_mutex);
}

void
oc_network_event_handler_mutex_destroy(void)
{
#ifdef OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE
  g_ifchange_initialized = false;
  close(g_ifchange_sock);
#ifdef OC_NETWORK_MONITOR
  remove_all_ip_interface();
  remove_all_network_interface_cbs();
#endif /* OC_NETWORK_MONITOR */
#endif /* OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE */
#ifdef OC_SESSION_EVENTS
  oc_session_events_remove_all_callbacks();
#endif /* OC_SESSION_EVENTS */
  pthread_mutex_destroy(&g_network_event_mutex);
}

static ip_context_t *
get_ip_context_for_device(size_t device)
{
  ip_context_t *dev = oc_list_head(ip_contexts);
  while (dev != NULL && dev->device != device) {
    dev = dev->next;
  }
  return dev;
}

#ifdef OC_IPV4
static int
add_mcast_sock_to_ipv4_mcast_group(int mcast_sock, const struct in_addr *local,
                                   unsigned iface_index)
{
  struct ip_mreqn mreq;

  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
  mreq.imr_ifindex = (int)iface_index;
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
add_mcast_sock_to_ipv6_mcast_group(int mcast_sock, unsigned if_index)
{
  struct ipv6_mreq mreq;

  /* Link-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_LL, 16);
  mreq.ipv6mr_interface = if_index;

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
  mreq.ipv6mr_interface = if_index;

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
  mreq.ipv6mr_interface = if_index;

  (void)setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq,
                   sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining site-local IPv6 multicast group %d", errno);
    return -1;
  }

  return 0;
}

static int
configure_mcast_socket(int mcast_sock, int sa_family)
{
  int ret = 0;
  struct ifaddrs *ifs = NULL;
  if (OC_GETIFADDRS(&ifs) < 0) {
    OC_ERR("failed querying interface addrs");
    return -1;
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
    unsigned if_index = if_nametoindex(interface->ifa_name);
    if (if_index == 0) {
      OC_ERR("failed obtaining interface(%s) index", interface->ifa_name);
      continue;
    }

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
  OC_FREEIFADDRS(ifs);

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

  long prev_interface_index = -1;
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

    CLANG_IGNORE_WARNING_START
    CLANG_IGNORE_WARNING("-Wsign-compare")
    while (NLMSG_OK(response, response_len)) {
      CLANG_IGNORE_WARNING_END
      if (response->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }
      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      bool include = false;
      struct ifaddrmsg *addrmsg = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (addrmsg->ifa_scope < RT_SCOPE_HOST) {
        if ((long)addrmsg->ifa_index == prev_interface_index) {
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

  if (oc_list_length(dev->eps) == 0) {
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev);
    oc_network_event_handler_mutex_unlock();
  }

  return oc_list_head(dev->eps);
}

#ifdef OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE

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
    response_len = recv(g_ifchange_sock, dummy, guess, MSG_PEEK);
    if (response_len < 0) {
      OC_ERR("reading payload size from netlink interface");
      return -1;
    }
  } while (response_len == guess);

  uint8_t buffer[response_len];
  response_len = recv(g_ifchange_sock, buffer, response_len, 0);
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

  CLANG_IGNORE_WARNING_START
  CLANG_IGNORE_WARNING("-Wsign-compare")
  while (NLMSG_OK(response, response_len)) {
    CLANG_IGNORE_WARNING_END
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
      oc_network_event_handler_mutex_lock();
      refresh_endpoints_list(dev);
      oc_network_event_handler_mutex_unlock();
    }
  }

  return ret;
}

#endif /* OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE */

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

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != 0;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
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
      endpoint->interface_index = (unsigned)pktinfo->ipi_ifindex;
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

#ifdef OC_DYNAMIC_ALLOCATION
static bool
fd_sets_are_equal(const fd_set *fd1, const fd_set *fd2)
{
  return (memcmp(fd1->fds_bits, fd2->fds_bits, sizeof(fd1->fds_bits)) == 0);
}

static int
fds_max(const fd_set *sourcefds)
{
  int max_fd = 0;
  for (int i = 0; i < FD_SETSIZE; i++) {
    if (FD_ISSET(i, sourcefds)) {
      max_fd = i;
    }
  }
  return max_fd;
}

static int
fds_count(const fd_set *sourcefds, int max_fd)
{
  int rfd_count = 0;
  for (int i = 0; i <= max_fd; i++) {
    if (FD_ISSET(i, sourcefds)) {
      rfd_count++;
    }
  }
  return rfd_count;
}

static int
pick_random_fd(const fd_set *sourcefds, int fd_count, int max_fd)
{
  assert(fd_count > 0);
  // get random number representing the position of descriptor in the fd_set
  int random_pos = (int)(oc_random_value() % fd_count);
  for (int i = 0, fd_pos = 0; i <= max_fd; i++) {
    if (FD_ISSET(i, sourcefds)) {
      if (random_pos == fd_pos) {
        return i;
      }
      // advance to the position
      fd_pos++;
    }
  }
  return -1;
}

static int
remove_random_fds(fd_set *rdfds, int rfds_count, int max_fd, int remove_count)
{
  int removed = 0;
  while (removed < remove_count) {
    int fd = pick_random_fd(rdfds, rfds_count, max_fd);
    if (fd < 0) {
      break;
    }
    // remove file descriptor from the set
    FD_CLR(fd, rdfds);
    --rfds_count;
    ++removed;
  }
  return removed;
}
#endif /* OC_DYNAMIC_ALLOCATION */

static void
add_control_flow_rfds(fd_set *output_set, const ip_context_t *dev)
{
#ifdef OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE
  /* Monitor network interface changes on the platform from only the 0th
   * logical device
   */
  if (dev->device == 0) {
    FD_SET(g_ifchange_sock, output_set);
  }
#endif /* OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE */
  FD_SET(dev->wakeup_pipe[0], output_set);
}

static void
udp_add_socks_to_rfd_set(ip_context_t *dev)
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

static bool
process_wakeup_signal(ip_context_t *dev, fd_set *fds)
{
  if (FD_ISSET(dev->wakeup_pipe[0], fds)) {
    FD_CLR(dev->wakeup_pipe[0], fds);
    ssize_t len;
    do {
      char buf;
      // write to pipe shall not block - so read the byte we wrote
      len = read(dev->wakeup_pipe[0], &buf, 1);
    } while (len < 0 && errno == EINTR);
    return true;
  }
  return false;
}

static int
process_socket_read_event(ip_context_t *dev, fd_set *rdfds)
{
  oc_message_t *message = oc_allocate_message();
  if (message == NULL) {
    return -1;
  }
  message->endpoint.device = dev->device;

  if (FD_ISSET(dev->server_sock, rdfds)) {
    FD_CLR(dev->server_sock, rdfds);
    int count = recv_msg(dev->server_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      oc_message_unref(message);
      return 0;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6;
    goto receive;
  }

  if (FD_ISSET(dev->mcast_sock, rdfds)) {
    FD_CLR(dev->mcast_sock, rdfds);
    int count = recv_msg(dev->mcast_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, true);
    if (count < 0) {
      oc_message_unref(message);
      return 0;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6 | MULTICAST;
    goto receive;
  }

#ifdef OC_IPV4
  if (FD_ISSET(dev->server4_sock, rdfds)) {
    FD_CLR(dev->server4_sock, rdfds);
    int count = recv_msg(dev->server4_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      oc_message_unref(message);
      return 0;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4;
    goto receive;
  }

  if (FD_ISSET(dev->mcast4_sock, rdfds)) {
    FD_CLR(dev->mcast4_sock, rdfds);
    int count = recv_msg(dev->mcast4_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, true);
    if (count < 0) {
      oc_message_unref(message);
      return 0;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | MULTICAST;
    goto receive;
  }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  if (FD_ISSET(dev->secure_sock, rdfds)) {
    FD_CLR(dev->secure_sock, rdfds);
    int count = recv_msg(dev->secure_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      oc_message_unref(message);
      return 0;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6 | SECURED;
    message->encrypted = 1;
    goto receive;
  }
#ifdef OC_IPV4
  if (FD_ISSET(dev->secure4_sock, rdfds)) {
    FD_CLR(dev->secure4_sock, rdfds);
    int count = recv_msg(dev->secure4_sock, message->data, OC_PDU_SIZE,
                         &message->endpoint, false);
    if (count < 0) {
      oc_message_unref(message);
      return 0;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | SECURED;
    message->encrypted = 1;
    goto receive;
  }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

#ifdef OC_TCP
  adapter_receive_state_t tcp_status =
    oc_tcp_receive_message(dev, rdfds, message);
  if (tcp_status == ADAPTER_STATUS_RECEIVE) {
    goto receive;
  }
#endif /* OC_TCP */

  oc_message_unref(message);
  return 0;

receive:
  OC_TRACE("Incoming message of size %zd bytes from", message->length);
  OC_LOGipaddr(OC_LOG_LEVEL_TRACE, message->endpoint);
  OC_TRACE("%s", "");
  oc_network_receive_event(message);
  return 1;
}

static int
process_event(ip_context_t *dev, fd_set *rdfds, fd_set *wfds)
{
  if (rdfds != NULL) {
    int ret = process_socket_read_event(dev, rdfds);
    if (ret != 0) {
      return ret;
    }
  }

#if OC_DBG_IS_ENABLED
  // GCOVR_EXCL_START
  if (rdfds != NULL) {
    for (int i = 0; i < FD_SETSIZE; ++i) {
      if (FD_ISSET(i, rdfds)) {
        OC_DBG("no handler found for read event (fd=%d)", i);
      }
    }
  }
  if (wfds != NULL) {
    for (int i = 0; i < FD_SETSIZE; ++i) {
      if (FD_ISSET(i, wfds)) {
        OC_DBG("no handler found for write event (fd=%d)", i);
      }
    }
  }
  // GCOVR_EXCL_STOP
#else  /* !OC_DBG_IS_ENABLED */
  (void)wfds;
#endif /* OC_DBG_IS_ENABLED */
  return 0;
}

static void
process_events(ip_context_t *dev, fd_set *rdfds, fd_set *wfds, int fd_count,
               int max_read_fd)
{
  if (fd_count == 0) {
    OC_TRACE("process_events: timeout");
    return;
  }

  OC_TRACE("processing %d events", fd_count);

  // process control flow events
  if (process_wakeup_signal(dev, rdfds)) {
    fd_count--;
  }

#ifdef OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE
  if ((dev->device == 0) && (FD_ISSET(g_ifchange_sock, rdfds))) {
    OC_DBG("interface change processed on (fd=%d)", g_ifchange_sock);
    FD_CLR(g_ifchange_sock, rdfds);
    if (process_interface_change_event() < 0) {
      OC_WRN("caught errors while handling a network interface change");
    }
    fd_count--;
  }
#endif /* OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE */

  // if (process_socket_signal_event(dev, rdfds)) {
  //   fd_count--;
  // }

#ifdef OC_DYNAMIC_ALLOCATION
  // check if network queue can consume all 'ready' events
  int available_count = OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS -
                        (int)oc_network_get_event_queue_length(dev->device);
  if (available_count < fd_count) {
    // get the number of read file descriptors
    int rfds_count = fds_count(rdfds, max_read_fd);
    int removed = remove_random_fds(rdfds, rfds_count, max_read_fd,
                                    rfds_count - available_count);
    fd_count -= removed;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  (void)max_read_fd;
#endif /* OC_DYNAMIC_ALLOCATION */

  for (int i = 0; i < fd_count; i++) {
    if (process_event(dev, rdfds, wfds) < 0) {
      break;
    }
  }
}

static void *
network_event_thread(void *data)
{
  ip_context_t *dev = (ip_context_t *)data;
  FD_ZERO(&dev->rfds);

  udp_add_socks_to_rfd_set(dev);
  add_control_flow_rfds(&dev->rfds, dev);
#ifdef OC_TCP
  oc_tcp_add_socks_to_fd_set(dev);
  oc_tcp_add_controlflow_socks_to_rfd_set(&dev->rfds, dev);
#endif /* OC_TCP */

  int max_read_fd = FD_SETSIZE;
  fd_set last_rdfds;
  FD_ZERO(&last_rdfds);

  while (dev->terminate != 1) {
    fd_set rdfds = dev->rfds;

#ifdef OC_DYNAMIC_ALLOCATION
    if (!fd_sets_are_equal(&rdfds, &last_rdfds)) {
      // fd set has changed -> recalculate max fd
      max_read_fd = fds_max(&rdfds);
      last_rdfds = rdfds;
    }

    if (oc_network_get_event_queue_length(dev->device) >=
        OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS) {
      // the queue is full -> add only control flow rfds
      FD_ZERO(&rdfds);
      add_control_flow_rfds(&rdfds, dev);
#ifdef OC_TCP
      oc_tcp_add_controlflow_socks_to_rfd_set(&rdfds, dev);
#endif /* OC_TCP */
    }
#endif /* OC_DYNAMIC_ALLOCATION */

    int n = select(FD_SETSIZE, &rdfds, NULL, NULL, NULL);

    if (dev->terminate) {
      break;
    }

    process_events(dev, &rdfds, NULL, n, max_read_fd);
  }
  pthread_exit(NULL);
  return NULL;
}

int
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

    pktinfo->ipi_ifindex = (int)message->endpoint.interface_index;
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
  OC_TRACE("Sent %zd bytes", bytes_sent);

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
}

int
oc_send_buffer(oc_message_t *message)
{
  OC_TRACE("Outgoing message of size %zd bytes to", message->length);
  OC_LOGipaddr(OC_LOG_LEVEL_TRACE, message->endpoint);
  OC_TRACE("%s", "");

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);
  if (dev == NULL) {
    return -1;
  }

  struct sockaddr_storage receiver = oc_socket_get_address(&message->endpoint);

#ifdef OC_TCP
  if (message->endpoint.flags & TCP) {
    return oc_tcp_send_buffer(dev, message, &receiver);
  }
#endif /* OC_TCP */

  int send_sock = -1;
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

int
oc_send_buffer2(oc_message_t *message, bool queue)
{
  (void)queue;
  return oc_send_buffer(message);
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  struct ifaddrs *ifs = NULL;
  if (OC_GETIFADDRS(&ifs) < 0) {
    OC_ERR("querying interfaces: %d", errno);
    goto done;
  }

  memset(&message->endpoint.addr_local, 0,
         sizeof(message->endpoint.addr_local));
  message->endpoint.interface_index = 0;

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

#define IN6_IS_ADDR_MC_REALM_LOCAL(addr)                                       \
  IN6_IS_ADDR_MULTICAST(addr) &&                                               \
    ((((const uint8_t *)(addr))[1] & 0x0f) == OC_IPV6_ADDR_SCOPE_REALM_LOCAL)

  for (struct ifaddrs *interface = ifs; interface != NULL;
       interface = interface->ifa_next) {
    /* Only broadcast on LAN/WLAN. 3G/4G/5G should not have the broadcast
       and multicast flags set. */
    if ((interface->ifa_flags & (OCF_IF_FLAGS | IFF_LOOPBACK)) !=
        OCF_IF_FLAGS) {
      OC_DBG("skipping %s",
             (interface->ifa_name ? interface->ifa_name : "<none>"));
      continue;
    }
    if ((message->endpoint.flags & IPV6) && interface->ifa_addr &&
        interface->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)interface->ifa_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        unsigned mif = if_nametoindex(interface->ifa_name);
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
  OC_FREEIFADDRS(ifs);
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
  if (setsockopt(dev->server4_sock, SOL_SOCKET, SO_REUSEADDR, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting reuseaddr option %d", errno);
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
  if (setsockopt(dev->secure4_sock, SOL_SOCKET, SO_REUSEADDR, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d", errno);
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
oc_connectivity_init(size_t device, oc_connectivity_ports_t ports)
{
  // TODO set ports
  (void)ports;
  OC_DBG("Initializing connectivity for device %zd", device);

  ip_context_t *dev = (ip_context_t *)oc_memb_alloc(&ip_context_s);
  if (!dev) {
    oc_abort("Insufficient memory");
  }
  oc_list_add(ip_contexts, dev);
  dev->device = device;
  OC_LIST_STRUCT_INIT(dev, eps);

  if (pipe(dev->wakeup_pipe) < 0) {
    OC_ERR("wakeup pipe: %d", errno);
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
  if (setsockopt(dev->server_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting reuseaddr option %d", errno);
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
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting reuseaddr option %d", errno);
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

#ifdef OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE
  /* Netlink socket to listen for network interface changes.
   * Only initialized once, and change events are captured by only
   * the network event thread for the 0th logical device.
   */
  if (!g_ifchange_initialized) {
    memset(&g_ifchange_nl, 0, sizeof(struct sockaddr_nl));
    g_ifchange_nl.nl_family = AF_NETLINK;
    g_ifchange_nl.nl_groups =
      RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    g_ifchange_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (g_ifchange_sock < 0) {
      OC_ERR("creating netlink socket to monitor network interface changes %d",
             errno);
      return -1;
    }
    if (bind(g_ifchange_sock, (struct sockaddr *)&g_ifchange_nl,
             sizeof(g_ifchange_nl)) == -1) {
      OC_ERR("binding netlink socket %d", errno);
      return -1;
    }
#ifdef OC_NETWORK_MONITOR
    if (!check_new_ip_interfaces()) {
      OC_ERR("checking new IP interfaces failed.");
      return -1;
    }
#endif /* OC_NETWORK_MONITOR */
    g_ifchange_initialized = true;
  }
#endif /* OC_NETLINK_IF_CHANGE_NOTIFICATIONS_AVAILABLE */

  if (pthread_create(&dev->event_thread, NULL, &network_event_thread, dev) !=
      0) {
    OC_ERR("creating network polling thread");
    return -1;
  }

  OC_DBG("Successfully initialized connectivity for device %zd", device);

  return 0;
}

static void
signal_event_thread(const ip_context_t *dev)
{
  ssize_t result;
  do {
    result = write(dev->wakeup_pipe[1], "\n", 1);
  } while (result == -1 && errno == EINTR);

  if (result == -1) {
    if (errno != ENOSPC) {
      OC_WRN("Failed to wakeup the network thread. Error %d", errno);
    }
    // ENOSPC is ignored as the pipe is already signaled
  } else if (result != 1) {
    OC_WRN("Unexpected number of bytes written to wakeup pipe: %zd", result);
  }
}

#ifdef OC_DYNAMIC_ALLOCATION
void
oc_connectivity_wakeup(size_t device)
{
  const ip_context_t *dev = get_ip_context_for_device(device);
  if (dev == NULL) {
    OC_WRN("no ip-context found for device(%zu)", device);
    return;
  }

  signal_event_thread(dev);
}
#endif /* OC_DYNAMIC_ALLOCATION */

void
oc_connectivity_shutdown(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  if (dev == NULL) {
    OC_WRN("no ip-context found for device(%zu)", device);
    return;
  }

  dev->terminate = 1;
  signal_event_thread(dev);

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

  close(dev->wakeup_pipe[1]);
  close(dev->wakeup_pipe[0]);

  free_endpoints_list(dev);

  oc_list_remove(ip_contexts, dev);
  oc_memb_free(&ip_context_s, dev);

  OC_DBG("oc_connectivity_shutdown for device %zd", device);
}

#ifdef OC_TCP
void
oc_connectivity_end_session(const oc_endpoint_t *endpoint)
{
  while (oc_connectivity_end_session_v1(endpoint, true, NULL)) {
    // no-op
  }
}

bool
oc_connectivity_end_session_v1(const oc_endpoint_t *endpoint,
                               bool notify_session_end,
                               oc_endpoint_t *session_endpoint)
{
  if (endpoint->flags & TCP) {
    ip_context_t *dev = get_ip_context_for_device(endpoint->device);
    if (dev) {
      return oc_tcp_end_session(dev, endpoint, notify_session_end,
                                session_endpoint);
    }
  }
  return false;
}
#endif /* OC_TCP */

#ifdef OC_DNS_LOOKUP
int
oc_dns_lookup(const char *domain, oc_string_t *addr, transport_flags flags)
{
  if (!domain || !addr) {
    OC_ERR("Error of input parameters");
    return -1;
  }

  struct addrinfo hints, *result = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = (flags & IPV6) ? AF_INET6 : AF_INET;
  hints.ai_socktype = (flags & TCP) ? SOCK_STREAM : SOCK_DGRAM;
  int ret = getaddrinfo(domain, NULL, &hints, &result);

  if (ret == 0) {
    char address[NI_MAXHOST];
    ret = getnameinfo(result->ai_addr, result->ai_addrlen, address,
                      sizeof(address), NULL, 0, 0);
    if (ret == 0) {
      char address[INET6_ADDRSTRLEN + 2] = { 0 };
      const char *dest = NULL;
      if (flags & IPV6) {
        struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *)result->ai_addr;
        address[0] = '[';
        dest = inet_ntop(AF_INET6, (void *)&s_addr->sin6_addr, address + 1,
                         INET6_ADDRSTRLEN);
        size_t addr_len = strlen(address);
        address[addr_len] = ']';
        address[addr_len + 1] = '\0';
      }
#ifdef OC_IPV4
      else {
        struct sockaddr_in *s_addr = (struct sockaddr_in *)result->ai_addr;
        dest = inet_ntop(AF_INET, (void *)&s_addr->sin_addr, address,
                         INET_ADDRSTRLEN);
      }
#endif /* OC_IPV4 */
      if (dest) {
        OC_DBG("%s address is %s", domain, address);
        oc_new_string(addr, address, strlen(address));
      } else {
        ret = -1;
      }
      freeaddrinfo(result);
    } else {
      OC_ERR("failed to resolve address(%s) with error(%d): %s", domain, ret,
             gai_strerror(ret));
    }
  }

  return ret;
}
#endif /* OC_DNS_LOOKUP */
