/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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

#include "api/oc_endpoint_internal.h"
#include "api/oc_network_events_internal.h"
#include "api/oc_message_internal.h"
#include "ip.h"
#include "ipadapter.h"
#include "ipcontext.h"
#include "netsocket.h"
#include "oc_config.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "port/common/posix/oc_socket_internal.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_fcntl_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_random.h"
#include "util/oc_atomic.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"

#ifdef OC_SESSION_EVENTS
#include "api/oc_session_events_internal.h"
#endif /* OC_SESSION_EVENTS */

#ifdef OC_TCP
#include "tcpadapter.h"
#include "tcpcontext.h"
#include "tcpsession.h"
#endif /* OC_TCP */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
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
#endif /* !IFA_FLAGS */

#define OCF_PORT_UNSECURED (5683)

static pthread_mutex_t g_mutex;
struct sockaddr_nl g_ifchange_nl;
static int g_ifchange_sock;
static bool g_ifchange_initialized;

OC_LIST(g_ip_contexts);
OC_MEMB(g_ip_context_s, ip_context_t, OC_MAX_NUM_DEVICES);

OC_MEMB(g_device_eps, oc_endpoint_t, 8 * OC_MAX_NUM_DEVICES); // fix

#ifdef OC_NETWORK_MONITOR
/**
 * Structure to manage interface list.
 */
typedef struct ip_interface
{
  struct ip_interface *next;
  unsigned if_index;
} ip_interface_t;

OC_LIST(g_ip_interface_list);
OC_MEMB(g_ip_interface_s, ip_interface_t, OC_MAX_IP_INTERFACES);

OC_LIST(oc_network_interface_cb_list);
OC_MEMB(oc_network_interface_cb_s, oc_network_interface_cb_t,
        OC_MAX_NETWORK_INTERFACE_CBS);

static ip_interface_t *
get_ip_interface(unsigned target_index)
{
  ip_interface_t *if_item = oc_list_head(g_ip_interface_list);
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

  ip_interface_t *new_if = oc_memb_alloc(&g_ip_interface_s);
  if (new_if == NULL) {
    OC_ERR("interface item alloc failed");
    return false;
  }
  new_if->if_index = target_index;
  oc_list_add(g_ip_interface_list, new_if);
  OC_DBG("New interface added: %d", new_if->if_index);
  return true;
}

static bool
check_new_ip_interfaces(void)
{
  struct ifaddrs *ifs = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("failed querying interface address");
    return false;
  }
  for (struct ifaddrs *interface = ifs; interface != NULL;
       interface = interface->ifa_next) {
    /* Ignore interfaces that are down and the loopback interface */
    if ((interface->ifa_flags & IFF_UP) == 0 ||
        (interface->ifa_flags & IFF_LOOPBACK) != 0) {
      continue;
    }
    /* Obtain interface index for this address */
    unsigned if_index = if_nametoindex(interface->ifa_name);
    if (if_index == 0) {
      OC_ERR("failed obtaining interface(%s) index: %d", interface->ifa_name,
             (int)errno);
      continue;
    }

    add_ip_interface(if_index);
  }
  freeifaddrs(ifs);
  return true;
}

static bool
remove_ip_interface(unsigned target_index)
{
  ip_interface_t *if_item = get_ip_interface(target_index);
  if (!if_item) {
    return false;
  }

  oc_list_remove(g_ip_interface_list, if_item);
  oc_memb_free(&g_ip_interface_s, if_item);
  OC_DBG("Removed from ip interface list: %d", target_index);
  return true;
}

static void
remove_all_ip_interface(void)
{
  ip_interface_t *if_item = oc_list_head(g_ip_interface_list);
  while (if_item != NULL) {
    ip_interface_t *next = if_item->next;
    oc_list_remove(g_ip_interface_list, if_item);
    oc_memb_free(&g_ip_interface_s, if_item);
    if_item = next;
  }
}

static void
remove_all_network_interface_cbs(void)
{
  oc_network_interface_cb_t *cb_item =
    oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL) {
    oc_network_interface_cb_t *next = cb_item->next;
    oc_list_remove(oc_network_interface_cb_list, cb_item);
    oc_memb_free(&oc_network_interface_cb_s, cb_item);
    cb_item = next;
  }
}
#endif /* OC_NETWORK_MONITOR */

void
oc_network_event_handler_mutex_init(void)
{
  if (pthread_mutex_init(&g_mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex");
  }
}

void
oc_network_event_handler_mutex_lock(void)
{
  pthread_mutex_lock(&g_mutex);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  pthread_mutex_unlock(&g_mutex);
}

void
oc_network_event_handler_mutex_destroy(void)
{
  g_ifchange_initialized = false;
  close(g_ifchange_sock);
#ifdef OC_NETWORK_MONITOR
  remove_all_ip_interface();
  remove_all_network_interface_cbs();
#endif /* OC_NETWORK_MONITOR */
#ifdef OC_SESSION_EVENTS
  oc_session_events_remove_all_callbacks();
#endif /* OC_SESSION_EVENTS */
  pthread_mutex_destroy(&g_mutex);
}

ip_context_t *
oc_get_ip_context_for_device(size_t device)
{
  pthread_mutex_lock(&g_mutex);
  ip_context_t *dev = oc_list_head(g_ip_contexts);
  while (dev != NULL && dev->device != device) {
    dev = dev->next;
  }
  pthread_mutex_unlock(&g_mutex);
  return dev;
}

static ssize_t
get_data(int sock, uint8_t *buffer, size_t buffer_size)
{
  ssize_t response_len;
  do {
    response_len = recv(sock, buffer, buffer_size, 0);
    if (response_len < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -errno;
    }
    break;
  } while (true);
  return response_len;
}

static bool
get_interface_addresses(ip_context_t *dev, unsigned char family, int port,
                        bool secure, bool tcp)
{
  if (port < 0) {
    return true;
  }
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
    return false;
  }

  do {
    if (send(nl_sock, &request, request.nlhdr.nlmsg_len, 0) < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(nl_sock);
      return false;
    }
    break;
  } while (true);

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(nl_sock, &rfds);

  if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) < 0) {
    close(nl_sock);
    return false;
  }

  long prev_interface_index = -1;
  bool done = false;
  // message used to read data from netlink socket
  oc_message_t *message = oc_allocate_message();
  if (!message) {
    close(nl_sock);
    return false;
  }
  while (!done) {
    ssize_t response_len =
      get_data(nl_sock, message->data, oc_message_buffer_size(message));
    if (response_len < 0) {
      OC_ERR("failed to get data (error %d)", (int)-response_len);
      close(nl_sock);
      oc_message_unref(message);
      return false;
    }
    CLANG_IGNORE_WARNING_START
    CLANG_IGNORE_WARNING("-Wcast-align")
    response = (struct nlmsghdr *)message->data;
    CLANG_IGNORE_WARNING_END
    if (response->nlmsg_type == NLMSG_ERROR) {
      close(nl_sock);
      oc_message_unref(message);
      return false;
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
        if ((long)addrmsg->ifa_index == prev_interface_index) {
          goto next_ifaddr;
        }
        ep.interface_index = addrmsg->ifa_index;
        include = true;
        CLANG_IGNORE_WARNING_START
        CLANG_IGNORE_WARNING("-Wcast-align")
        struct rtattr *attr = IFA_RTA(addrmsg);
        CLANG_IGNORE_WARNING_END
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
          CLANG_IGNORE_WARNING_START
          CLANG_IGNORE_WARNING("-Wcast-align")
          attr = RTA_NEXT(attr, att_len);
          CLANG_IGNORE_WARNING_END
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
          ep.addr.ipv4.port = (uint16_t)port;
        } else
#endif /* OC_IPV4 */
          if (family == AF_INET6) {
            ep.addr.ipv6.port = (uint16_t)port;
          }
#ifdef OC_TCP
        if (tcp) {
          ep.flags |= TCP;
        }
#else  /* !OC_TCP */
        (void)tcp;
#endif /* OC_TCP */
        oc_endpoint_t *new_ep = oc_memb_alloc(&g_device_eps);
        if (!new_ep) {
          oc_message_unref(message);
          close(nl_sock);
          return false;
        }
        memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
        oc_list_add(dev->eps, new_ep);
      }

    next_ifaddr:
      CLANG_IGNORE_WARNING_START
      CLANG_IGNORE_WARNING("-Wcast-align")
      response = NLMSG_NEXT(response, response_len);
      CLANG_IGNORE_WARNING_END
    }
  }
  close(nl_sock);
  oc_message_unref(message);
  return true;
}

static void
free_endpoints_list(ip_context_t *dev)
{
  oc_endpoint_t *ep = oc_list_pop(dev->eps);

  while (ep != NULL) {
    oc_memb_free(&g_device_eps, ep);
    ep = oc_list_pop(dev->eps);
  }
}

static void
refresh_endpoints_list(ip_context_t *dev)
{
  free_endpoints_list(dev);

  if (!get_interface_addresses(
        dev, AF_INET6, oc_sock_listener_get_port(&dev->server), false, false)) {
    OC_ERR("failed to refresh endpoints for ipv6 interface with port:%d",
           oc_sock_listener_get_port(&dev->server));
  }
#ifdef OC_SECURITY
  if (!get_interface_addresses(
        dev, AF_INET6, oc_sock_listener_get_port(&dev->secure), true, false)) {
    OC_ERR("failed to refresh endpoints for secure ipv6 interface with port:%d",
           oc_sock_listener_get_port(&dev->secure));
  }
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  if (!get_interface_addresses(
        dev, AF_INET, oc_sock_listener_get_port(&dev->server4), false, false)) {
    OC_ERR("failed to refresh endpoints for ipv4 interface with port:%d",
           oc_sock_listener_get_port(&dev->server4));
  }
#ifdef OC_SECURITY
  if (!get_interface_addresses(
        dev, AF_INET, oc_sock_listener_get_port(&dev->secure4), true, false)) {
    OC_ERR("failed to refresh endpoints for secure ipv4 interface with port:%d",
           oc_sock_listener_get_port(&dev->secure4));
  }
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */

#ifdef OC_TCP
  if (!get_interface_addresses(dev, AF_INET6,
                               oc_sock_listener_get_port(&dev->tcp.server),
                               false, true)) {
    OC_ERR("failed to refresh endpoints for ipv6 interface (TCP) with port:%d",
           oc_sock_listener_get_port(&dev->tcp.server));
  }
#ifdef OC_SECURITY
  if (!get_interface_addresses(dev, AF_INET6,
                               oc_sock_listener_get_port(&dev->tcp.secure),
                               true, true)) {
    OC_ERR("failed to refresh endpoints for secure ipv6 interface (TCP) with "
           "port:%d",
           oc_sock_listener_get_port(&dev->tcp.secure));
  }
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  if (!get_interface_addresses(dev, AF_INET,
                               oc_sock_listener_get_port(&dev->tcp.server4),
                               false, true)) {
    OC_ERR("failed to refresh endpoints for ipv4 interface (TCP) with port:%d",
           oc_sock_listener_get_port(&dev->tcp.server4));
  }
#ifdef OC_SECURITY
  if (!get_interface_addresses(dev, AF_INET,
                               oc_sock_listener_get_port(&dev->tcp.secure4),
                               true, true)) {
    OC_ERR("failed to refresh endpoints for secure ipv4 interface (TCP) with "
           "port:%d",
           oc_sock_listener_get_port(&dev->tcp.secure4));
  }
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#endif /* OC_TCP */
}

oc_endpoint_t *
oc_connectivity_get_endpoints(size_t device)
{
  ip_context_t *dev = oc_get_ip_context_for_device(device);
  if (dev == NULL) {
    return NULL;
  }

  bool refresh = false;
  bool swapped = false;
  int8_t expected = OC_ATOMIC_LOAD8(dev->flags);
  while ((expected & IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST) != 0) {
    int8_t desired =
      (int8_t)(expected & ~IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST);
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
  oc_message_t *message = oc_allocate_message();
  if (!message) {
    return -1;
  }
  ssize_t response_len =
    get_data(g_ifchange_sock, message->data, oc_message_buffer_size(message));
  if (response_len < 0) {
    OC_ERR("failed reading payload from netlink interface (error %d)",
           (int)-response_len);
    oc_message_unref(message);
    return -1;
  }
  CLANG_IGNORE_WARNING_START
  CLANG_IGNORE_WARNING("-Wcast-align")
  struct nlmsghdr *response = (struct nlmsghdr *)message->data;
  CLANG_IGNORE_WARNING_END
  if (response->nlmsg_type == NLMSG_ERROR) {
    OC_ERR("caught NLMSG_ERROR in payload from netlink interface");
    oc_message_unref(message);
    return -1;
  }

  bool success = true;
  size_t num_devices = oc_core_get_num_devices();
  bool if_state_changed = false;
  while (NLMSG_OK(response, response_len)) {
    if (response->nlmsg_type == RTM_NEWADDR) {
      const struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (ifa) {
#ifdef OC_NETWORK_MONITOR
        if (add_ip_interface(ifa->ifa_index)) {
          oc_network_interface_event(NETWORK_INTERFACE_UP);
        }
#endif /* OC_NETWORK_MONITOR */
        CLANG_IGNORE_WARNING_START
        CLANG_IGNORE_WARNING("-Wcast-align")
        struct rtattr *attr = IFA_RTA(ifa);
        CLANG_IGNORE_WARNING_END
        int att_len = IFA_PAYLOAD(response);
        while (RTA_OK(attr, att_len)) {
          if (attr->rta_type == IFA_ADDRESS) {
#ifdef OC_IPV4
            if (ifa->ifa_family == AF_INET) {
              for (size_t i = 0; i < num_devices; i++) {
                const ip_context_t *dev = oc_get_ip_context_for_device(i);
                if (dev == NULL) {
                  continue;
                }
                if (dev->mcast4_sock < 0) {
                  continue;
                }
                success = oc_netsocket_add_sock_to_ipv4_mcast_group(
                            dev->mcast4_sock, RTA_DATA(attr), ifa->ifa_index) &&
                          success;
              }
            } else
#endif /* OC_IPV4 */
              if (ifa->ifa_family == AF_INET6 &&
                  ifa->ifa_scope == RT_SCOPE_LINK) {
                for (size_t i = 0; i < num_devices; i++) {
                  const ip_context_t *dev = oc_get_ip_context_for_device(i);
                  if (dev == NULL) {
                    continue;
                  }
                  if (dev->mcast_sock < 0) {
                    continue;
                  }
                  success = oc_netsocket_add_sock_to_ipv6_mcast_group(
                              dev->mcast_sock, ifa->ifa_index) &&
                            success;
                }
              }
          }
          CLANG_IGNORE_WARNING_START
          CLANG_IGNORE_WARNING("-Wcast-align")
          attr = RTA_NEXT(attr, att_len);
          CLANG_IGNORE_WARNING_END
        }
      }
      if_state_changed = true;
    } else if (response->nlmsg_type == RTM_DELADDR) {
      const struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (ifa) {
#ifdef OC_NETWORK_MONITOR
        if (remove_ip_interface(ifa->ifa_index)) {
          oc_network_interface_event(NETWORK_INTERFACE_DOWN);
        }
#endif /* OC_NETWORK_MONITOR */
      }
      if_state_changed = true;
    }
    CLANG_IGNORE_WARNING_START
    CLANG_IGNORE_WARNING("-Wcast-align")
    response = NLMSG_NEXT(response, response_len);
    CLANG_IGNORE_WARNING_END
  }

  if (if_state_changed) {
    for (size_t i = 0; i < num_devices; i++) {
      ip_context_t *dev = oc_get_ip_context_for_device(i);
      if (dev == NULL) {
        continue;
      }
      bool swapped = false;
      int8_t expected = OC_ATOMIC_LOAD8(dev->flags);
      while ((expected & IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST) == 0) {
        int8_t desired =
          (int8_t)(expected | IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST);
        OC_ATOMIC_COMPARE_AND_SWAP8(dev->flags, expected, desired, swapped);
        if (swapped) {
          break;
        }
      }
    }
  }
  oc_message_unref(message);
  return success ? 0 : -1;
}

static void
udp_add_socks_to_rfd_set(ip_context_t *dev)
{
  oc_sock_listener_fd_set(&dev->server, &dev->rfds);
  if (dev->mcast_sock >= 0) {
    FD_SET(dev->mcast_sock, &dev->rfds);
  }
#ifdef OC_SECURITY
  oc_sock_listener_fd_set(&dev->secure, &dev->rfds);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  oc_sock_listener_fd_set(&dev->server4, &dev->rfds);
  if (dev->mcast4_sock >= 0) {
    FD_SET(dev->mcast4_sock, &dev->rfds);
  }
#ifdef OC_SECURITY
  oc_sock_listener_fd_set(&dev->secure4, &dev->rfds);
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

static adapter_receive_state_t
oc_udp_receive_message(const ip_context_t *dev, fd_set *fds,
                       oc_message_t *message)
{
  if (oc_sock_listener_fd_isset(&dev->server, fds)) {
    OC_DBG("udp receive server.sock(fd=%d)", dev->server.sock);
    FD_CLR(dev->server.sock, fds);
    int count = oc_ip_recv_msg(dev->server.sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6;
    return ADAPTER_STATUS_RECEIVE;
  }

  if ((dev->mcast_sock >= 0) && FD_ISSET(dev->mcast_sock, fds)) {
    OC_DBG("udp receive mcast_sock(fd=%d)", dev->mcast_sock);
    FD_CLR(dev->mcast_sock, fds);
    int count = oc_ip_recv_msg(dev->mcast_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, true);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6 | MULTICAST;
    return ADAPTER_STATUS_RECEIVE;
  }

#ifdef OC_IPV4
  if (oc_sock_listener_fd_isset(&dev->server4, fds)) {
    OC_DBG("udp receive server4.sock(fd=%d)", dev->server4.sock);
    FD_CLR(dev->server4.sock, fds);
    int count = oc_ip_recv_msg(dev->server4.sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4;
    return ADAPTER_STATUS_RECEIVE;
  }

  if ((dev->mcast4_sock >= 0) && FD_ISSET(dev->mcast4_sock, fds)) {
    OC_DBG("udp receive mcast4_sock(fd=%d)", dev->mcast4_sock);
    FD_CLR(dev->mcast4_sock, fds);
    int count = oc_ip_recv_msg(dev->mcast4_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, true);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | MULTICAST;
    return ADAPTER_STATUS_RECEIVE;
  }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  if (oc_sock_listener_fd_isset(&dev->secure, fds)) {
    OC_DBG("udp receive secure.sock(fd=%d)", dev->secure.sock);
    FD_CLR(dev->secure.sock, fds);
    int count = oc_ip_recv_msg(dev->secure.sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV6 | SECURED;
    message->encrypted = 1;
    return ADAPTER_STATUS_RECEIVE;
  }
#ifdef OC_IPV4
  if (oc_sock_listener_fd_isset(&dev->secure4, fds)) {
    OC_DBG("udp receive secure4.sock(fd=%d)", dev->secure4.sock);
    FD_CLR(dev->secure4.sock, fds);
    int count = oc_ip_recv_msg(dev->secure4.sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | SECURED;
    message->encrypted = 1;
    return ADAPTER_STATUS_RECEIVE;
  }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

  return ADAPTER_STATUS_NONE;
}

static bool
process_socket_signal_event(const ip_context_t *dev, fd_set *rdfds)
{
#ifdef OC_TCP
  if (!FD_ISSET(dev->tcp.connect_pipe[0], rdfds)) {
    return false;
  }
  FD_CLR(dev->tcp.connect_pipe[0], rdfds);
  adapter_receive_state_t status = tcp_receive_signal(&dev->tcp);
  OC_DBG("Signal event received(fd=%d, status=%d)", dev->tcp.connect_pipe[0],
         status);
#if !OC_DBG_IS_ENABLED
  (void)status;
#endif /* OC_DBG_IS_ENABLED */
  return true;
#else  /* !OC_TCP */
  (void)dev;
  (void)rdfds;
  return false;
#endif /* OC_TCP */
}

static int
process_socket_read_event(ip_context_t *dev, fd_set *rdfds)
{
  oc_message_t *message = oc_allocate_message();
  if (message == NULL) {
    return -1;
  }
  message->endpoint.device = dev->device;

  adapter_receive_state_t s = oc_udp_receive_message(dev, rdfds, message);
  if (s == ADAPTER_STATUS_RECEIVE) {
    goto receive;
  }
#ifdef OC_TCP
  if (s == ADAPTER_STATUS_NONE) {
    s = tcp_receive_message(dev, rdfds, message);
    if (s == ADAPTER_STATUS_RECEIVE) {
      goto receive;
    }
  }
#endif /* OC_TCP */

  oc_message_unref(message);
  return s == ADAPTER_STATUS_NONE ? 0 : 1;

receive:
  OC_DBG("Incoming message of size %zd bytes from", message->length);
  OC_LOGipaddr(message->endpoint);
  OC_DBG("%s", "");

  oc_network_receive_event(message);
  return 1;
}

static int
process_socket_write_event(fd_set *wfds)
{
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  return tcp_process_waiting_sessions(wfds) ? 1 : 0;
#else  /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  (void)wfds;
  return 0;
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
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

  if (wfds != NULL) {
    int ret = process_socket_write_event(wfds);
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
#endif /* OC_DBG_IS_ENABLED */

  return 0;
}

#ifdef OC_DYNAMIC_ALLOCATION
static bool
fd_sets_are_equal(const fd_set *fd1, const fd_set *fd2)
{
#ifdef __FDS_BITS
  return (memcmp(__FDS_BITS(fd1), __FDS_BITS(fd2), sizeof(__FDS_BITS(fd1))) ==
          0);
#else  //!__FDS_BITS
  return (memcmp(fd1->fds_bits, fd2->fds_bits, sizeof(fd1->fds_bits)) == 0);
#endif //__FDS_BITS
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
  int random_rfd = (int)oc_random_value() % fd_count;
  for (int i = 0; i <= max_fd; i++) {
    if (FD_ISSET(i, sourcefds)) {
      if (--fd_count == random_rfd) {
        return i;
      }
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
process_events(ip_context_t *dev, fd_set *rdfds, fd_set *wfds, int fd_count,
               int max_read_fd)
{
  if (fd_count == 0) {
    OC_DBG("process_events: timeout");
    return;
  }

  OC_DBG("processing %d events", fd_count);

  // process control flow events
  if (process_wakeup_signal(dev, rdfds)) {
    fd_count--;
  }

  if ((dev->device == 0) && (FD_ISSET(g_ifchange_sock, rdfds))) {
    OC_DBG("interface change processed on (fd=%d)", g_ifchange_sock);
    FD_CLR(g_ifchange_sock, rdfds);
    if (process_interface_change_event() < 0) {
      OC_WRN("caught errors while handling a network interface change");
    }
    fd_count--;
  }

  if (process_socket_signal_event(dev, rdfds)) {
    fd_count--;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  // check if network queue can consume all 'ready' events
  int available_count = OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS -
                        oc_network_get_event_queue_length(dev->device);
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

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
static struct timeval
to_timeval(oc_clock_time_t ticks)
{
  unsigned sec = (unsigned)(ticks / OC_CLOCK_SECOND);
  unsigned usec =
    (unsigned)((double)(ticks % OC_CLOCK_SECOND) * (1.e06 / OC_CLOCK_SECOND));
  if (sec == 0 && usec == 0) {
    usec = 1;
  }
  struct timeval tval = {
    .tv_sec = sec,
    .tv_usec = usec,
  };
  return tval;
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

static void
add_control_flow_rfds(fd_set *output_set, const ip_context_t *dev)
{
  /* Monitor network interface changes on the platform from only the 0th
   * logical device
   */
  if (dev->device == 0) {
    FD_SET(g_ifchange_sock, output_set);
  }
  FD_SET(dev->wakeup_pipe[0], output_set);
}

static void *
network_event_thread(void *data)
{
  ip_context_t *dev = (ip_context_t *)data;
  FD_ZERO(&dev->rfds);

  udp_add_socks_to_rfd_set(dev);
  add_control_flow_rfds(&dev->rfds, dev);
#ifdef OC_TCP
  tcp_add_socks_to_rfd_set(dev);
  tcp_add_controlflow_socks_to_rfd_set(&dev->rfds, dev);
#endif /* OC_TCP */

  int max_read_fd = FD_SETSIZE;
  fd_set last_rdfds;
  FD_ZERO(&last_rdfds);

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  oc_clock_time_t expires_in = 0;
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  while (OC_ATOMIC_LOAD8(dev->terminate) != 1) {
    struct timeval *timeout = NULL;
    fd_set rdfds = ip_context_rfds_fd_copy(dev);
    fd_set *wfds = NULL;
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
    fd_set write_fds = tcp_context_cfds_fd_copy(&dev->tcp);
    wfds = &write_fds;
    struct timeval tv;
    if (expires_in > 0) {
      tv = to_timeval(expires_in);
      timeout = &tv;
      OC_DBG("network_event_thread timeout:%us %uusec", (unsigned)tv.tv_sec,
             (unsigned)tv.tv_usec);
    }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

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
      tcp_add_controlflow_socks_to_rfd_set(&rdfds, dev);
#endif /* OC_TCP */
    }
#endif /* OC_DYNAMIC_ALLOCATION */
    int n = select(FD_SETSIZE, &rdfds, wfds, NULL, timeout);

    if (OC_ATOMIC_LOAD8(dev->terminate)) {
      break;
    }

    process_events(dev, &rdfds, wfds, n, max_read_fd);

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
    expires_in = tcp_check_expiring_sessions(oc_clock_time_monotonic());
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  }
  pthread_exit(NULL);
  return NULL;
}

static int
oc_send_buffer_internal(oc_message_t *message, bool create, bool queue)
{
  OC_DBG("Outgoing message of size %zd bytes to", message->length);
  OC_LOGipaddr(message->endpoint);
  OC_DBG("%s", "");

  ip_context_t *dev = oc_get_ip_context_for_device(message->endpoint.device);
  if (dev == NULL) {
    return -1;
  }

  struct sockaddr_storage receiver = oc_socket_get_address(&message->endpoint);

#ifdef OC_TCP
  if ((message->endpoint.flags & TCP) != 0) {
    if (create) {
      return oc_tcp_send_buffer(dev, message, &receiver);
    }
    return oc_tcp_send_buffer2(message, queue);
  }
#else  /* !OC_TCP */
  (void)create;
  (void)queue;
#endif /* OC_TCP */

  int send_sock = -1;
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
      send_sock = dev->secure4.sock;
    } else {
      send_sock = dev->secure.sock;
    }
#else  /* !OC_IPV4 */
    send_sock = dev->secure.sock;
#endif /* OC_IPV4 */
  } else
#endif /* OC_SECURITY */
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
    send_sock = dev->server4.sock;
  } else {
    send_sock = dev->server.sock;
  }
#else  /* !OC_IPV4 */
  {
    send_sock = dev->server.sock;
  }
#endif /* OC_IPV4 */

  return (int)oc_ip_send_msg(send_sock, &receiver, message);
}

int
oc_send_buffer(oc_message_t *message)
{
  return oc_send_buffer_internal(message, true, true);
}

int
oc_send_buffer2(oc_message_t *message, bool queue)
{
  return oc_send_buffer_internal(message, false, queue);
}

#ifdef OC_CLIENT

typedef enum {
  SEND_DISCOVERY_OK = 0,
  SEND_DISCOVERY_SKIPPED = 1,

  SEND_DISCOVERY_ERROR = -1,
} send_discovery_t;

static send_discovery_t
send_ipv6_discovery_request(oc_message_t *message,
                            const struct ifaddrs *interface, int server_sock)
{
  if (server_sock == -1) {
    IN6_IS_ADDR_LINKLOCAL(
      "skipping sending of discovery request: server socket for IPv6 is "
      "disabled");
    return SEND_DISCOVERY_SKIPPED;
  }

  CLANG_IGNORE_WARNING_START
  CLANG_IGNORE_WARNING("-Wcast-align")
  const struct sockaddr_in6 *addr = (struct sockaddr_in6 *)interface->ifa_addr;
  CLANG_IGNORE_WARNING_END
  if (!IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
    OC_DBG("skipping sending of discovery request: only link-local addresses "
           "are supported");
    return SEND_DISCOVERY_SKIPPED;
  }

  unsigned mif = if_nametoindex(interface->ifa_name);
  if (mif == 0) {
    OC_ERR("cannot send discovery request: cannot obtain interface(%s) "
           "index(error: %d)",
           interface->ifa_name, (int)errno);
    return SEND_DISCOVERY_ERROR;
  }

  if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mif,
                 sizeof(mif)) == -1) {
    OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d", errno);
    return SEND_DISCOVERY_ERROR;
  }
  message->endpoint.interface_index = mif;

#define IN6_IS_ADDR_MC_REALM_LOCAL(addr)                                       \
  IN6_IS_ADDR_MULTICAST(addr) &&                                               \
    ((((const uint8_t *)(addr))[1] & 0x0f) == OC_IPV6_ADDR_SCOPE_REALM_LOCAL)

  if (IN6_IS_ADDR_MC_LINKLOCAL(message->endpoint.addr.ipv6.address)) {
    message->endpoint.addr.ipv6.scope = mif;
    unsigned int hops = 1;
    setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
               sizeof(hops));
  } else if (IN6_IS_ADDR_MC_REALM_LOCAL(message->endpoint.addr.ipv6.address)) {
    unsigned int hops = 255;
    setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
               sizeof(hops));
    message->endpoint.addr.ipv6.scope = 0;
  } else if (IN6_IS_ADDR_MC_SITELOCAL(message->endpoint.addr.ipv6.address)) {
    unsigned int hops = 255;
    setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
               sizeof(hops));
    message->endpoint.addr.ipv6.scope = 0;
  }
#undef IN6_IS_ADDR_MC_REALM_LOCAL

  if (oc_send_buffer(message) < 0) {
    OC_ERR("failed to send ipv6 discovery request");
    return SEND_DISCOVERY_ERROR;
  }
  OC_DBG("sent discovery request on interface %s", interface->ifa_name);
  return SEND_DISCOVERY_OK;
}

#ifdef OC_IPV4
static send_discovery_t
send_ipv4_discovery_request(oc_message_t *message,
                            const struct ifaddrs *interface, int server_sock)
{
  if (server_sock == -1) {
    OC_DBG("skipping sending of discovery request: server socket for IPv4 is "
           "disabled");
    return SEND_DISCOVERY_SKIPPED;
  }
  CLANG_IGNORE_WARNING_START
  CLANG_IGNORE_WARNING("-Wcast-align")
  const struct sockaddr_in *addr = (struct sockaddr_in *)interface->ifa_addr;
  CLANG_IGNORE_WARNING_END
  if (setsockopt(server_sock, IPPROTO_IP, IP_MULTICAST_IF, &addr->sin_addr,
                 sizeof(addr->sin_addr)) == -1) {
    OC_ERR("setting socket option for default IP_MULTICAST_IF: %d", (int)errno);
    return SEND_DISCOVERY_ERROR;
  }
  int ttl = OC_IPV4_MULTICAST_TTL;
  if (setsockopt(server_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
                 sizeof(int)) == -1) {
    OC_ERR("setting socket option for default IP_MULTICAST_TTL: %d", errno);
    return SEND_DISCOVERY_ERROR;
  }
  unsigned if_index = if_nametoindex(interface->ifa_name);
  if (if_index == 0) {
    OC_ERR("could not get interface index for %s (error: %d)",
           interface->ifa_name, (int)errno);
    return SEND_DISCOVERY_ERROR;
  }
  message->endpoint.interface_index = if_index;
  if (oc_send_buffer(message) < 0) {
    OC_ERR("failed to send ipv4 discovery request");
    return SEND_DISCOVERY_ERROR;
  }
  OC_DBG("sent discovery request on interface %s", interface->ifa_name);
  return SEND_DISCOVERY_OK;
}
#endif /* OC_IPV4 */

static send_discovery_t
send_discovery_request(oc_message_t *message, const struct ifaddrs *interface,
                       const ip_context_t *dev)
{
  if (interface->ifa_addr != NULL) {
    if ((message->endpoint.flags & IPV6) != 0 &&
        interface->ifa_addr->sa_family == AF_INET6) {
      return send_ipv6_discovery_request(message, interface, dev->server.sock);
    }
#ifdef OC_IPV4
    if ((message->endpoint.flags & IPV4) != 0 &&
        interface->ifa_addr->sa_family == AF_INET) {
      return send_ipv4_discovery_request(message, interface, dev->server4.sock);
    }
#endif /* OC_IPV4 */
  }
  return SEND_DISCOVERY_SKIPPED;
}

void
oc_send_discovery_request(oc_message_t *message)
{
  struct ifaddrs *ifs = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interfaces: %d", errno);
    return;
  }

  memset(&message->endpoint.addr_local, 0,
         sizeof(message->endpoint.addr_local));
  message->endpoint.interface_index = 0;

  const ip_context_t *dev =
    oc_get_ip_context_for_device(message->endpoint.device);

  for (struct ifaddrs *interface = ifs; interface != NULL;
       interface = interface->ifa_next) {
    if ((interface->ifa_flags & IFF_UP) == 0 ||
        (interface->ifa_flags & IFF_LOOPBACK) != 0) {
      continue;
    }

    if (send_discovery_request(message, interface, dev) ==
        SEND_DISCOVERY_ERROR) {
      freeifaddrs(ifs);
      return;
    }
  }
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

#ifdef OC_IPV4
static bool
initialize_ip_context_ipv4(oc_sock_listener_t *server, bool enabled,
                           uint16_t port)
{
  if (!enabled) {
    OC_DBG("IPv4 listening socket is disabled");
    server->sock = -1;
    return true;
  }

  int sock = oc_netsocket_create_ipv4(port);
  if (sock < 0) {
    OC_ERR("failed creating IPv4 listening socket on port %u", (unsigned)port);
    server->sock = -1;
    return false;
  }
  server->sock = sock;
  return true;
}

static bool
initialize_ip_context_ipv4_mcast(ip_context_t *dev, bool enabled)
{
  if (!enabled) {
    OC_WRN("discovery via IPv4 multicast is disabled");
    dev->mcast4_sock = -1;
    return true;
  }

  int mcast4_sock = oc_netsocket_create_mcast_ipv4(OCF_PORT_UNSECURED);
  if (mcast4_sock < 0) {
    OC_ERR("failed creating IPv4 multicast socket on port %u",
           (unsigned)OCF_PORT_UNSECURED);
    dev->mcast4_sock = -1;
    return false;
  }
  dev->mcast4_sock = mcast4_sock;
  return true;
}

static bool
connectivity_ipv4_init(ip_context_t *dev, oc_connectivity_ports_t ports)
{
  OC_DBG("Initializing IPv4 connectivity for device %zd", dev->device);

  if (!initialize_ip_context_ipv4_mcast(
        dev, (ports.udp.flags & OC_CONNECTIVITY_DISABLE_IPV4_PORT) == 0)) {
    return false;
  }

  if (!initialize_ip_context_ipv4(
        &dev->server4,
        (ports.udp.flags & OC_CONNECTIVITY_DISABLE_IPV4_PORT) == 0,
        ports.udp.port4)) {
    return false;
  }

#ifdef OC_SECURITY
  if (!initialize_ip_context_ipv4(
        &dev->secure4,
        (ports.udp.flags & OC_CONNECTIVITY_DISABLE_SECURE_IPV4_PORT) == 0,
        ports.udp.secure_port4)) {
    return false;
  }
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized IPv4 connectivity for device %zd",
         dev->device);
  return true;
}
#endif /* OC_IPV4 */

static bool
initialize_ip_context_ipv6(oc_sock_listener_t *server, bool enabled,
                           uint16_t port)
{
  if (!enabled) {
    OC_DBG("IPv6 listening socket is disabled");
    server->sock = -1;
    return true;
  }

  int sock = oc_netsocket_create_ipv6(port);
  if (sock < 0) {
    OC_ERR("failed creating IPv6 listening socket on port %u", (unsigned)port);
    server->sock = -1;
    return false;
  }
  server->sock = sock;
  return true;
}

static bool
initialize_ip_context_ipv6_mcast(ip_context_t *dev, bool enabled)
{
  if (!enabled) {
    OC_WRN("discovery via IPv6 multicast is disabled");
    dev->mcast_sock = -1;
    return true;
  }

  int mcast_sock = oc_netsocket_create_mcast_ipv6(OCF_PORT_UNSECURED);
  if (mcast_sock < 0) {
    OC_ERR("failed creating IPv6 multicast socket on port %u",
           (unsigned)OCF_PORT_UNSECURED);
    dev->mcast_sock = -1;
    return false;
  }

  dev->mcast_sock = mcast_sock;
  return true;
}

static bool
initialize_ip_context(ip_context_t *dev, size_t device,
                      oc_connectivity_ports_t ports)
{
  dev->device = device;
  OC_LIST_STRUCT_INIT(dev, eps);

  if (pthread_mutex_init(&dev->rfds_mutex, NULL) != 0) {
    oc_abort("error initializing TCP adapter mutex");
  }

  if (pipe(dev->wakeup_pipe) < 0) {
    OC_ERR("wakeup pipe: %d", errno);
    return false;
  }
  if (!oc_fcntl_set_nonblocking(dev->wakeup_pipe[0])) {
    OC_ERR("Could not set non-block wakeup_pipe[0]");
    return false;
  }

  if (!initialize_ip_context_ipv6_mcast(
        dev, (ports.udp.flags & OC_CONNECTIVITY_DISABLE_IPV6_PORT) == 0)) {
    return false;
  }

  if (!initialize_ip_context_ipv6(
        &dev->server,
        (ports.udp.flags & OC_CONNECTIVITY_DISABLE_IPV6_PORT) == 0,
        ports.udp.port)) {
    return false;
  }
#ifdef OC_SECURITY
  if (!initialize_ip_context_ipv6(
        &dev->secure,
        (ports.udp.flags & OC_CONNECTIVITY_DISABLE_SECURE_IPV6_PORT) == 0,
        ports.udp.secure_port)) {
    return false;
  }
#endif

#ifdef OC_IPV4
  if (!connectivity_ipv4_init(dev, ports)) {
    OC_ERR("Could not initialize IPv4");
  }
#endif /* OC_IPV4 */

  OC_DBG("=======ip port info.========");
  OC_DBG("  ipv6 port   : %d", oc_sock_listener_get_port(&dev->server));
#ifdef OC_SECURITY
  OC_DBG("  ipv6 secure : %d", oc_sock_listener_get_port(&dev->secure));
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  OC_DBG("  ipv4 port   : %d", oc_sock_listener_get_port(&dev->server4));
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %d", oc_sock_listener_get_port(&dev->secure4));
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */

#ifdef OC_TCP
  if (!tcp_connectivity_init(dev, ports)) {
    OC_ERR("Could not initialize TCP adapter");
  }
#endif /* OC_TCP */

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
      return false;
    }
    if (bind(g_ifchange_sock, (struct sockaddr *)&g_ifchange_nl,
             sizeof(g_ifchange_nl)) == -1) {
      OC_ERR("binding netlink socket %d", errno);
      return false;
    }
#ifdef OC_NETWORK_MONITOR
    if (!check_new_ip_interfaces()) {
      OC_ERR("checking new IP interfaces failed.");
      return false;
    }
#endif /* OC_NETWORK_MONITOR */
    g_ifchange_initialized = true;
  }

  if (pthread_create(&dev->event_thread, NULL, &network_event_thread, dev) !=
      0) {
    OC_ERR("creating network polling thread");
    return false;
  }

  return true;
}

static void
signal_event_thread(ip_context_t *dev)
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

int
oc_connectivity_init(size_t device, oc_connectivity_ports_t ports)
{
  OC_DBG("Initializing connectivity for device %zd", device);

  ip_context_t *dev = (ip_context_t *)oc_memb_alloc(&g_ip_context_s);
  if (dev == NULL) {
    oc_abort("Insufficient memory");
  }

  if (!initialize_ip_context(dev, device, ports)) {
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

  OC_DBG("Successfully initialized connectivity for device %zd", device);
  pthread_mutex_lock(&g_mutex);
  oc_list_add(g_ip_contexts, dev);
  pthread_mutex_unlock(&g_mutex);

  return 0;
}

#ifdef OC_DYNAMIC_ALLOCATION
void
oc_connectivity_wakeup(size_t device)
{
  ip_context_t *dev = oc_get_ip_context_for_device(device);
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
  ip_context_t *dev = oc_get_ip_context_for_device(device);
  if (dev == NULL) {
    OC_WRN("no ip-context found for device(%zu)", device);
    return;
  }

  OC_ATOMIC_STORE8(dev->terminate, 1);
  signal_event_thread(dev);

  pthread_join(dev->event_thread, NULL);

  oc_sock_listener_close(&dev->server);
  if (dev->mcast_sock >= 0) {
    close(dev->mcast_sock);
  }

#ifdef OC_IPV4
  oc_sock_listener_close(&dev->server4);
  if (dev->mcast4_sock >= 0) {
    close(dev->mcast4_sock);
  }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  oc_sock_listener_close(&dev->secure);
#ifdef OC_IPV4
  oc_sock_listener_close(&dev->secure4);
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

#ifdef OC_TCP
  tcp_connectivity_shutdown(dev);
#endif /* OC_TCP */

  close(dev->wakeup_pipe[1]);
  close(dev->wakeup_pipe[0]);

  pthread_mutex_destroy(&dev->rfds_mutex);

  free_endpoints_list(dev);

  pthread_mutex_lock(&g_mutex);
  oc_list_remove(g_ip_contexts, dev);
  pthread_mutex_unlock(&g_mutex);
  oc_memb_free(&g_ip_context_s, dev);

  OC_DBG("oc_connectivity_shutdown for device %zd", device);
}

#ifdef OC_TCP
bool
oc_connectivity_end_session_v1(const oc_endpoint_t *endpoint,
                               bool notify_session_end,
                               oc_endpoint_t *session_endpoint)
{
  if ((endpoint->flags & TCP) != 0 &&
      oc_get_ip_context_for_device(endpoint->device) != NULL) {
    return tcp_end_session(endpoint, notify_session_end, session_endpoint);
  }
  return false;
}

void
oc_connectivity_end_session(const oc_endpoint_t *endpoint)
{
  while (oc_connectivity_end_session_v1(endpoint, true, NULL)) {
    // no-op
  }
}
#endif /* OC_TCP */
