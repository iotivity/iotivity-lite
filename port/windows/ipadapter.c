/****************************************************************************
 *
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
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

#include "api/oc_network_events_internal.h"
#include "api/oc_session_events_internal.h"
#include "ipcontext.h"
#include "mutex.h"
#include "network_addresses.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "port/common/posix/oc_socket_internal.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#ifdef OC_NETWORK_MONITOR
#include "oc_network_monitor.h"
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_TCP
#include "tcpadapter.h"
#endif /* OC_TCP */
#ifdef OC_SESSION_EVENTS
#include "api/oc_session_events_internal.h"
#endif /* OC_SESSION_EVENTS */

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Mswsock.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <malloc.h>
#endif /* OC_DYNAMIC_ALLOCATION */

/* Maximum possible number of WSAEVENTs to be waited on. */
#define MAX_WSAEVENT_ARRAY_SIZE 8

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

static HANDLE g_network_mutex;
SOCKET ifchange_sock;
BOOL ifchange_initialized;
OVERLAPPED ifchange_event;
static LPFN_WSARECVMSG PWSARecvMsg;
static LPFN_WSASENDMSG PWSASendMsg;

OC_LIST(g_ip_contexts);
OC_MEMB(g_ip_context_s, ip_context_t, OC_MAX_NUM_DEVICES);

OC_MEMB(device_eps, oc_endpoint_t, 1);

#ifdef OC_NETWORK_MONITOR
OC_LIST(ip_interface_list);
OC_MEMB(ip_interface_s, ifaddr_t, OC_MAX_IP_INTERFACES);

OC_LIST(oc_network_interface_cb_list);
OC_MEMB(oc_network_interface_cb_s, oc_network_interface_cb_t,
        OC_MAX_NETWORK_INTERFACE_CBS);
static HANDLE oc_network_interface_cb_mutex;

static ifaddr_t *
find_ip_interface(ifaddr_t *if_list, DWORD target_index)
{
  ifaddr_t *if_item = if_list;
  while (if_item != NULL && if_item->if_index != target_index) {
    if_item = if_item->next;
  }
  return if_item;
}

static bool
add_ip_interface(DWORD target_index)
{
  if (find_ip_interface(oc_list_head(ip_interface_list), target_index)) {
    return false;
  }
  ifaddr_t *new_if = oc_memb_alloc(&ip_interface_s);
  if (!new_if) {
    OC_ERR("interface item alloc failed");
    return false;
  }
  new_if->if_index = target_index;
  oc_list_add(ip_interface_list, new_if);
  OC_DBG("New interface added: %ld", new_if->if_index);
  return true;
}

static bool
remove_ip_interface(DWORD target_index)
{
  ifaddr_t *if_item =
    find_ip_interface(oc_list_head(ip_interface_list), target_index);
  if (!if_item) {
    return false;
  }

  oc_list_remove(ip_interface_list, if_item);
  oc_memb_free(&ip_interface_s, if_item);
  OC_DBG("Removed from ip interface list: %ld", target_index);
  return true;
}

static void
remove_all_ip_interface(void)
{
  ifaddr_t *if_item = oc_list_head(ip_interface_list), *next;
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

void
oc_network_event_handler_mutex_init(void)
{
  g_network_mutex = mutex_new();
#ifdef OC_NETWORK_MONITOR
  oc_network_interface_cb_mutex = mutex_new();
#endif /* OC_NETWORK_MONITOR */
#ifdef OC_TCP
  oc_tcp_adapter_mutex_init();
#endif /* OC_TCP */
}

void
oc_network_event_handler_mutex_lock(void)
{
  mutex_lock(g_network_mutex);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  mutex_unlock(g_network_mutex);
}

void
oc_network_event_handler_mutex_destroy(void)
{
#ifdef OC_TCP
  oc_tcp_adapter_mutex_destroy();
#endif /* OC_TCP */
  ifchange_initialized = false;
  mutex_free(g_network_mutex);
  closesocket(ifchange_sock);
#ifdef OC_NETWORK_MONITOR
  mutex_free(oc_network_interface_cb_mutex);
  remove_all_ip_interface();
  remove_all_network_interface_cbs();
#endif /* OC_NETWORK_MONITOR */
#ifdef OC_SESSION_EVENTS
  oc_session_events_remove_all_callbacks();
#endif /* OC_SESSION_EVENTS */
  WSACleanup();
}

static ip_context_t *
get_ip_context_for_device(size_t device)
{
  oc_network_event_handler_mutex_lock();
  ip_context_t *dev = oc_list_head(g_ip_contexts);
  while (dev != NULL && dev->device != device) {
    dev = dev->next;
  }
  oc_network_event_handler_mutex_unlock();
  return dev;
}

#ifdef OC_IPV4
static int
add_mcast_sock_to_ipv4_mcast_group(SOCKET mcast_sock,
                                   const struct in_addr *local)
{
  struct ip_mreq mreq;

  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
  memcpy(&mreq.imr_interface, local, sizeof(struct in_addr));

  setsockopt(mcast_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining IPv4 multicast group %d", WSAGetLastError());
    return -1;
  }

  return 0;
}
#endif /* OC_IPV4 */

static int
add_mcast_sock_to_ipv6_mcast_group(SOCKET mcast_sock, DWORD if_index)
{
  struct ipv6_mreq mreq;

  /* Link-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_LL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining link-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  /* Realm-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_RL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining realm-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  /* Site-local scope */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_SL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining site-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

#ifdef OC_WKCORE

  OC_DBG("Adding all CoAP Nodes");
  /* Link-local scope ALL COAP NODES */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_LL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining link-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  /* Realm-local scope ALL COAP nodes  */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_RL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining realm-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  /* Site-local scope ALL COAP nodes */
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_SL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining site-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }
#endif

  return 0;
}

static int
update_mcast_socket(SOCKET mcast_sock, int sa_family, ifaddr_t *ifaddr_list)
{
  int ret = 0;
  ifaddr_t *ifaddr;
  bool ifaddr_supplied = false;
  if (!ifaddr_list) {
    ifaddr_list = get_network_addresses();
    if (!ifaddr_list) {
      OC_ERR("could not obtain list of network addresses");
      return -1;
    }
  } else {
    ifaddr_supplied = true;
  }

  for (ifaddr = ifaddr_list; ifaddr; ifaddr = ifaddr->next) {
    if (sa_family == AF_INET6 && ifaddr->addr.ss_family == AF_INET6) {
      ret += add_mcast_sock_to_ipv6_mcast_group(mcast_sock, ifaddr->if_index);
    }
#ifdef OC_IPV4
    if (sa_family == AF_INET && ifaddr->addr.ss_family == AF_INET) {
      struct sockaddr_in *a = (struct sockaddr_in *)&ifaddr->addr;
      ret += add_mcast_sock_to_ipv4_mcast_group(mcast_sock, &a->sin_addr);
    }
#endif
  }

  if (!ifaddr_supplied) {
    free_network_addresses(ifaddr_list);
  }

  return ret;
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
get_interface_addresses(ifaddr_t *ifaddr_list, ip_context_t *dev,
                        unsigned char family, uint16_t port, bool secure,
                        bool tcp)
{
  ifaddr_t *ifaddr;

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(oc_endpoint_t));

  if (secure) {
    ep.flags = SECURED;
  }
  if (tcp) {
    ep.flags |= TCP;
  }

  for (ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    ep.interface_index = ifaddr->if_index;
    if (family == AF_INET6 && ifaddr->addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ifaddr->addr;
      memcpy(ep.addr.ipv6.address, &addr->sin6_addr, sizeof(addr->sin6_addr));
      ep.flags |= IPV6;
      ep.addr.ipv6.port = port;
      ep.addr.ipv6.scope = (uint8_t)addr->sin6_scope_id;
      oc_endpoint_t *new_ep = oc_memb_alloc(&device_eps);
      if (!new_ep) {
        return;
      }
      memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
      oc_list_add(dev->eps, new_ep);
      OC_DBG("Adding address for interface %ld", ifaddr->if_index);
      OC_LOGipaddr(OC_LOG_LEVEL_DEBUG, ep);
      OC_DBG("%s", "");
      continue;
    }
#ifdef OC_IPV4
    if (family == AF_INET && ifaddr->addr.ss_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)&ifaddr->addr;
      memcpy(ep.addr.ipv4.address, &addr->sin_addr.S_un.S_addr,
             sizeof(addr->sin_addr));
      ep.flags |= IPV4;
      ep.addr.ipv4.port = port;
      oc_endpoint_t *new_ep = oc_memb_alloc(&device_eps);
      if (!new_ep) {
        return;
      }
      memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
      oc_list_add(dev->eps, new_ep);
      OC_DBG("Adding address for interface %ld", ifaddr->if_index);
      OC_LOGipaddr(OC_LOG_LEVEL_DEBUG, ep);
      OC_DBG("%s", "");
      continue;
    }
#endif
  }
}

static void
refresh_endpoints_list(ip_context_t *dev)
{
  free_endpoints_list(dev);
  ifaddr_t *ifaddr_list = get_network_addresses();
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->port, false, false);
#ifdef OC_SECURITY
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->dtls_port, true,
                          false);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  get_interface_addresses(ifaddr_list, dev, AF_INET, dev->port4, false, false);
#ifdef OC_SECURITY
  get_interface_addresses(ifaddr_list, dev, AF_INET, dev->dtls4_port, true,
                          false);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#ifdef OC_TCP
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->tcp.port, false,
                          true);
#ifdef OC_SECURITY
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->tcp.tls_port, true,
                          true);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  get_interface_addresses(ifaddr_list, dev, AF_INET, dev->tcp.port4, false,
                          true);
#ifdef OC_SECURITY
  get_interface_addresses(ifaddr_list, dev, AF_INET, dev->tcp.tls4_port, true,
                          true);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#endif /* OC_TCP */
}

static int
process_interface_change_event(void)
{
  int ret = 0;
  ifaddr_t *ifaddr_list = get_network_addresses();
  if (!ifaddr_list) {
    return -1;
  }

  size_t num_devices = oc_core_get_num_devices();
  for (size_t i = 0; i < num_devices; i++) {
    ip_context_t *dev = get_ip_context_for_device(i);
    if (dev == NULL) {
      continue;
    }

    ret += update_mcast_socket(dev->mcast_sock, AF_INET6, ifaddr_list);
#ifdef OC_IPV4
    ret += update_mcast_socket(dev->mcast4_sock, AF_INET, ifaddr_list);
#endif /* OC_IPV4 */

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

#ifdef OC_NETWORK_MONITOR
  bool if_up = false;
  bool if_down = false;
  for (ifaddr_t *ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    if (add_ip_interface(ifaddr->if_index)) {
      if_up = true;
    }
  }

  for (ifaddr_t *ifaddr = oc_list_head(ip_interface_list); ifaddr != NULL;) {
    if (!find_ip_interface(ifaddr_list, ifaddr->if_index)) {
      ifaddr_t *next = ifaddr->next;
      remove_ip_interface(ifaddr->if_index);
      ifaddr = next;
      if_down = true;
    } else {
      ifaddr = ifaddr->next;
    }
  }
  if (if_up) {
    oc_network_interface_event(NETWORK_INTERFACE_UP);
  }
  if (if_down) {
    oc_network_interface_event(NETWORK_INTERFACE_DOWN);
  }
#endif /* OC_NETWORK_MONITOR */

  free_network_addresses(ifaddr_list);

  return ret;
}

static int
get_WSARecvMsg(void)
{
  if (PWSARecvMsg) {
    return 0;
  }

  DWORD NumberOfBytes = 0;
  GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;

  SOCKET sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) {
    OC_ERR("could not create socket for obtaining WSARecvMsg handle");
    return -1;
  }

  int result = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID), &PWSARecvMsg,
                        sizeof(PWSARecvMsg), &NumberOfBytes, NULL, NULL);

  closesocket(sock);

  if (result == SOCKET_ERROR) {
    OC_ERR("could not obtain handle to WSARecvMsg :%d", WSAGetLastError());
    return -1;
  }

  return 0;
}

static int
recv_msg(SOCKET sock, uint8_t *recv_buf, int recv_buf_size,
         oc_endpoint_t *endpoint, bool multicast)
{
  if (!PWSARecvMsg && get_WSARecvMsg() < 0) {
    OC_ERR("could not get handle to WSARecvMsg");
    return -1;
  }

  struct sockaddr_storage client;

  WSABUF WSABuf;
  WSABuf.buf = (char *)recv_buf;
  WSABuf.len = recv_buf_size;

  WSAMSG Msg;
  memset(&Msg, 0, sizeof(Msg));
  Msg.name = (LPSOCKADDR)&client;
  Msg.namelen = sizeof(client);

  Msg.lpBuffers = &WSABuf;
  Msg.dwBufferCount = 1;

  union {
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    char in6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_buf;
  Msg.Control.buf = (char *)&control_buf;
  Msg.Control.len = sizeof(control_buf);

  Msg.dwFlags = 0;

  DWORD NumberOfBytes = 0;

  if (PWSARecvMsg(sock, &Msg, &NumberOfBytes, NULL, NULL) == 0) {
    switch (client.ss_family) {
    case AF_INET: {
      struct sockaddr_in *addr = (struct sockaddr_in *)&client;
      memcpy(endpoint->addr.ipv4.address, &addr->sin_addr.s_addr,
             sizeof(addr->sin_addr.s_addr));
      endpoint->addr.ipv4.port = ntohs(addr->sin_port);
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&client;
      memcpy(endpoint->addr.ipv6.address, addr->sin6_addr.s6_addr,
             sizeof(addr->sin6_addr.s6_addr));
      endpoint->addr.ipv6.scope = (uint8_t)addr->sin6_scope_id;
      endpoint->addr.ipv6.port = ntohs(addr->sin6_port);
      break;
    }
    }

    LPWSACMSGHDR MsgHdr = NULL;
    do {
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
      MsgHdr = WSA_CMSG_NXTHDR(&Msg, MsgHdr);
      if (!MsgHdr) {
        break;
      }

      switch (MsgHdr->cmsg_type) {
      case IP_PKTINFO: {
        switch (client.ss_family) {
        case AF_INET: {
          struct in_pktinfo *pktinfo =
            (struct in_pktinfo *)WSA_CMSG_DATA(MsgHdr);
          endpoint->interface_index = pktinfo->ipi_ifindex;
          if (!multicast) {
            memcpy(endpoint->addr_local.ipv4.address,
                   &pktinfo->ipi_addr.S_un.S_addr, 4);
          } else {
            memset(endpoint->addr_local.ipv4.address, 0, 4);
          }
          return (int)NumberOfBytes;
        } break;

        case AF_INET6: {
          struct in6_pktinfo *pktinfo =
            (struct in6_pktinfo *)WSA_CMSG_DATA(MsgHdr);
          endpoint->interface_index = pktinfo->ipi6_ifindex;
          if (!multicast) {
            memcpy(endpoint->addr_local.ipv6.address, pktinfo->ipi6_addr.u.Byte,
                   16);
          } else {
            memset(endpoint->addr_local.ipv6.address, 0, 16);
          }
          return (int)NumberOfBytes;
        } break;
        default:
          break;
        }
      } break;
      default:
        break;
      }
    } while (true);
  }

  return -1;
}

static DWORD
network_event_thread(void *data)
{
  ip_context_t *dev = (ip_context_t *)data;

#define OC_WSAEVENTSELECT(socket, event_handle, event_type)                    \
  do {                                                                         \
    if (WSAEventSelect(socket, event_handle, event_type) == SOCKET_ERROR) {    \
      goto network_event_thread_error;                                         \
    }                                                                          \
  } while (0)

  WSAEVENT mcast6_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->mcast_sock, mcast6_event, FD_READ);

  WSAEVENT server6_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->server_sock, server6_event, FD_READ);
  dev->event_server_handle = server6_event;

#ifdef OC_SECURITY
  WSAEVENT secure6_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->secure_sock, secure6_event, FD_READ);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  WSAEVENT mcast4_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->mcast4_sock, mcast4_event, FD_READ);

  WSAEVENT server4_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->server4_sock, server4_event, FD_READ);

#ifdef OC_SECURITY
  WSAEVENT secure4_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->secure4_sock, secure4_event, FD_READ);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#undef OC_WSAEVENTSELECT

  WSAEVENT event_list[MAX_WSAEVENT_ARRAY_SIZE];
  DWORD event_list_size = 0;

  // Add control flow events.
  if (dev->device == 0) {
    event_list[event_list_size++] = ifchange_event.hEvent;
    process_interface_change_event();
  }
#ifdef OC_DYNAMIC_ALLOCATION
  event_list[event_list_size++] = dev->wake_up_event;
#endif // OC_DYNAMIC_ALLOCATION
  DWORD control_flow_event_count = event_list_size;

  // Add remaining message events.
  event_list[event_list_size++] = mcast6_event;
  event_list[event_list_size++] = server6_event;
#ifdef OC_SECURITY
  event_list[event_list_size++] = secure6_event;
#ifdef OC_IPV4
  event_list[event_list_size++] = mcast4_event;
  event_list[event_list_size++] = server4_event;
  event_list[event_list_size++] = secure4_event;
#endif /* OC_IPV4 */
#else  /* OC_SECURITY */
  event_list[event_list_size++] = mcast4_event;
  event_list[event_list_size++] = server4_event;
#endif /* !OC_SECURITY */

  while (!dev->terminate) {
    DWORD event_count = event_list_size;

#ifdef OC_DYNAMIC_ALLOCATION
    DWORD queue_length = (DWORD)oc_network_get_event_queue_length(dev->device);
    if (queue_length >= OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS) {
      // Network event queue is full, wait only for control flow events.
      event_count = control_flow_event_count;
    }
#endif /* OC_DYNAMIC_ALLOCATION */

    DWORD i =
      WSAWaitForMultipleEvents(event_count, event_list, FALSE, INFINITE, FALSE);
    i -= WSA_WAIT_EVENT_0;

    // Process control flow events.
    for (; i < control_flow_event_count; i++) {

      WSAEVENT cf_event = event_list[i];
      DWORD ret = WSAWaitForMultipleEvents(1, &cf_event, TRUE, 0, FALSE);

      if (ret != WSA_WAIT_TIMEOUT && ret != WSA_WAIT_FAILED) {
        if (WSAResetEvent(cf_event) == FALSE) {
          OC_WRN("WSAResetEvent returned error: %d", WSAGetLastError());
        }
        if (dev->device == 0 && cf_event == ifchange_event.hEvent) {
          process_interface_change_event();
          DWORD bytes_returned = 0;
          if (WSAIoctl(ifchange_sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0,
                       &bytes_returned, &ifchange_event,
                       NULL) == SOCKET_ERROR) {
            if (GetLastError() != ERROR_IO_PENDING) {
              OC_ERR("could not reset SIO_ADDRESS_LIST_CHANGE on network "
                     "interface change socket");
            }
          }
        }
      }
    }

    // Collect signalled message events.
    WSAEVENT msg_events[MAX_WSAEVENT_ARRAY_SIZE];
    DWORD msg_event_count = 0;

    for (; i < event_count; i++) {
      DWORD ret = WSAWaitForMultipleEvents(1, event_list + i, TRUE, 0, FALSE);
      if (ret != WSA_WAIT_TIMEOUT && ret != WSA_WAIT_FAILED) {
        msg_events[msg_event_count++] = event_list[i];
      }
    }

#ifdef OC_DYNAMIC_ALLOCATION
    // Randomly remove events from list if the queue is about to fill.
    DWORD available_items =
      OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS - queue_length;
    DWORD items_to_remove =
      msg_event_count - min(msg_event_count, available_items);

    while (items_to_remove--) {
      DWORD rnd = (DWORD)rand() % msg_event_count;
      msg_event_count--;
      msg_events[rnd] = msg_events[msg_event_count];
    }
#endif /* OC_DYNAMIC_ALLOCATION */

    // Process message events.
    for (i = 0; !dev->terminate && i < msg_event_count; i++) {

      WSAEVENT msg_event = msg_events[i];
      DWORD ret = WSAWaitForMultipleEvents(1, &msg_event, TRUE, 0, FALSE);

      if (ret != WSA_WAIT_TIMEOUT && ret != WSA_WAIT_FAILED) {
        if (WSAResetEvent(msg_event) == FALSE) {
          OC_WRN("WSAResetEvent returned error: %d", WSAGetLastError());
        }

        oc_message_t *message = oc_allocate_message();
        if (message == NULL) {
          break;
        }

        message->endpoint.device = dev->device;

        if (msg_event == server6_event) {
          int count = recv_msg(dev->server_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6;
        }

        if (msg_event == mcast6_event) {
          int count = recv_msg(dev->mcast_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, true);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6 | MULTICAST;
        }

#ifdef OC_IPV4
        if (msg_event == server4_event) {
          int count = recv_msg(dev->server4_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4;
        }

        if (msg_event == mcast4_event) {
          int count = recv_msg(dev->mcast4_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, true);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4 | MULTICAST;
        }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
        if (msg_event == secure6_event) {
          int count = recv_msg(dev->secure_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6 | SECURED;
          message->encrypted = 1;
        }
#ifdef OC_IPV4
        if (msg_event == secure4_event) {
          int count = recv_msg(dev->secure4_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4 | SECURED;
          message->encrypted = 1;
        }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

        OC_TRACE("Incoming message of size %zd bytes from", message->length);
        OC_LOGipaddr(OC_LOG_LEVEL_TRACE, message->endpoint);
        OC_TRACE("%s", "");
        oc_network_receive_event(message);
      }
    }
  }

  for (DWORD i = 0; i < event_list_size; ++i) {
    WSACloseEvent(event_list[i]);
  }

  return 0;

network_event_thread_error:
  oc_abort("err in network event thread");
  return -1;
}

oc_endpoint_t *
oc_connectivity_get_endpoints(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
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

  if (oc_list_length(dev->eps) == 0 || refresh) {
    refresh_endpoints_list(dev);
  }

  return oc_list_head(dev->eps);
}

static int
get_WSASendMsg(void)
{
  if (PWSASendMsg) {
    return 0;
  }

  DWORD NumberOfBytes = 0;
  GUID WSASendMsg_GUID = WSAID_WSASENDMSG;

  SOCKET sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) {
    OC_ERR("could not create socket for obtaining WASSendMsg handle");
    return -1;
  }

  int result = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &WSASendMsg_GUID, sizeof(WSASendMsg_GUID), &PWSASendMsg,
                        sizeof(PWSASendMsg), &NumberOfBytes, NULL, NULL);

  closesocket(sock);

  if (result == SOCKET_ERROR) {
    OC_ERR("could not obtain handle to WSASendMsg :%d", WSAGetLastError());
    return -1;
  }

  return 0;
}

static bool
check_if_address_unset(uint8_t *address, int size)
{
  int i = 0;
  for (i = 0; i < size; i++) {
    if (address[i] != 0) {
      break;
    }
  }
  if (i < size) {
    return false;
  }
  return true;
}

static void
set_source_address_for_interface(ADDRESS_FAMILY family, uint8_t *address,
                                 int address_size, unsigned interface_index)
{
  if (!check_if_address_unset(address, address_size)) {
    return;
  }
  ifaddr_t *ifaddr_list = get_network_addresses(), *addr;
  for (addr = ifaddr_list; addr != NULL; addr = addr->next) {
    if (addr->addr.ss_family == family && addr->if_index == interface_index) {
      if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr->addr;
        memcpy(address, a->sin6_addr.u.Byte, 16);
      }
#ifdef OC_IPV4
      else if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&addr->addr;
        memcpy(address, &a->sin_addr.S_un.S_addr, 4);
      }
#endif /* OC_IPV4 */
    }
  }
  free_network_addresses(ifaddr_list);
}

static int
send_msg(SOCKET sock, struct sockaddr_storage *receiver, oc_message_t *message)
{
  if (!PWSASendMsg && get_WSASendMsg() < 0) {
    return -1;
  }

  WSABUF WSABuf;
  WSAMSG Msg;
  memset(&Msg, 0, sizeof(Msg));

  Msg.name = (LPSOCKADDR)receiver;

  Msg.lpBuffers = &WSABuf;
  Msg.dwBufferCount = 1;

  Msg.dwFlags = 0;

  LPWSACMSGHDR MsgHdr = NULL;

  union {
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    char in6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_buf;

  Msg.Control.buf = (char *)&control_buf;

  if (message->endpoint.flags & IPV6) {
    Msg.namelen = sizeof(struct sockaddr_in6);

#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    Msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));

#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    MsgHdr = WSA_CMSG_FIRSTHDR(&Msg);
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    memset(MsgHdr, 0, WSA_CMSG_SPACE(sizeof(struct in6_pktinfo)));

    MsgHdr->cmsg_level = IPPROTO_IPV6;
    MsgHdr->cmsg_type = IPV6_PKTINFO;
    MsgHdr->cmsg_len = WSA_CMSG_LEN(sizeof(struct in6_pktinfo));

    struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)WSA_CMSG_DATA(MsgHdr);

    /* Get the outgoing interface index from message->endpint */
    pktinfo->ipi6_ifindex = message->endpoint.interface_index;

    /* Set the source address of this message using the address
     * from the endpoint's addr_local attribute.
     */
    set_source_address_for_interface(AF_INET6,
                                     message->endpoint.addr_local.ipv6.address,
                                     16, message->endpoint.interface_index);

    memcpy(&pktinfo->ipi6_addr, message->endpoint.addr_local.ipv6.address, 16);
  }
#ifdef OC_IPV4
  else if (message->endpoint.flags & IPV4) {
    Msg.namelen = sizeof(struct sockaddr_in);
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    Msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in_pktinfo));

#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    MsgHdr = WSA_CMSG_FIRSTHDR(&Msg);
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif /* _MSC_VER */
    memset(MsgHdr, 0, WSA_CMSG_SPACE(sizeof(struct in_pktinfo)));

    MsgHdr->cmsg_level = IPPROTO_IP;
    MsgHdr->cmsg_type = IP_PKTINFO;
    MsgHdr->cmsg_len = WSA_CMSG_LEN(sizeof(struct in_pktinfo));

    struct in_pktinfo *pktinfo = (struct in_pktinfo *)WSA_CMSG_DATA(MsgHdr);

    pktinfo->ipi_ifindex = message->endpoint.interface_index;

    set_source_address_for_interface(AF_INET,
                                     message->endpoint.addr_local.ipv4.address,
                                     4, message->endpoint.interface_index);

    memcpy(&pktinfo->ipi_addr.S_un.S_addr,
           message->endpoint.addr_local.ipv4.address, 4);
  }
#else  /* OC_IPV4 */
  else {
    OC_ERR("invalid endpoint");
    return -1;
  }
#endif /* !OC_IPV4 */

  DWORD NumberOfBytes = 0;
  int bytes_sent = 0;
  while (bytes_sent < (int)message->length) {
    WSABuf.buf = (CHAR *)(message->data + bytes_sent);
    WSABuf.len = (ULONG)(message->length - bytes_sent);
    if (PWSASendMsg(sock, &Msg, 0, &NumberOfBytes, NULL, NULL) ==
        SOCKET_ERROR) {
      OC_WRN("WSASendMsg() returned errno %d", WSAGetLastError());
      break;
    }
    bytes_sent += (int)NumberOfBytes;
  }
  OC_TRACE("Sent %d bytes", bytes_sent);

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

  SOCKET send_sock = INVALID_SOCKET;
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
  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);
  if (dev == NULL) {
    OC_ERR("cannot send discovery request: device(%zu) ip-context not found",
           message->endpoint.device);
    return;
  }

  ifaddr_t *ifaddr_list = get_network_addresses();
  ifaddr_t *ifaddr;

  for (ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    if (message->endpoint.flags & IPV6 && ifaddr->addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ifaddr->addr;
      DWORD mif = (DWORD)ifaddr->if_index;
      if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                     (char *)&mif, sizeof(mif)) == SOCKET_ERROR) {
        OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d",
               WSAGetLastError());
        goto done;
      }
      if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        message->endpoint.addr.ipv6.scope = (uint8_t)ifaddr->if_index;
      }
      message->endpoint.interface_index = ifaddr->if_index;
      memcpy(message->endpoint.addr_local.ipv6.address, addr->sin6_addr.u.Byte,
             16);
      oc_send_buffer(message);
#ifdef OC_IPV4
    } else if (message->endpoint.flags & IPV4 &&
               ifaddr->addr.ss_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)&ifaddr->addr;
      if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_MULTICAST_IF,
                     (char *)&addr->sin_addr,
                     sizeof(addr->sin_addr)) == SOCKET_ERROR) {
        OC_ERR("setting socket option for default IP_MULTICAST_IF: %d",
               WSAGetLastError());
        goto done;
      }
      DWORD ttl = OC_IPV4_MULTICAST_TTL;
      if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_MULTICAST_TTL,
                     (char *)&ttl, sizeof(DWORD)) == -1) {
        OC_ERR("setting socket option for default IP_MULTICAST_TTL: %d",
               WSAGetLastError());
        goto done;
      }
      message->endpoint.interface_index = ifaddr->if_index;
      memcpy(message->endpoint.addr_local.ipv4.address,
             &addr->sin_addr.S_un.S_addr, 4);
      oc_send_buffer(message);
    }
#else  /* OC_IPV4 */
    }
#endif /* ! OC_IPV4 */
  }
done:
  free_network_addresses(ifaddr_list);
}
#endif /* OC_CLIENT */

#ifdef OC_IPV4
static int
connectivity_ipv4_init(ip_context_t *dev)
{
  OC_DBG("Initializing IPv4 connectivity for device %zd", dev->device);
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
  if (dev->secure4_sock == (SOCKET)SOCKET_ERROR) {
    OC_ERR("creating secure IPv4 socket");
    return -1;
  }
#endif /* OC_SECURITY */

  dev->server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server4_sock == (SOCKET)SOCKET_ERROR ||
      dev->mcast4_sock == (SOCKET)SOCKET_ERROR) {
    OC_ERR("creating IPv4 server sockets");
    return -1;
  }

  int on = 1;
  if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting pktinfo IPv4 option %d\n", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->server4_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->server4_sock, (struct sockaddr *)&dev->server4,
           sizeof(dev->server4)) == SOCKET_ERROR) {
    OC_ERR("binding server4 socket %d", WSAGetLastError());
    return -1;
  }

  socklen_t socklen = sizeof(dev->server4);
  if (getsockname(dev->server4_sock, (struct sockaddr *)&dev->server4,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining server4 socket information %d", WSAGetLastError());
    return -1;
  }

  dev->port4 = ntohs(l->sin_port);

  if (update_mcast_socket(dev->mcast4_sock, AF_INET, NULL) < 0) {
    OC_WRN("could not configure IPv4 mcast socket at this time..will reattempt "
           "on the next network interface update");
  }

  if (setsockopt(dev->mcast4_sock, IPPROTO_IP, IP_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting pktinfo IPv4 option %d\n", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr IPv4 option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->mcast4_sock, (struct sockaddr *)&dev->mcast4,
           sizeof(dev->mcast4)) == SOCKET_ERROR) {
    OC_ERR("binding mcast IPv4 socket %d", WSAGetLastError());
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure4_sock, IPPROTO_IP, IP_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting pktinfo IPV4 option %d\n", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->secure4_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr IPv4 option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
           sizeof(dev->secure4)) == SOCKET_ERROR) {
    OC_ERR("binding IPv4 secure socket %d", WSAGetLastError());
    return -1;
  }

  socklen = sizeof(dev->secure4);
  if (getsockname(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining DTLS4 socket information %d", WSAGetLastError());
    return -1;
  }

  dev->dtls4_port = ntohs(sm->sin_port);
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized IPv4 connectivity for device %zd",
         dev->device);

  return 0;
}
#endif

#ifdef OC_NETWORK_MONITOR
int
oc_add_network_interface_event_callback(interface_event_handler_t cb)
{
  if (!cb)
    return -1;

  mutex_lock(oc_network_interface_cb_mutex);
  oc_network_interface_cb_t *cb_item =
    oc_memb_alloc(&oc_network_interface_cb_s);
  if (!cb_item) {
    mutex_unlock(oc_network_interface_cb_mutex);
    OC_ERR("network interface callback item alloc failed");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_network_interface_cb_list, cb_item);
  mutex_unlock(oc_network_interface_cb_mutex);
  return 0;
}

int
oc_remove_network_interface_event_callback(interface_event_handler_t cb)
{
  if (!cb)
    return -1;

  mutex_lock(oc_network_interface_cb_mutex);
  oc_network_interface_cb_t *cb_item =
    oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL && cb_item->handler != cb) {
    cb_item = cb_item->next;
  }
  if (!cb_item) {
    mutex_unlock(oc_network_interface_cb_mutex);
    return -1;
  }
  oc_list_remove(oc_network_interface_cb_list, cb_item);
  oc_memb_free(&oc_network_interface_cb_s, cb_item);
  mutex_unlock(oc_network_interface_cb_mutex);
  return 0;
}

void
handle_network_interface_event_callback(oc_interface_event_t event)
{
  mutex_lock(oc_network_interface_cb_mutex);
  oc_network_interface_cb_t *cb_item =
    oc_list_head(oc_network_interface_cb_list);
  while (cb_item) {
    cb_item->handler(event);
    cb_item = cb_item->next;
  }
  mutex_unlock(oc_network_interface_cb_mutex);
}
#endif /* OC_NETWORK_MONITOR */

int
oc_connectivity_init(size_t device, oc_connectivity_ports_t ports)
{
  // TODO set ports
  (void)ports;
  if (!ifchange_initialized) {
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);
  }

  OC_DBG("Initializing connectivity for device %zd", device);
  ip_context_t *dev = (ip_context_t *)oc_memb_alloc(&g_ip_context_s);
  if (dev == NULL) {
    oc_abort("Insufficient memory");
  }

#ifdef OC_DYNAMIC_ALLOCATION
  dev->wake_up_event = WSACreateEvent();
  if (dev->wake_up_event == WSA_INVALID_EVENT) {
    OC_ERR("Creating wake up event for network event thread");
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  dev->device = device;
  OC_LIST_STRUCT_INIT(dev, eps);
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

  if (dev->server_sock == (SOCKET)SOCKET_ERROR ||
      dev->mcast_sock == (SOCKET)SOCKET_ERROR) {
    OC_ERR("creating server sockets");
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

#ifdef OC_SECURITY
  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock == (SOCKET)SOCKET_ERROR) {
    OC_ERR("creating secure socket");
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
#endif /* OC_SECURITY */

  int on = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting sock option %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
  if (setsockopt(dev->server_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == SOCKET_ERROR) {
    OC_ERR("binding server socket %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining server socket information %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

  dev->port = ntohs(l->sin6_port);

  if (update_mcast_socket(dev->mcast_sock, AF_INET6, NULL) < 0) {
    OC_WRN("could not configure IPv6 mcast socket at this time..will reattempt "
           "on the next network interface update");
  }

  if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast,
           sizeof(dev->mcast)) == SOCKET_ERROR) {
    OC_ERR("binding mcast socket %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }
  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure,
           sizeof(dev->secure)) == SOCKET_ERROR) {
    OC_ERR("binding IPv6 secure socket %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining secure socket information %d", WSAGetLastError());
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

  dev->dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4");
  }
#endif /* OC_IPV4 */

#ifdef OC_TCP
  if (oc_tcp_connectivity_init(dev) != 0) {
    OC_ERR("Could not initialize TCP adapter");
  }
#endif /* OC_TCP */

  if (!ifchange_initialized) {
    ifchange_sock =
      WSASocketW(AF_INET6, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (ifchange_sock == INVALID_SOCKET) {
      OC_ERR("creating socket to track network interface changes");
      oc_memb_free(&g_ip_context_s, dev);
      return -1;
    }
    BOOL v6_only = FALSE;
    if (setsockopt(ifchange_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6_only,
                   sizeof(v6_only)) == SOCKET_ERROR) {
      OC_ERR("setting socket option to make it dual IPv4/v6");
      oc_memb_free(&g_ip_context_s, dev);
      return -1;
    }
    ifchange_event.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ifchange_event.hEvent == NULL) {
      OC_ERR("creating network interface change event");
      oc_memb_free(&g_ip_context_s, dev);
      return -1;
    }
    if (WSAEventSelect(ifchange_sock, ifchange_event.hEvent,
                       FD_ADDRESS_LIST_CHANGE) == SOCKET_ERROR) {
      OC_ERR("binding network interface change event to socket");
      oc_memb_free(&g_ip_context_s, dev);
      return -1;
    }
    DWORD bytes_returned = 0;
    if (WSAIoctl(ifchange_sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0,
                 &bytes_returned, &ifchange_event, NULL) == SOCKET_ERROR) {
      DWORD err = GetLastError();
      if (err != ERROR_IO_PENDING) {
        OC_ERR("could not set SIO_ADDRESS_LIST_CHANGE on network interface "
               "change socket");
        oc_memb_free(&g_ip_context_s, dev);
        return -1;
      }
    }
    ifchange_initialized = TRUE;
  }

  dev->event_thread_handle =
    CreateThread(0, 0, network_event_thread, dev, 0, &dev->event_thread);
  if (dev->event_thread_handle == NULL) {
    OC_ERR("creating network polling thread");
    oc_memb_free(&g_ip_context_s, dev);
    return -1;
  }

  OC_DBG("Successfully initialized connectivity for device %zd", device);
  oc_network_event_handler_mutex_lock();
  oc_list_add(g_ip_contexts, dev);
  oc_network_event_handler_mutex_unlock();

  return 0;
}

void
oc_connectivity_wakeup(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  if (dev == NULL) {
    OC_WRN("no ip-context found for device(%zu)", device);
    return;
  }

  if (WSASetEvent(dev->wake_up_event) == FALSE) {
    OC_WRN("cannot wake up network event thread (error: %d)",
           WSAGetLastError());
  }
}

void
oc_connectivity_shutdown(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  if (dev == NULL) {
    OC_WRN("no ip-context found for device(%zu)", device);
    return;
  }

  dev->terminate = TRUE;
  /* signal WSASelectEvent() in the thread to leave */
  WSASetEvent(dev->event_server_handle);

  WaitForSingleObject(dev->event_thread_handle, INFINITE);
  TerminateThread(dev->event_thread_handle, 0);

  closesocket(dev->server_sock);
  closesocket(dev->mcast_sock);

#ifdef OC_IPV4
  closesocket(dev->server4_sock);
  closesocket(dev->mcast4_sock);
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  closesocket(dev->secure_sock);
#ifdef OC_IPV4
  closesocket(dev->secure4_sock);
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

#ifdef OC_TCP
  oc_tcp_connectivity_shutdown(dev);
#endif /* OC_TCP */

  free_endpoints_list(dev);

  oc_network_event_handler_mutex_lock();
  oc_list_remove(g_ip_contexts, dev);
  oc_network_event_handler_mutex_unlock();
  oc_memb_free(&g_ip_context_s, dev);

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
      return oc_tcp_end_session(endpoint, notify_session_end, session_endpoint);
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
    char address[INET6_ADDRSTRLEN + 2] = { 0 };
    const char *dest = NULL;
    if (flags & IPV6) {
      struct sockaddr_in6 *sock_addr = (struct sockaddr_in6 *)result->ai_addr;
      address[0] = '[';
      dest = inet_ntop(AF_INET6, (void *)&sock_addr->sin6_addr, address + 1,
                       INET6_ADDRSTRLEN);
      size_t addr_len = strlen(address);
      address[addr_len] = ']';
      address[addr_len + 1] = '\0';
    }
#ifdef OC_IPV4
    else {
      struct sockaddr_in *sock_addr = (struct sockaddr_in *)result->ai_addr;
      dest = inet_ntop(AF_INET, (void *)&sock_addr->sin_addr, address,
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

  return ret;
}
#endif /* OC_DNS_LOOKUP */
