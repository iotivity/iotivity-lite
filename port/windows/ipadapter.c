/*
// Copyright (c) 2017 Lynx Technology
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

#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Mswsock.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <malloc.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"

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

static HANDLE mutex;
SOCKET ifchange_sock;
BOOL ifchange_initialized;
OVERLAPPED ifchange_event;
static LPFN_WSARECVMSG PWSARecvMsg;
static LPFN_WSASENDMSG PWSASendMsg;

typedef struct ip_context_t
{
  struct ip_context_t *next;
  OC_LIST_STRUCT(eps);
  struct sockaddr_storage mcast;
  struct sockaddr_storage server;
  SOCKET mcast_sock;
  SOCKET server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  struct sockaddr_storage secure;
  SOCKET secure_sock;
  uint16_t dtls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  struct sockaddr_storage mcast4;
  struct sockaddr_storage server4;
  SOCKET mcast4_sock;
  SOCKET server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  struct sockaddr_storage secure4;
  SOCKET secure4_sock;
  uint16_t dtls4_port;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  HANDLE event_thread_handle;
  HANDLE event_server_handle;
  DWORD event_thread;
  BOOL terminate;
  size_t device;
} ip_context_t;

#ifdef OC_DYNAMIC_ALLOCATION
OC_LIST(ip_contexts);
#else /* OC_DYNAMIC_ALLOCATION */
static ip_context_t devices[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

OC_MEMB(device_eps, oc_endpoint_t, 1);

void
oc_network_event_handler_mutex_init(void)
{
  mutex = CreateMutex(NULL, FALSE, NULL);
  if (mutex == NULL) {
    oc_abort("error initializing network event handler mutex");
  }
}

void
oc_network_event_handler_mutex_lock(void)
{
  WaitForSingleObject(mutex, INFINITE);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  ReleaseMutex(mutex);
}

void
oc_network_event_handler_mutex_destroy(void)
{
  ifchange_initialized = false;
  CloseHandle(mutex);
  closesocket(ifchange_sock);
  WSACleanup();
}

static ip_context_t *
get_ip_context_for_device(size_t device)
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

typedef struct ifaddr_t
{
  struct ifaddr_t *next;
  struct sockaddr_storage addr;
  DWORD if_index;
} ifaddr_t;

static ifaddr_t *
get_network_addresses()
{
  ifaddr_t *ifaddr_list = NULL;
  ULONG family = AF_INET6;
  int i, max_retries = 5;
  IP_ADAPTER_ADDRESSES *interface_list = NULL;
  IP_ADAPTER_ADDRESSES *interface = NULL;
  ULONG out_buf_len = 8000;

#ifdef OC_IPV4
  family = AF_UNSPEC;
#endif /* OC_IPV4 */

  for (i = 0; i < max_retries; i++) {
    DWORD dwRetVal = 0;
    interface_list = calloc(1, out_buf_len);
    if (interface_list == NULL) {
      OC_ERR("not enough memory to run GetAdaptersAddresses");
      return NULL;
    }
    dwRetVal = GetAdaptersAddresses(
      family, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
      NULL, interface_list, &out_buf_len);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      OC_ERR("retry GetAdaptersAddresses with out_buf_len=%d", out_buf_len);
      free(interface_list);
      interface_list = NULL;
      continue;
    }
    break;
  }

  if (interface_list == NULL) {
    OC_ERR("failed to run GetAdaptersAddresses");
    return NULL;
  }

  for (interface = interface_list; interface != NULL;
       interface = interface->Next) {
    IP_ADAPTER_UNICAST_ADDRESS *address = NULL;
    if (IfOperStatusUp != interface->OperStatus ||
        interface->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }

#ifdef OC_DEBUG
    if (interface->FriendlyName) {
      OC_DBG("processing interface %ws:", interface->FriendlyName);
    }
#endif /* OC_DEBUG */
       /* Process all IPv4 addresses on this interface. */
#ifdef OC_IPV4
    for (address = interface->FirstUnicastAddress; address;
         address = address->Next) {
      ifaddr_t *ifaddr = NULL;
      if (address->Address.lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *addr =
          (struct sockaddr_in *)address->Address.lpSockaddr;
        ifaddr = calloc(1, sizeof(ifaddr_t));
        if (ifaddr == NULL) {
          OC_ERR("no memory for ifaddr");
          goto cleanup;
        }
        memcpy(&ifaddr->addr, addr, sizeof(struct sockaddr_in));
        ifaddr->if_index = interface->IfIndex;
        ifaddr->next = ifaddr_list;
        ifaddr_list = ifaddr;
      }
    }
#endif /* OC_IPV4 */
       /* Process all IPv6 addresses on this interface. */
    struct sockaddr_in6 *v6addr = NULL;
    for (address = interface->FirstUnicastAddress; address;
         address = address->Next) {
      if (address->Address.lpSockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr =
          (struct sockaddr_in6 *)address->Address.lpSockaddr;
        /* If the first address we see is link-local save it. */
        if (!v6addr && IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
          v6addr = addr;
        }
        /* If we see a non link-local and DNS_ELIGIBLE address, */
        if (!IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr) &&
            (address->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE)) {
          /* If this is the first address we're seeing, save it. */
          if (!v6addr) {
            v6addr = addr;
          }
          uint8_t b = addr->sin6_addr.u.Byte[0];
          if (!((b & 0xfc) == b) && !((b & 0xfd) == b)) {
            /* We've gotten a non-private global address
             * which we could use. So, break.
             */
            v6addr = addr;
            break;
          } else {
            /* We've gotten a private IPv6 address in global scope. */
            /* If the saved address is link-local, substitute that with this. */
            if (IN6_IS_ADDR_LINKLOCAL(&v6addr->sin6_addr)) {
              v6addr = addr;
            }
            /* Process the remaining addresses on this interface to see if we
            /* can find the global address assigned by our ISP. */
            continue;
          }
        }
        /* If we see a non link-local and non DNS_ELIGIBLE address, ignore it.
         */
        if (!IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr) &&
            !(address->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE)) {
#ifdef OC_DEBUG
          char dotname[NI_MAXHOST] = { 0 };
          getnameinfo((const SOCKADDR *)addr, sizeof(struct sockaddr_in6),
                      dotname, sizeof(dotname), NULL, 0, NI_NUMERICHOST);
          PRINT("%s is not IN6_IS_ADDR_LINKLOCAL and not "
                "IP_ADAPTER_ADDRESS_DNS_ELIGIBLE, skipped.\n",
                dotname);
#endif /* OC_DEBUG */
          continue;
        }
      }
    }
    if (!v6addr) {
      return ifaddr_list;
    }
    ifaddr_t *ifaddr = calloc(1, sizeof(ifaddr_t));
    if (ifaddr == NULL) {
      OC_ERR("no memory for ifaddr");
      goto cleanup;
    }
    memcpy(&ifaddr->addr, v6addr, sizeof(struct sockaddr_in6));
    ifaddr->if_index = interface->Ipv6IfIndex;
    ifaddr->next = ifaddr_list;
    ifaddr_list = ifaddr;
  }

cleanup:
  free(interface_list);

  return ifaddr_list;
}

static void
free_network_addresses(ifaddr_t *ifaddr)
{
  while (ifaddr) {
    ifaddr_t *tmp = ifaddr;
    ifaddr = ifaddr->next;
    free(tmp);
  }
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
    } else if (sa_family == AF_INET && ifaddr->addr.ss_family == AF_INET) {
      struct sockaddr_in *a = (struct sockaddr_in *)&ifaddr->addr;
      ret += add_mcast_sock_to_ipv4_mcast_group(mcast_sock, &a->sin_addr);
    }
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
                        unsigned char family, uint16_t port, bool secure)
{
  ifaddr_t *ifaddr;

  oc_endpoint_t ep = { 0 };

  if (secure) {
    ep.flags = SECURED;
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
      PRINT("Adding address for interface %d\n", ifaddr->if_index);
      PRINTipaddr(ep);
      PRINT("\n\n");
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
      PRINT("Adding address for interface %d\n", ifaddr->if_index);
      PRINTipaddr(ep);
      PRINT("\n\n");
      continue;
    }
#endif
  }
}

static void
refresh_endpoints_list(ip_context_t *dev, ifaddr_t *ifaddr_list)
{
  bool ifaddr_supplied = false;
  free_endpoints_list(dev);
  if (!ifaddr_list) {
    ifaddr_list = get_network_addresses();
  } else {
    ifaddr_supplied = true;
  }
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->port, false);
#ifdef OC_SECURITY
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->dtls_port, true);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  get_interface_addresses(ifaddr_list, dev, AF_INET, dev->port4, false);
#ifdef OC_SECURITY
  get_interface_addresses(ifaddr_list, dev, AF_INET, dev->dtls4_port, true);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  if (!ifaddr_supplied) {
    free_network_addresses(ifaddr_list);
  }
}

static int
process_interface_change_event(void)
{
  int ret = 0;
  size_t num_devices = oc_core_get_num_devices(), i;
  ifaddr_t *ifaddr_list = get_network_addresses();
  if (!ifaddr_list) {
    return -1;
  }

  for (i = 0; i < num_devices; i++) {
    ip_context_t *dev = get_ip_context_for_device(i);
    ret += update_mcast_socket(dev->mcast_sock, AF_INET6, ifaddr_list);
#ifdef OC_IPV4
    ret += update_mcast_socket(dev->mcast4_sock, AF_INET, ifaddr_list);
#endif /* OC_IPV4 */
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev, ifaddr_list);
    oc_network_event_handler_mutex_unlock();
  }

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

  union
  {
#pragma warning(suppress : 4116)
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#pragma warning(suppress : 4116)
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
#pragma warning(suppress : 4116)
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
            oc_endpoint_t *dst =
              oc_connectivity_get_endpoints(endpoint->device);
            while (dst->interface_index != endpoint->interface_index ||
                   !(dst->flags & IPV4)) {
              dst = dst->next;
            }
            memcpy(endpoint->addr_local.ipv4.address, dst->addr.ipv4.address,
                   4);
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
            /* For a multicast receiving socket, check the incoming interface
            * index and save that interface's highest scoped address in the
            * endpoint's addr_local attribute. This would be used as the source
            * address of a multicast response.
            */
            oc_endpoint_t *dst =
              oc_connectivity_get_endpoints(endpoint->device);

            while (dst->interface_index != endpoint->interface_index ||
                   !(dst->flags & IPV6)) {
              dst = dst->next;
            }
            memcpy(endpoint->addr_local.ipv6.address, dst->addr.ipv6.address,
                   16);
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

static void *
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

  DWORD events_list_size = 0;
  WSAEVENT events_list[7];
  DWORD IFCHANGE = 0;
  if (dev->device == 0) {
    events_list[0] = ifchange_event.hEvent;
    events_list_size++;
  }
  DWORD MCAST6 = events_list_size;
  events_list[events_list_size] = mcast6_event;
  events_list_size++;
  DWORD SERVER6 = events_list_size;
  events_list[events_list_size] = server6_event;
  events_list_size++;
#if defined(OC_SECURITY)
  DWORD SECURE6 = events_list_size;
  events_list[events_list_size] = secure6_event;
  events_list_size++;
#if defined(OC_IPV4)
  DWORD MCAST4 = events_list_size;
  events_list[events_list_size] = mcast4_event;
  events_list_size++;
  DWORD SERVER4 = events_list_size;
  events_list[events_list_size] = server4_event;
  events_list_size++;
  DWORD SECURE4 = events_list_size;
  events_list[events_list_size] = secure4_event;
  events_list_size++;
#endif                 /* OC_IPV4 */
#elif defined(OC_IPV4) /* OC_SECURITY */
  DWORD MCAST4 = events_list_size;
  events_list[events_list_size] = mcast4_event;
  events_list_size++;
  DWORD SERVER4 = events_list_size;
  events_list[events_list_size] = server4_event;
  events_list_size++;
#endif                 /* !OC_SECURITY */

  DWORD i, index;

  while (!dev->terminate) {
    index = WSAWaitForMultipleEvents(events_list_size, events_list, FALSE,
                                     INFINITE, FALSE);
    index -= WSA_WAIT_EVENT_0;
    for (i = index; !dev->terminate && i < events_list_size; i++) {
      index = WSAWaitForMultipleEvents(1, &events_list[i], TRUE, 0, FALSE);
      if (index != WSA_WAIT_TIMEOUT && index != WSA_WAIT_FAILED) {
        if (WSAResetEvent(events_list[i]) == FALSE) {
          OC_WRN("WSAResetEvent returned error: %d", WSAGetLastError());
        }
        if (dev->device == 0 && i == IFCHANGE) {
          process_interface_change_event();
          DWORD bytes_returned = 0;
          if (WSAIoctl(ifchange_sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0,
                       &bytes_returned, &ifchange_event,
                       NULL) == SOCKET_ERROR) {
            DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
              OC_ERR("could not reset SIO_ADDRESS_LIST_CHANGE on network "
                     "interface change socket");
            }
          }
          continue;
        }

        oc_message_t *message = oc_allocate_message();

        if (!message) {
          break;
        }

        message->endpoint.device = dev->device;

        if (i == SERVER6) {
          int count = recv_msg(dev->server_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6;
          goto common;
        }

        if (i == MCAST6) {
          int count = recv_msg(dev->mcast_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, true);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6 | MULTICAST;
          goto common;
        }

#ifdef OC_IPV4
        if (i == SERVER4) {
          int count = recv_msg(dev->server4_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4;
          goto common;
        }

        if (i == MCAST4) {
          int count = recv_msg(dev->mcast4_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, true);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4 | MULTICAST;
          goto common;
        }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
        if (i == SECURE6) {
          int count = recv_msg(dev->secure_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6 | SECURED;
          goto common;
        }
#ifdef OC_IPV4
        if (i == SECURE4) {
          int count = recv_msg(dev->secure4_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4 | SECURED;
        }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */
      common:
#ifdef OC_DEBUG
        PRINT("Incoming message of size %zd bytes from ", message->length);
        PRINTipaddr(message->endpoint);
        PRINT("\n\n");
#endif /* OC_DEBUG */
        oc_network_event(message);
      }
    }
  }

  for (i = 0; i < events_list_size; ++i) {
    WSACloseEvent(events_list[i]);
  }

  return NULL;

network_event_thread_error:
  oc_abort("err in network event thread");
  return NULL;
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
    refresh_endpoints_list(dev, NULL);
    oc_network_event_handler_mutex_unlock();
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
                                 int address_size, int interface_index)
{
  if (!check_if_address_unset(address, address_size)) {
    return;
  }
  ifaddr_t *ifaddr_list = get_network_addresses(), *addr;
  for (addr = ifaddr_list; addr != NULL; addr = addr->next) {
    if (addr->addr.ss_family == family &&
        (int)addr->if_index == interface_index) {
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

int
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

  union
  {
#pragma warning(suppress : 4116)
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#pragma warning(suppress : 4116)
    char in6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_buf;

  Msg.Control.buf = (char *)&control_buf;

  if (message->endpoint.flags & IPV6) {
    Msg.namelen = sizeof(struct sockaddr_in6);

#pragma warning(suppress : 4116)
    Msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));

#pragma warning(suppress : 4116)
    MsgHdr = WSA_CMSG_FIRSTHDR(&Msg);
#pragma warning(suppress : 4116)
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
#pragma warning(suppress : 4116)
    Msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in_pktinfo));

#pragma warning(suppress : 4116)
    MsgHdr = WSA_CMSG_FIRSTHDR(&Msg);
#pragma warning(suppress : 4116)
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
      OC_WRN("WSASendMsg() returned %d", WSAGetLastError());
      break;
    }
    bytes_sent += (int)NumberOfBytes;
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
  PRINT("\n");
#endif /* OC_DEBUG */
  struct sockaddr_storage receiver;
  memset(&receiver, 0, sizeof(receiver));
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
  SOCKET send_sock = INVALID_SOCKET;

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

  return send_msg(send_sock, &receiver, message);
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  ifaddr_t *ifaddr_list = get_network_addresses();
  ifaddr_t *ifaddr;

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

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
  OC_DBG("Initializing IPv4 connectivity for device %d", dev->device);
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
  if (dev->secure4_sock == SOCKET_ERROR) {
    OC_ERR("creating secure IPv4 socket");
    return -1;
  }
#endif /* OC_SECURITY */

  dev->server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server4_sock == SOCKET_ERROR || dev->mcast4_sock == SOCKET_ERROR) {
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

  OC_DBG("Successfully initialized IPv4 connectivity for device %d",
         dev->device);

  return 0;
}
#endif

int
oc_connectivity_init(size_t device)
{
  if (!ifchange_initialized) {
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);
  }

  OC_DBG("Initializing connectivity for device %d", device);
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

  if (dev->server_sock == SOCKET_ERROR || dev->mcast_sock == SOCKET_ERROR) {
    OC_ERR("creating server sockets");
    return -1;
  }

#ifdef OC_SECURITY
  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock == SOCKET_ERROR) {
    OC_ERR("creating secure socket");
    return -1;
  }
#endif /* OC_SECURITY */

  int on = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting sock option %d", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->server_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == SOCKET_ERROR) {
    OC_ERR("binding server socket %d", WSAGetLastError());
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining server socket information %d", WSAGetLastError());
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
    return -1;
  }
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast,
           sizeof(dev->mcast)) == SOCKET_ERROR) {
    OC_ERR("binding mcast socket %d", WSAGetLastError());
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure,
           sizeof(dev->secure)) == SOCKET_ERROR) {
    OC_ERR("binding IPv6 secure socket %d", WSAGetLastError());
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining secure socket information %d", WSAGetLastError());
    return -1;
  }

  dev->dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4");
  }
#endif /* OC_IPV4 */

  if (!ifchange_initialized) {
    ifchange_sock =
      WSASocketW(AF_INET6, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (ifchange_sock == INVALID_SOCKET) {
      OC_ERR("creating socket to track network interface changes");
      return -1;
    }
    BOOL v6_only = FALSE;
    if (setsockopt(ifchange_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6_only,
                   sizeof(v6_only)) == SOCKET_ERROR) {
      OC_ERR("setting socket option to make it dual IPv4/v6");
      return -1;
    }
    ifchange_event.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ifchange_event.hEvent == NULL) {
      OC_ERR("creating network interface change event");
      return -1;
    }
    if (WSAEventSelect(ifchange_sock, ifchange_event.hEvent,
                       FD_ADDRESS_LIST_CHANGE) == SOCKET_ERROR) {
      OC_ERR("binding network interface change event to socket");
      return -1;
    }
    DWORD bytes_returned = 0;
    if (WSAIoctl(ifchange_sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0,
                 &bytes_returned, &ifchange_event, NULL) == SOCKET_ERROR) {
      DWORD err = GetLastError();
      if (err != ERROR_IO_PENDING) {
        OC_ERR("could not set SIO_ADDRESS_LIST_CHANGE on network interface "
               "change socket");
        return -1;
      }
    }
    ifchange_initialized = TRUE;
  }

  dev->event_thread_handle =
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network_event_thread, dev, 0,
                 &dev->event_thread);
  if (dev->event_thread_handle == NULL) {
    OC_ERR("creating network polling thread");
    return -1;
  }

  OC_DBG("Successfully initialized connectivity for device %d", device);

  return 0;
}

void
oc_connectivity_shutdown(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  dev->terminate = TRUE;
  /* signal WSASelectEvent() in the thread to leave */
  WSASetEvent(dev->event_server_handle);

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

  WaitForSingleObject(dev->event_thread_handle, INFINITE);
  TerminateThread(dev->event_thread_handle, 0);

  free_endpoints_list(dev);

#ifdef OC_DYNAMIC_ALLOCATION
  oc_list_remove(ip_contexts, dev);
  free(dev);
#endif /* OC_DYNAMIC_ALLOCATION */

  OC_DBG("oc_connectivity_shutdown for device %d", device);
}
