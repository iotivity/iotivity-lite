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

typedef struct ip_context_t
{
  struct ip_context_t *next;
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
  mutex = CreateMutex(NULL, FALSE, NULL);
  if (mutex == NULL) {
    oc_abort("error initializing network event handler mutex\n");
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
  CloseHandle(mutex);
  closesocket(ifchange_sock);
  WSACleanup();
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
      OC_ERR("not enough memory to run GetAdaptersAddresses\n");
      return NULL;
    }
    dwRetVal = GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, NULL,
                                    interface_list, &out_buf_len);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      OC_ERR("retry GetAdaptersAddresses with out_buf_len=%d\n", out_buf_len);
      free(interface_list);
      interface_list = NULL;
      continue;
    }
    break;
  }
  if (interface_list == NULL) {
    OC_ERR("failed to run GetAdaptersAddresses\n");
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
      OC_DBG("processing interface %ws:\n", interface->FriendlyName);
    }
#endif /* OC_DEBUG */

    for (address = interface->FirstUnicastAddress; address;
         address = address->Next) {
      ifaddr_t *ifaddr = NULL;

#ifdef OC_IPV4
      if (address->Address.lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *addr =
          (struct sockaddr_in *)address->Address.lpSockaddr;
        ifaddr = calloc(1, sizeof(ifaddr_t));
        if (ifaddr == NULL) {
          OC_ERR("no memory for ifaddr\n");
          goto cleanup;
        }
        memcpy(&ifaddr->addr, addr, sizeof(struct sockaddr_in));
        ifaddr->if_index = interface->IfIndex;
      }
#endif /* OC_IPV4 */
      if (address->Address.lpSockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr =
          (struct sockaddr_in6 *)address->Address.lpSockaddr;
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
        ifaddr = calloc(1, sizeof(ifaddr_t));
        if (ifaddr == NULL) {
          OC_ERR("no memory for ifaddr\n");
          goto cleanup;
        }
        memcpy(&ifaddr->addr, addr, sizeof(struct sockaddr_in6));
        ifaddr->if_index = interface->Ipv6IfIndex;
      }
      if (ifaddr) {
        ifaddr->next = ifaddr_list;
        ifaddr_list = ifaddr;
      }
    }
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
    OC_ERR("joining IPv4 multicast group %d\n", errno);
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
    OC_ERR("joining link-local IPv6 multicast group %d\n", errno);
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
    OC_ERR("joining realm-local IPv6 multicast group %d\n", errno);
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
    OC_ERR("joining site-local IPv6 multicast group %d\n", errno);
    return -1;
  }

  return 0;
}

static int
update_mcast_socket(SOCKET mcast_sock, int sa_family)
{
  int ret = 0;
  ifaddr_t *ifaddrs = get_network_addresses(), *ifaddr;
  if (!ifaddrs) {
    OC_ERR("could not obtain list of network addresses\n");
    return -1;
  }

  for (ifaddr = ifaddrs; ifaddr; ifaddr = ifaddr->next) {
    if (sa_family == AF_INET6 && ifaddr->addr.ss_family == AF_INET6) {
      ret += add_mcast_sock_to_ipv6_mcast_group(mcast_sock, ifaddr->if_index);
    } else if (sa_family == AF_INET && ifaddr->addr.ss_family == AF_INET) {
      struct sockaddr_in *a = (struct sockaddr_in *)&ifaddr->addr;
      ret += add_mcast_sock_to_ipv4_mcast_group(mcast_sock, &a->sin_addr);
    }
  }

  free_network_addresses(ifaddrs);

  return ret;
}

static int
process_interface_change_event(void)
{
  int ret = 0, num_devices = oc_core_get_num_devices(), i;

  for (i = 0; i < num_devices; i++) {
    ip_context_t *dev = get_ip_context_for_device(i);
    ret += update_mcast_socket(dev->mcast_sock, AF_INET6);
    ret += update_mcast_socket(dev->mcast4_sock, AF_INET);
  }

  return ret;
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

  struct sockaddr_storage client;
  memset(&client, 0, sizeof(client));
  struct sockaddr_in6 *c = (struct sockaddr_in6 *)&client;
  socklen_t len = sizeof(client);

#ifdef OC_IPV4
  struct sockaddr_in *c4 = (struct sockaddr_in *)&client;
#endif

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
          OC_WRN("WSAResetEvent returned error: %d\n", WSAGetLastError());
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
                     "interface change socket\n");
            }
          }
          continue;
        }

        len = sizeof(client);
        oc_message_t *message = oc_allocate_message();

        if (!message) {
          break;
        }

        if (i == SERVER6) {
          int count =
            recvfrom(dev->server_sock, (char *)message->data, OC_PDU_SIZE, 0,
                     (struct sockaddr *)&client, &len);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6;
          message->endpoint.device = dev->device;
          goto common;
        }

        if (i == MCAST6) {
          int count =
            recvfrom(dev->mcast_sock, (char *)message->data, OC_PDU_SIZE, 0,
                     (struct sockaddr *)&client, &len);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6;
          message->endpoint.device = dev->device;
          goto common;
        }

#ifdef OC_IPV4
        if (i == SERVER4) {
          int count =
            recvfrom(dev->server4_sock, (char *)message->data, OC_PDU_SIZE, 0,
                     (struct sockaddr *)&client, &len);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4;
          message->endpoint.device = dev->device;
          goto common;
        }

        if (i == MCAST4) {
          int count =
            recvfrom(dev->mcast4_sock, (char *)message->data, OC_PDU_SIZE, 0,
                     (struct sockaddr *)&client, &len);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4;
          message->endpoint.device = dev->device;
          goto common;
        }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
        if (i == SECURE6) {
          int count =
            recvfrom(dev->secure_sock, (char *)message->data, OC_PDU_SIZE, 0,
                     (struct sockaddr *)&client, &len);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6 | SECURED;
          message->endpoint.device = dev->device;
          goto common;
        }
#ifdef OC_IPV4
        if (i == SECURE4) {
          int count =
            recvfrom(dev->secure4_sock, (char *)message->data, OC_PDU_SIZE, 0,
                     (struct sockaddr *)&client, &len);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV4 | SECURED;
          message->endpoint.device = dev->device;
        }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */
      common:
#ifdef OC_IPV4
        if (message->endpoint.flags & IPV4) {
          memcpy(message->endpoint.addr.ipv4.address, &c4->sin_addr.s_addr,
                 sizeof(c4->sin_addr.s_addr));
          message->endpoint.addr.ipv4.port = ntohs(c4->sin_port);
        } else if (message->endpoint.flags & IPV6) {
#else  /* OC_IPV4 */
        if (message->endpoint.flags & IPV6) {
#endif /* !OC_IPV4 */
          memcpy(message->endpoint.addr.ipv6.address, c->sin6_addr.s6_addr,
                 sizeof(c->sin6_addr.s6_addr));
          message->endpoint.addr.ipv6.scope = (uint8_t)c->sin6_scope_id;
          message->endpoint.addr.ipv6.port = ntohs(c->sin6_port);
        }

#ifdef OC_DEBUG
        PRINT("Incoming message of size %d bytes from ", message->length);
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
  oc_abort("err in network event thread\n");
  return NULL;
}

static void
get_interface_addresses(unsigned char family, uint16_t port, bool secure)
{
  ifaddr_t *ifaddr_list = get_network_addresses();
  ifaddr_t *ifaddr;

  oc_endpoint_t ep = { 0 };

  if (secure) {
    ep.flags = SECURED;
  }

  for (ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    if (family == AF_INET6 && ifaddr->addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ifaddr->addr;
      memcpy(ep.addr.ipv6.address, &addr->sin6_addr, sizeof(addr->sin6_addr));
      ep.flags |= IPV6;
      ep.addr.ipv6.port = port;
      ep.addr.ipv6.scope = (uint8_t)addr->sin6_scope_id;
      if (oc_add_endpoint_to_list(&ep) == -1) {
        OC_ERR("oc_add_endpoint_to_list failed.\n");
        break;
      }
      continue;
    }
#ifdef OC_IPV4
    if (family == AF_INET && ifaddr->addr.ss_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)&ifaddr->addr;
      memcpy(ep.addr.ipv4.address, &addr->sin_addr, sizeof(addr->sin_addr));
      ep.flags |= IPV4;
      ep.addr.ipv4.port = port;
      if (oc_add_endpoint_to_list(&ep) == -1) {
        OC_ERR("oc_add_endpoint_to_list failed.\n");
        break;
      }
      continue;
    }
#endif
  }
  free_network_addresses(ifaddr_list);
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  oc_init_endpoint_list();
  ip_context_t *dev = get_ip_context_for_device(device);
  get_interface_addresses(AF_INET6, dev->port, false);
#ifdef OC_SECURITY
  get_interface_addresses(AF_INET6, dev->dtls_port, true);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  get_interface_addresses(AF_INET, dev->port4, false);
#ifdef OC_SECURITY
  get_interface_addresses(AF_INET, dev->dtls4_port, true);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  return oc_get_endpoint_list();
}

void
oc_send_buffer(oc_message_t *message)
{
#ifdef OC_DEBUG
  PRINT("Outgoing message of size %d bytes to ", message->length);
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

  int bytes_sent = 0, x;
  while (bytes_sent < (int)message->length) {
    x = sendto(send_sock, (const char *)(message->data + bytes_sent),
               message->length - bytes_sent, 0, (struct sockaddr *)&receiver,
               sizeof(receiver));
    if (x == SOCKET_ERROR) {
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
  ifaddr_t *ifaddr_list = get_network_addresses();
  ifaddr_t *ifaddr;

  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);

  for (ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    if (message->endpoint.flags & IPV6 && ifaddr->addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ifaddr->addr;
      int mif = addr->sin6_scope_id;
      if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                     (char *)&mif, sizeof(mif)) == SOCKET_ERROR) {
        OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d\n",
               errno);
        goto done;
      }
      oc_send_buffer(message);
#ifdef OC_IPV4
    } else if (message->endpoint.flags & IPV4 &&
               ifaddr->addr.ss_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)&ifaddr->addr;
      if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_MULTICAST_IF,
                     (char *)&addr->sin_addr,
                     sizeof(addr->sin_addr)) == SOCKET_ERROR) {
        OC_ERR("setting socket option for default IP_MULTICAST_IF: %d\n",
               errno);
        goto done;
      }
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
  if (dev->secure4_sock == SOCKET_ERROR) {
    OC_ERR("creating secure IPv4 socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  dev->server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server4_sock == SOCKET_ERROR || dev->mcast4_sock == SOCKET_ERROR) {
    OC_ERR("creating IPv4 server sockets\n");
    return -1;
  }

  if (bind(dev->server4_sock, (struct sockaddr *)&dev->server4,
           sizeof(dev->server4)) == SOCKET_ERROR) {
    OC_ERR("binding server4 socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server4);
  if (getsockname(dev->server4_sock, (struct sockaddr *)&dev->server4,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining server4 socket information %d\n", errno);
    return -1;
  }

  dev->port4 = ntohs(l->sin_port);

  if (update_mcast_socket(dev->mcast4_sock, AF_INET) < 0) {
    OC_WRN("could not configure IPv4 mcast socket at this time..will reattempt "
           "on the next network interface update\n");
  }

  int reuse = 1;
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }
  if (bind(dev->mcast4_sock, (struct sockaddr *)&dev->mcast4,
           sizeof(dev->mcast4)) == SOCKET_ERROR) {
    OC_ERR("binding mcast IPv4 socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure4_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }

  if (bind(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
           sizeof(dev->secure4)) == SOCKET_ERROR) {
    OC_ERR("binding IPv4 secure socket %d\n", errno);
    return -1;
  }

  socklen = sizeof(dev->secure4);
  if (getsockname(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
                  &socklen) == SOCKET_ERROR) {
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

int
oc_connectivity_init(int device)
{
  if (!ifchange_initialized) {
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);
  }

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

  if (dev->server_sock == SOCKET_ERROR || dev->mcast_sock == SOCKET_ERROR) {
    OC_ERR("creating server sockets\n");
    return -1;
  }

#ifdef OC_SECURITY
  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock == SOCKET_ERROR) {
    OC_ERR("creating secure socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  int opt = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt,
                 sizeof(opt)) == SOCKET_ERROR) {
    OC_ERR("setting sock option %d\n", errno);
    return -1;
  }

  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == SOCKET_ERROR) {
    OC_ERR("binding server socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining server socket information %d\n", errno);
    return -1;
  }

  dev->port = ntohs(l->sin6_port);

  if (update_mcast_socket(dev->mcast_sock, AF_INET6) < 0) {
    OC_WRN("could not configure IPv6 mcast socket at this time..will reattempt "
           "on the next network interface update\n");
  }

  int reuse = 1;
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast,
           sizeof(dev->mcast)) == SOCKET_ERROR) {
    OC_ERR("binding mcast socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure,
           sizeof(dev->secure)) == SOCKET_ERROR) {
    OC_ERR("binding IPv6 secure socket %d\n", errno);
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure,
                  &socklen) == SOCKET_ERROR) {
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

  if (!ifchange_initialized) {
    ifchange_sock =
      WSASocketW(AF_INET6, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (ifchange_sock == INVALID_SOCKET) {
      OC_ERR("creating socket to track network interface changes\n");
      return -1;
    }
    BOOL v6_only = FALSE;
    if (setsockopt(ifchange_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6_only,
                   sizeof(v6_only)) == SOCKET_ERROR) {
      OC_ERR("setting socket option to make it dual IPv4/v6\n");
      return -1;
    }
    ifchange_event.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ifchange_event.hEvent == NULL) {
      OC_ERR("creating network interface change event\n");
      return -1;
    }
    if (WSAEventSelect(ifchange_sock, ifchange_event.hEvent,
                       FD_ADDRESS_LIST_CHANGE) == SOCKET_ERROR) {
      OC_ERR("binding network interface change event to socket\n");
      return -1;
    }
    DWORD bytes_returned = 0;
    if (WSAIoctl(ifchange_sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0,
                 &bytes_returned, &ifchange_event, NULL) == SOCKET_ERROR) {
      DWORD err = GetLastError();
      if (err != ERROR_IO_PENDING) {
        OC_ERR("could not set SIO_ADDRESS_LIST_CHANGE on network interface "
               "change socket\n");
        return -1;
      }
    }
    ifchange_initialized = TRUE;
  }

  dev->event_thread_handle =
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network_event_thread, dev, 0,
                 &dev->event_thread);
  if (dev->event_thread_handle == NULL) {
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

#ifdef OC_DYNAMIC_ALLOCATION
  oc_list_remove(ip_contexts, dev);
  free(dev);
#endif /* OC_DYNAMIC_ALLOCATION */

  OC_DBG("oc_connectivity_shutdown for device %d\n", device);
}
