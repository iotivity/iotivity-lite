/*
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

#define WIN32_LEAN_AND_MEAN
#include <malloc.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#undef NO_ERROR

#include "oc_buffer.h"
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

// the Windows critical section stuff is here,
// because many definitions in <windows.h> collide with iotivity, e.g. INT, BOOL
// etc. There is no conflict when only including oc_buffer.h

static CRITICAL_SECTION cs;
static CONDITION_VARIABLE cv;

void
infinite_wait_for_event()
{
  SleepConditionVariableCS(&cv, &cs, INFINITE);
}

void
ms_wait_for_event(int ms)
{
  SleepConditionVariableCS(&cv, &cs, ms);
}

void
event_has_arrived()
{
  WakeConditionVariable(&cv);
}

static HANDLE thread_handle;
static DWORD event_thread;
static HANDLE mutex;
static struct sockaddr_storage mcast, server, client;
static int server_sock = -1, mcast_sock = -1, terminate;
#ifdef OC_IPV4
static struct sockaddr_storage mcast4, server4;
static int server4_sock = -1, mcast4_sock = -1;
#endif

#ifdef OC_SECURITY
static struct sockaddr_storage secure;
static int secure_sock = -1;
#ifdef OC_IPV4
static struct sockaddr_storage secure4;
static int secure4_sock = -1;
#endif
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
  mutex = CreateMutex(NULL, FALSE, NULL);
  if (mutex == NULL) {
    OC_ERR("initializing network event handler mutex\n");
    abort_impl();
  }
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
}

void
oc_network_event_handler_mutex_lock(void)
{
  WaitForSingleObject(mutex, 0);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  ReleaseMutex(mutex);
}

#ifdef OC_DEBUG
static int32_t
hexdump(const void *const buf, const size_t len)
{
  FILE *const fp = stderr;
  const uint32_t indent = 5;
  const unsigned char *p = (unsigned char *)buf;
  size_t i, j;

  if (NULL == buf || 0 == len || NULL == fp)
    return -1;

  for (j = 0; j < indent; ++j)
    fputc(' ', fp);
  for (i = 0; i < len; ++i) {
    fprintf(fp, "%02X", p[i]);
    if (0 == ((i + 1) & (0x0f)) && i + 1 < len) {
      fputc('\n', fp);
      for (j = 0; j < indent; ++j)
        fputc(' ', fp);
    } else
      fputc(' ', fp);
  }
  fputc('\n', fp);

  fflush(fp);

  return 0;
}
#endif

static void *
network_event_thread(void *data)
{
  (void)data;
  struct sockaddr_in6 *c = (struct sockaddr_in6 *)&client;
  socklen_t len = sizeof(client);

#ifdef OC_IPV4
  struct sockaddr_in *c4 = (struct sockaddr_in *)&client;
#endif

  fd_set rfds, setfds;

  FD_ZERO(&rfds);
  FD_SET(server_sock, &rfds);
  FD_SET(mcast_sock, &rfds);

#ifdef OC_SECURITY
  FD_SET(secure_sock, &rfds);
#endif

#ifdef OC_IPV4
  FD_SET(server4_sock, &rfds);
  FD_SET(mcast4_sock, &rfds);
#ifdef OC_SECURITY
  FD_SET(secure4_sock, &rfds);
#endif
#endif

  int i, n;

  while (!terminate) {
    setfds = rfds;
    n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

    for (i = 0; i < n; i++) {
      len = sizeof(client);
      oc_message_t *message = oc_allocate_message();

      if (!message) {
        break;
      }

      if (FD_ISSET(server_sock, &setfds)) {
        int count = recvfrom(server_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
            oc_message_unref(message);
            continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6;
        FD_CLR(server_sock, &setfds);
        goto common;
      }

      if (FD_ISSET(mcast_sock, &setfds)) {
        int count = recvfrom(mcast_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
            oc_message_unref(message);
            continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6;
        FD_CLR(mcast_sock, &setfds);
        goto common;
      }

#ifdef OC_IPV4
      if (FD_ISSET(server4_sock, &setfds)) {
        int count = recvfrom(server4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
            oc_message_unref(message);
            continue;
        }
        message->length = count;
        message->endpoint.flags = IPV4;
        FD_CLR(server4_sock, &setfds);
        goto common;
      }

      if (FD_ISSET(mcast4_sock, &setfds)) {
        int count = recvfrom(mcast4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
            oc_message_unref(message);
            continue;
        }
        message->length = count;
        message->endpoint.flags = IPV4;
        FD_CLR(mcast4_sock, &setfds);
        goto common;
      }
#endif

#ifdef OC_SECURITY
      if (FD_ISSET(secure_sock, &setfds)) {
        int count = recvfrom(secure_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
            oc_message_unref(message);
            continue;
        }
        message->length = count;
        message->endpoint.flags = IPV6 | SECURED;
      }
#ifdef OC_IPV4
      if (FD_ISSET(secure4_sock, &setfds)) {
        int count = recvfrom(secure4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
            oc_message_unref(message);
            continue;
        }
        message->length = count;
        message->endpoint.flags = IPV4 | SECURED;
      }
#endif
#endif /* OC_SECURITY */

    common:
#ifdef OC_IPV4
      if (message->endpoint.flags & IPV4) {
        memcpy(message->endpoint.addr.ipv4.address, &c4->sin_addr.s_addr,
               sizeof(c4->sin_addr.s_addr));
        message->endpoint.addr.ipv4.port = ntohs(c4->sin_port);
      } else if (message->endpoint.flags & IPV6) {
#else
      if (message->endpoint.flags & IPV6) {
#endif
        memcpy(message->endpoint.addr.ipv6.address, c->sin6_addr.s6_addr,
               sizeof(c->sin6_addr.s6_addr));
        message->endpoint.addr.ipv6.scope = c->sin6_scope_id;
        message->endpoint.addr.ipv6.port = ntohs(c->sin6_port);
      }

      OC_DBG("Incoming message from ");
      OC_LOGipaddr(message->endpoint);
      OC_DBG("\n");

      oc_network_event(message);
    }
  }

  CloseHandle(mutex);
  return NULL;
}

void
oc_send_buffer(oc_message_t *message)
{
  OC_DBG("Outgoing message to ");
  OC_LOGipaddr(message->endpoint);
  OC_DBG("\n");

  struct sockaddr_storage receiver;
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

#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
      send_sock = secure4_sock;
    } else {
      send_sock = secure_sock;
    }
#else
    send_sock = secure_sock;
#endif
  } else
#endif /* OC_SECURITY */
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
    send_sock = server4_sock;
  } else {
    send_sock = server_sock;
  }
#else  /* OC_IPV4 */
  {
    send_sock = server_sock;
  }
#endif /* !OC_IPV4 */

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

static int
get_network_interfaces(struct sockaddr ifa_addr[], int nic_size)
{
#ifdef DEBUG
  char longname[50] = { 0 };
  char dotname[INET6_ADDRSTRLEN] = { 0 };
#endif
  IP_ADAPTER_ADDRESSES *info = NULL;
  ULONG info_size = 0;

  int nCount = 0;

  if (ifa_addr == NULL || nic_size == 0)
    return 0;

  memset(ifa_addr, 0, nic_size * sizeof(*ifa_addr));

  // Gets the number of bytes needed to store all currently active adapter-info.
  GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL,
                       &info_size);

  if (info_size == 0 || (info = calloc(1, info_size)) == NULL)
    goto cleanup;

  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, info,
                           &info_size) != NO_ERROR)
    goto cleanup;

  IP_ADAPTER_ADDRESSES *adapter = NULL;
  for (adapter = info; nCount < nic_size && adapter != NULL;
       adapter = adapter->Next) {
    IP_ADAPTER_UNICAST_ADDRESS *address = NULL;

    if (IfOperStatusUp != adapter->OperStatus)
      continue;

    for (address = adapter->FirstUnicastAddress; nCount < nic_size && address;
         address = address->Next) {
      if (address->Address.lpSockaddr->sa_family == AF_INET) {
        memcpy(&ifa_addr[nCount], address->Address.lpSockaddr,
               sizeof(struct sockaddr_in));
#ifdef DEBUG
        getnameinfo(&ifa_addr[nCount], sizeof(struct sockaddr_in), dotname,
                    sizeof(dotname), NULL, 0, NI_NUMERICHOST);
        if (adapter->FriendlyName) {
          WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName,
                              wcslen(adapter->FriendlyName), longname,
                              sizeof(longname), NULL, NULL);
          PRINT("%s %s\n", dotname, longname);
        }
#endif
      } else if (address->Address.lpSockaddr->sa_family == AF_INET6) {
        memcpy(&ifa_addr[nCount], address->Address.lpSockaddr,
               sizeof(struct sockaddr_in6));
#ifdef DEBUG
        getnameinfo(&ifa_addr[nCount], sizeof(struct sockaddr_in6), dotname,
                    sizeof(dotname), NULL, 0, NI_NUMERICHOST);
        if (adapter->FriendlyName) {
          WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName,
                              wcslen(adapter->FriendlyName), longname,
                              sizeof(longname), NULL, NULL);
          PRINT("%s %s\n", dotname, longname);
        }
#endif
      } else {
        continue; // only AF_INET and AF_INET6
      }
      nCount++;
    }
  }

cleanup:
  free(info);

  return nCount;
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
#define MAX_ADDRS 10
  struct sockaddr ifa_addrs[MAX_ADDRS];
  int i, count;

  count = get_network_interfaces(ifa_addrs, MAX_ADDRS);
  if (count <= 0) {
    OC_ERR("querying interfaces: %d\n", errno);
    goto done;
  }
  for (i = 0; i < count; i++) {
    if (message->endpoint.flags & IPV6 && ifa_addrs[i].sa_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ifa_addrs[i];
      if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        int mif = addr->sin6_scope_id;
        if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                       (char *)&mif, sizeof(mif)) == -1) {
          OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d\n",
              errno);
          goto done;
        }
        oc_send_buffer(message);
      }
#ifdef OC_IPV4
    } else if (message->endpoint.flags & IPV4 &&
               ifa_addrs[i].sa_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)&ifa_addrs[i];
      if (setsockopt(server_sock, IPPROTO_IP, IP_MULTICAST_IF,
                     (char *)&addr->sin_addr, sizeof(addr->sin_addr)) == -1) {
        OC_ERR("setting socket option for default IP_MULTICAST_IF: %d\n",
            errno);
        goto done;
      }
      oc_send_buffer(message);
    }
#else
    }
#endif
  }
done:;
}
#endif /* OC_CLIENT */

#ifdef OC_IPV4
static int
connectivity_ipv4_init(void)
{
  memset(&mcast4, 0, sizeof(struct sockaddr_storage));
  memset(&server4, 0, sizeof(struct sockaddr_storage));

  struct sockaddr_in *m = (struct sockaddr_in *)&mcast4;
  m->sin_family = AF_INET;
  m->sin_port = htons(OCF_PORT_UNSECURED);
  m->sin_addr.s_addr = INADDR_ANY;

  struct sockaddr_in *l = (struct sockaddr_in *)&server4;
  l->sin_family = AF_INET;
  l->sin_addr.s_addr = INADDR_ANY;
  l->sin_port = 0;

#ifdef OC_SECURITY
  memset(&secure4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *sm = (struct sockaddr_in *)&secure4;
  sm->sin_family = AF_INET;
  sm->sin_port = dtls_port;
  sm->sin_addr.s_addr = INADDR_ANY;

  secure4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (secure4_sock < 0) {
    OC_ERR("creating secure IPv4 socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (server4_sock < 0 || mcast4_sock < 0) {
    OC_ERR("creating IPv4 server sockets\n");
    return -1;
  }

  if (bind(server4_sock, (struct sockaddr *)&server4, sizeof(server4)) == -1) {
    OC_ERR("binding server4 socket %d\n", errno);
    return -1;
  }

  struct ip_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
  if (setsockopt(mcast4_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining IPv4 multicast group %d\n", errno);
    return -1;
  }

  int reuse = 1;
  if (setsockopt(mcast4_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }
  if (bind(mcast4_sock, (struct sockaddr *)&mcast4, sizeof(mcast4)) == -1) {
    OC_ERR("binding mcast IPv4 socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(secure4_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }

  if (bind(secure4_sock, (struct sockaddr *)&secure4, sizeof(secure4)) == -1) {
    OC_ERR("binding IPv4 secure socket %d\n", errno);
    return -1;
  }
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized IPv4 connectivity\n");

  return 0;
}
#endif

static int
add_mcast_sock_to_ipv6_multicast_group(const uint8_t *addr)
{
  struct ipv6_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, addr, 16);
  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining IPv6 multicast group %d\n", errno);
    return -1;
  }
  return 0;
}

int
oc_connectivity_init(void)
{
  WSADATA wsadata;
  WSAStartup(MAKEWORD(2, 2), &wsadata);

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
    OC_ERR("creating server sockets\n");
    return -1;
  }

#ifdef OC_SECURITY
  secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (secure_sock < 0) {
    OC_ERR("creating secure socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) == -1) {
    OC_ERR("binding server socket %d\n", errno);
    return -1;
  }

  if (add_mcast_sock_to_ipv6_multicast_group(ALL_OCF_NODES_LL) < 0) {
    return -1;
  }
  if (add_mcast_sock_to_ipv6_multicast_group(ALL_OCF_NODES_RL) < 0) {
    return -1;
  }
  if (add_mcast_sock_to_ipv6_multicast_group(ALL_OCF_NODES_SL) < 0) {
    return -1;
  }

  int reuse = 1;
  if (setsockopt(mcast_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(mcast_sock, (struct sockaddr *)&mcast, sizeof(mcast)) == -1) {
    OC_ERR("binding mcast socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(secure_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(secure_sock, (struct sockaddr *)&secure, sizeof(secure)) == -1) {
    OC_ERR("binding IPv6 secure socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(secure);
  if (getsockname(secure_sock, (struct sockaddr *)&secure, &socklen) == -1) {
    OC_ERR("obtaining secure socket information %d\n", errno);
    return -1;
  }

  dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (connectivity_ipv4_init() != 0)
    PRINT("Could not initialize IPv4\n");
#endif

  thread_handle = CreateThread(
    0, 0, (LPTHREAD_START_ROUTINE)network_event_thread, NULL, 0, &event_thread);
  if (thread_handle == NULL) {
    OC_ERR("creating network polling thread\n");
    return -1;
  }

  OC_DBG("Successfully initialized connectivity\n");

  return 0;
}

void
oc_connectivity_shutdown(void)
{
  terminate = 1;

  closesocket(server_sock);
  closesocket(mcast_sock);

#ifdef OC_IPV4
  closesocket(server4_sock);
  closesocket(mcast4_sock);
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  closesocket(secure_sock);
#ifdef OC_IPV4
  closesocket(secure4_sock);
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

  WaitForSingleObject(thread_handle, INFINITE);
  TerminateThread(thread_handle, 0);
  WSACleanup();

  OC_DBG("oc_connectivity_shutdown\n");
}
