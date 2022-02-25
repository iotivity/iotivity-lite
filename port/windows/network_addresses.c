/*
// Copyright (c) 2017 Lynx Technology
// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2019 Kistler Instrumente AG
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
// clang-format off
#include <windows.h>
#include <WinSock2.h>
#include <Mswsock.h>
#include <inttypes.h>
#include <iphlpapi.h>
#include <malloc.h>
#include <oc_log.h>
#include <ws2tcpip.h>
// clang-format on

/**
 * Structure to manage interface list.
 */
typedef struct ifaddr_t
{
  struct ifaddr_t *next;
  struct sockaddr_storage addr;
  DWORD if_index;
} ifaddr_t;

ifaddr_t *
get_network_addresses()
{
  ifaddr_t *ifaddr_list = NULL;
  ULONG family = AF_INET6;
  int i, max_retries = 5;
  IP_ADAPTER_ADDRESSES *iface_list = NULL;
  IP_ADAPTER_ADDRESSES *iface = NULL;
  ULONG out_buf_len = 8000;

#ifdef OC_IPV4
  family = AF_UNSPEC;
#endif /* OC_IPV4 */

  for (i = 0; i < max_retries; i++) {
    DWORD dwRetVal = 0;
    iface_list = calloc(1, out_buf_len);
    if (iface_list == NULL) {
      OC_ERR("not enough memory to run GetAdaptersAddresses");
      return NULL;
    }
    dwRetVal =
      GetAdaptersAddresses(family,
                           GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
                             GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                           NULL, iface_list, &out_buf_len);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      OC_ERR("retry GetAdaptersAddresses with out_buf_len=%d", out_buf_len);
      free(iface_list);
      iface_list = NULL;
      continue;
    }
    break;
  }

  if (iface_list == NULL) {
    OC_ERR("failed to run GetAdaptersAddresses");
    return NULL;
  }

  for (iface = iface_list; iface != NULL; iface = iface->Next) {
    IP_ADAPTER_UNICAST_ADDRESS *address = NULL;
    if (IfOperStatusUp != iface->OperStatus ||
        iface->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }

#ifdef OC_DEBUG
    if (iface->FriendlyName) {
      OC_DBG("processing iface %ws:", iface->FriendlyName);
    }
#endif /* OC_DEBUG */
/* Process all IPv4 addresses on this interface. */
#ifdef OC_IPV4
    for (address = iface->FirstUnicastAddress; address;
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
        ifaddr->if_index = iface->IfIndex;
        ifaddr->next = ifaddr_list;
        ifaddr_list = ifaddr;
      }
    }
#endif /* OC_IPV4 */
    /* Process all IPv6 addresses on this interface. */
    struct sockaddr_in6 *v6addr = NULL;
    for (address = iface->FirstUnicastAddress; address;
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
      continue;
    }
    ifaddr_t *ifaddr = calloc(1, sizeof(ifaddr_t));
    if (ifaddr == NULL) {
      OC_ERR("no memory for ifaddr");
      goto cleanup;
    }
    memcpy(&ifaddr->addr, v6addr, sizeof(struct sockaddr_in6));
    ifaddr->if_index = iface->Ipv6IfIndex;
    ifaddr->next = ifaddr_list;
    ifaddr_list = ifaddr;
  }

cleanup:
  free(iface_list);

  return ifaddr_list;
}

void
free_network_addresses(ifaddr_t *ifaddr)
{
  while (ifaddr) {
    ifaddr_t *tmp = ifaddr;
    ifaddr = ifaddr->next;
    free(tmp);
  }
}
