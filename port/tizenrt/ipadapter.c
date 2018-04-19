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


void
oc_network_event_handler_mutex_init(void)
{
  oc_abort(__func__);
}

void
oc_network_event_handler_mutex_lock(void)
{
  oc_abort(__func__);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  oc_abort(__func__);
}

void oc_network_event_handler_mutex_destroy(void) {
  oc_abort(__func__);
}

static ip_context_t *get_ip_context_for_device(int device) {
  oc_abort(__func__);
  return NULL;
}

#ifdef OC_IPV4
static int add_mcast_sock_to_ipv4_mcast_group(int mcast_sock,
                                              const struct in_addr *local,
                                              int interface_index) {
  oc_abort(__func__);
  return 0;
}
#endif /* OC_IPV4 */

static int add_mcast_sock_to_ipv6_mcast_group(int mcast_sock,
                                              int interface_index) {

  (void) mcast_sock;
  (void) interface_index;
  oc_abort(__func__);
  return 0;
}

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

/* Called after network interface up/down events.
 * This function reconfigures IPv6/v4 multicast sockets for
 * all logical devices.
 */
static int process_interface_change_event(void) {
  int ret = 0;
  oc_abort(__func__);
  return ret;
}


static void *network_event_thread(void *data) {
  (void) data;
  oc_abort(__func__);
  return NULL;
}

static void
get_interface_addresses(unsigned char family, uint16_t port, bool secure,
                        bool tcp)
{
  (void) family;
  (void) port;
  (void) secure;
  (void) tcp;
  oc_abort(__func__);
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  (void) device;
  oc_abort(__func__);
  return NULL;
}

void oc_send_buffer(oc_message_t *message) {
  (void) message;
  oc_abort(__func__);
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
  (void) dev;
  oc_abort(__func__);
  return 0;
}
#endif

int oc_connectivity_init(int device) {
  (void) device;
  oc_abort(__func__);
  return -1;
}

void
oc_connectivity_shutdown(int device)
{
  (void) device;
  oc_abort(__func__);
}
