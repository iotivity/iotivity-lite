/*
// Copyright (c) 2016 Intel Corporation
// Copyright (c) 2022 Kistler Instruments
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
#include <logging/log.h>
LOG_MODULE_REGISTER(oc_ipadapter, LOG_LEVEL_DBG);
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
#include <net/if.h>
#include "ipv6.h"
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
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

#ifdef OC_WKCORE
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
#endif

#define ALL_COAP_NODES_V4 0xe00001bb

#define NETWORK_THREAD_STACKSIZE (1024 + CONFIG_TEST_EXTRA_STACKSIZE)
static pthread_attr_t oc_network_thread_attr;
K_THREAD_STACK_DEFINE(oc_network_thread_stack, NETWORK_THREAD_STACKSIZE);
static pthread_mutex_t oc_network_mutex;
static struct net_mgmt_event_callback net_mgmt_event_if_cb;
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
    OC_ERR("Failed to allocate memory for ip interface list item");
    return false;
  }
  new_if->if_index = target_index;
  oc_list_add(ip_interface_list, new_if);
  OC_DBG("Added to ip interface list: %d", new_if->if_index);
  return true;
}

static void
check_new_ip_interfaces_cb(struct net_if *iface, void *user_data)
{
  add_ip_interface(net_if_get_by_iface(iface));
}

static bool
check_new_ip_interfaces(void)
{
  net_if_foreach(&check_new_ip_interfaces_cb, NULL);
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
  if (pthread_mutex_init(&oc_network_mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex");
  }
}

void
oc_network_event_handler_mutex_lock(void)
{
  pthread_mutex_lock(&oc_network_mutex);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  pthread_mutex_unlock(&oc_network_mutex);
}

void
oc_network_event_handler_mutex_destroy(void)
{
  ifchange_initialized = false;
#ifdef OC_NETWORK_MONITOR
  remove_all_ip_interface();
  remove_all_network_interface_cbs();
#endif /* OC_NETWORK_MONITOR */
#ifdef OC_SESSION_EVENTS
  remove_all_session_event_cbs();
#endif /* OC_SESSION_EVENTS */
  pthread_mutex_destroy(&oc_network_mutex);
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
net_if_manage_ipv4_mcast_group(struct net_if *iface)
{
  struct in_addr addr;
  addr.s_addr = htonl(ALL_COAP_NODES_V4);
  struct net_if_mcast_addr *mcast_addr = net_if_ipv4_maddr_lookup(&addr, &iface);
  if(mcast_addr == NULL) {
    OC_DBG("Add IPv4 multicast address on interface with index %d", net_if_get_by_iface(iface));
    mcast_addr = net_if_ipv4_maddr_add(iface, &addr);
    if(mcast_addr == NULL) {
      OC_ERR("Failed to add IPv4 multicast address");
      return -1;
    }
  }
  if(!net_if_ipv4_maddr_is_joined(mcast_addr)) {
    OC_DBG("Join IPv4 multicast address on interface with index %d", net_if_get_by_iface(iface));
    net_if_ipv4_maddr_join(mcast_addr);
  }
  return 0;
}
#endif /* OC_IPV4 */

static int
net_if_manage_ipv6_mcast_group(struct net_if *iface)
{
  /* Link-local scope */
  struct in6_addr addr;
  memcpy(addr.s6_addr, ALL_OCF_NODES_LL, 16);
//  struct net_if_mcast_addr *mcast_addr = net_if_ipv6_maddr_lookup(&addr, &iface);
//  if(mcast_addr == NULL)
//  {
//    OC_ERR("No link-local multicast address on interface with index %d", net_if_get_by_iface(iface));
//    return -1;
//  }
//  net_if_ipv6_maddr_join(mcast_addr);
  int ret = net_ipv6_mld_join(iface, &addr);
  if (ret == -EALREADY)
  {
    return 0;
  }
  else if (ret < 0)
  {
    OC_ERR("Cannot join link-local IPv6 multicast group (%d)", ret);
    return -1;
  }

  /* Realm-local scope */
  memcpy(addr.s6_addr, ALL_OCF_NODES_RL, 16);
//  mcast_addr = net_if_ipv6_maddr_lookup(&addr, &iface);
//  if(mcast_addr == NULL)
//  {
//    OC_ERR("No realm-local multicast address on interface with index %d", net_if_get_by_iface(iface));
//    return -1;
//  }
//  net_if_ipv6_maddr_join(mcast_addr);
  ret = net_ipv6_mld_join(iface, &addr);
  if (ret == -EALREADY)
  {
    return 0;
  }
  else if (ret < 0)
  {
    OC_ERR("Cannot join realm-local IPv6 multicast group (%d)", ret);
    return -1;
  }

  /* Site-local scope */
  memcpy(addr.s6_addr, ALL_OCF_NODES_SL, 16);
//  mcast_addr = net_if_ipv6_maddr_lookup(&addr, &iface);
//  if(mcast_addr == NULL)
//  {
//    OC_ERR("No site-local multicast address on interface with index %d", net_if_get_by_iface(iface));
//    return -1;
//  }
//  net_if_ipv6_maddr_join(mcast_addr);
  ret = net_ipv6_mld_join(iface, &addr);
  if (ret == -EALREADY)
  {
    return 0;
  }
  else if (ret < 0)
  {
    OC_ERR("Cannot join site-local IPv6 multicast group (%d)", ret);
    return -1;
  }
  return 0;
}

static void
configure_mcast_socket_net_if(struct net_if *iface, void *user_data)
{
  int sa_family = *(int*)user_data;
  /* Ignore interfaces that are down */
  if (!net_if_is_up(iface)) {
    return;
  }
  /* Ignore interfaces not belonging to the address family under consideration
   */
  if(sa_family == AF_INET6) {
    net_if_manage_ipv6_mcast_group(iface);
  }
#ifdef OC_IPV4
  else if (sa_family == AF_INET) {
    net_if_manage_ipv4_mcast_group(iface);
  }
#endif
}

static int
configure_mcast_socket(int mcast_sock, int sa_family)
{
  net_if_foreach(&configure_mcast_socket_net_if, &sa_family);
  return 0;
}

struct get_interface_addresses_params {
  ip_context_t *dev;
  unsigned char family;
  uint16_t port;
  bool secure;
  bool tcp;
};

static void
get_interface_addresses_net_if(struct net_if *iface, void *user_data)
{
  struct get_interface_addresses_params *params = user_data;
  oc_endpoint_t ep = { 0 };
  ep.interface_index = net_if_get_by_iface(iface);
  /* Ignore interfaces that are down */
  if (!net_if_is_up(iface)) {
    OC_DBG("Interface %d is down", ep.interface_index);
    return;
  }

  if (params->secure) {
    ep.flags |= SECURED;
  }
#ifdef OC_IPV4
  if (params->family == AF_INET) {
    ep.addr.ipv4.port = params->port;
  } else
#endif /* OC_IPV4 */
  if (params->family == AF_INET6) {
    ep.addr.ipv6.port = params->port;
  }
#ifdef OC_TCP
  if (params->tcp) {
    ep.flags |= TCP;
  }
#endif /* OC_TCP */
  if (params->family == AF_INET6) {
    ep.flags |= IPV6;
    struct net_if_ipv6 *ipv6;
    if (net_if_config_ipv6_get(iface, &ipv6) < 0) {
      OC_ERR("net_if_config_ipv6_get for interface %d failed",
             ep.interface_index);
      return;
    }
    for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
      if (!ipv6->unicast[i].is_used || ipv6->unicast[i].address.family != AF_INET6) {
        continue;
      }
      if (net_ipv6_is_addr_unspecified(&(ipv6->unicast[i].address.in6_addr)) ||
          net_ipv6_is_addr_loopback(&(ipv6->unicast[i].address.in6_addr))) {
        continue;
      }
      memcpy(ep.addr.ipv6.address, ipv6->unicast[i].address.in6_addr.s6_addr, 16);
      ep.addr.ipv6.scope = ipv6->unicast[i].address.in6_addr.s6_addr[1];
      oc_endpoint_t *new_ep = oc_memb_alloc(&device_eps);
      if (!new_ep) {
        return;
      }
      memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
#ifdef OC_DEBUG
      char buf[IPADDR_BUFF_SIZE];
      SNPRINTFipaddr(buf, IPADDR_BUFF_SIZE, ep);
      OC_DBG("add endpoint: %s, family: %d, if index: %d, secure: %d, tcp: %d",
             buf, (int)params->family, ep.interface_index,
             (int)params->secure, (int)params->tcp);
#endif /* OC_DEBUG */
      oc_list_add(params->dev->eps, new_ep);
    }
  }
#ifdef OC_IPV4
  if (params->family == AF_INET) {
    ep.flags |= IPV4;
    struct net_if_ipv4 *ipv4;
    if (net_if_config_ipv4_get(iface, &ipv4) < 0) {
      OC_ERR("net_if_config_ipv6_get for interface %d failed",
             ep.interface_index);
      return;
    }
    for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
      if (!ipv4->unicast[i].is_used || ipv4->unicast[i].address.family != AF_INET) {
        continue;
      }
      if (net_ipv4_is_addr_unspecified(&(ipv4->unicast[i].address.in_addr)) ||
          net_ipv4_is_addr_loopback(&(ipv4->unicast[i].address.in_addr))) {
        continue;
      }
      memcpy(ep.addr.ipv4.address, ipv4->unicast[i].address.in_addr.s4_addr, 4);
      oc_endpoint_t *new_ep = oc_memb_alloc(&device_eps);
      if (!new_ep) {
        return;
      }
      memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
#ifdef OC_DEBUG
      char buf[IPADDR_BUFF_SIZE];
      SNPRINTFipaddr(buf, IPADDR_BUFF_SIZE, ep);
      OC_DBG("add endpoint: %s, family: %d, if index: %d, secure: %d, tcp: %d",
             buf, (int)params->family, ep.interface_index,
             (int)params->secure, (int)params->tcp);
#endif /* OC_DEBUG */
      oc_list_add(params->dev->eps, new_ep);
    }
  }
#endif /* OC_IPV4 */
}

static void
get_interface_addresses(ip_context_t *dev, unsigned char family, uint16_t port,
                        bool secure, bool tcp)
{
  struct get_interface_addresses_params params = {
    .dev = dev,
    .family = family,
    .port = port,
    .secure = secure,
    .tcp = tcp
  };
  net_if_foreach(&get_interface_addresses_net_if, &params);
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
static void
process_interface_change_event(struct net_if *iface, oc_interface_event_t event)
{
  int num_devices = oc_core_get_num_devices();

  if (event == NETWORK_INTERFACE_UP) {
#ifdef OC_NETWORK_MONITOR
    if (add_ip_interface(net_if_get_by_iface(iface))) {
      oc_network_interface_event(event);
    }
#endif /* OC_NETWORK_MONITOR */
  } else if (event == NETWORK_INTERFACE_DOWN) {
#ifdef OC_NETWORK_MONITOR
    if (remove_ip_interface(net_if_get_by_iface(iface))) {
      oc_network_interface_event(event);
    }
#endif /* OC_NETWORK_MONITOR */
  }

  for (int i = 0; i < num_devices; i++) {
    ip_context_t *dev = get_ip_context_for_device(i);
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev);
    oc_network_event_handler_mutex_unlock();
  }
}

static int
recv_msg(int sock, uint8_t *recv_buf, int recv_buf_size,
         oc_endpoint_t *endpoint, bool multicast)
{
  struct sockaddr server_sockaddr;
  socklen_t server_sockaddr_len;
  server_sockaddr_len = sizeof(server_sockaddr);
  int ret = zsock_getsockname(sock, &server_sockaddr, &server_sockaddr_len);
  if (ret < 0) {
    OC_ERR("getsockname() failed: %d", errno);
    return -1;
  }
  struct sockaddr client_sockaddr;
  socklen_t client_sockaddr_len;
  client_sockaddr_len = sizeof(client_sockaddr);

  ret = recvfrom(sock, recv_buf, recv_buf_size, 0, &client_sockaddr, &client_sockaddr_len);
  if (ret < 0) {
    OC_ERR("recvfrom() failed: %d", errno);
    return -1;
  }

  if (client_sockaddr.sa_family == AF_INET6) {
    /* Set source address of packet in endpoint structure */
    struct sockaddr_in6 *c6 = net_sin6(&client_sockaddr);
    memcpy(endpoint->addr.ipv6.address, c6->sin6_addr.s6_addr,
           sizeof(c6->sin6_addr.s6_addr));
    endpoint->addr.ipv6.scope = c6->sin6_scope_id;
    endpoint->addr.ipv6.port = ntohs(c6->sin6_port);
    /* Set receiving network interface index */
    struct net_if *iface;
    struct net_if_addr* if_addr = net_if_ipv6_addr_lookup(&net_sin6(&server_sockaddr)->sin6_addr, &iface);
    endpoint->interface_index = net_if_get_by_iface(iface);
    /* For a unicast receiving socket, extract the interface address
     * into the endpoint's addr_local attribute.
     * This would be used to set the source address of a response that
     * results from this message.
     */
    if (!multicast) {
      memcpy(endpoint->addr_local.ipv6.address, if_addr->address.in6_addr.s6_addr, 16);
    } else {
      memset(endpoint->addr_local.ipv6.address, 0, 16);
    }
  }
#ifdef OC_IPV4
  else if (client_sockaddr.sa_family == AF_INET) {
    /* Set source address of packet in endpoint structure */
    struct sockaddr_in *c4 = net_sin(&client_sockaddr);
    memcpy(endpoint->addr.ipv4.address, &c4->sin_addr.s_addr,
           sizeof(c4->sin_addr.s_addr));
    endpoint->addr.ipv6.port = ntohs(c4->sin_port);
    /* Set receiving network interface index */
    struct net_if *iface;
    struct net_if_addr* if_addr = net_if_ipv4_addr_lookup(&net_sin(&server_sockaddr)->sin_addr, &iface);
    endpoint->interface_index = net_if_get_by_iface(iface);
    /* For a unicast receiving socket, extract the interface address
     * into the endpoint's addr_local attribute.
     * This would be used to set the source address of a response that
     * results from this message.
     */
    if (!multicast) {
      memcpy(endpoint->addr_local.ipv4.address, &if_addr->address.in_addr.s_addr, 4);
    } else {
      memset(endpoint->addr_local.ipv4.address, 0, 4);
    }
  }
#endif /* OC_IPV4 */
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
      oc_message_t *message = oc_allocate_message();
      if (!message) {
        OC_WRN("Failed to allocate message!");
        break;
      }

      message->endpoint.device = dev->device;

      if (oc_udp_receive_message(dev, &setfds, message) == ADAPTER_STATUS_RECEIVE) {
        goto common;
      }
#ifdef OC_TCP
      if (oc_tcp_receive_message(dev, &setfds, message) == ADAPTER_STATUS_RECEIVE) {
        goto common;
      }
#endif /* OC_TCP */

      oc_message_unref(message);
      continue;

    common:
#ifdef OC_DEBUG
      PRINT("Incoming message of size %zd bytes from ", message->length);
      PRINTipaddr(message->endpoint);
      PRINT("\n");
#endif /* OC_DEBUG */

      oc_network_event(message);
    }
  }
  pthread_exit(NULL);
  return NULL;
}

static int
send_msg(int sock, struct sockaddr *receiver, oc_message_t *message)
{
  int bytes_sent = 0, x;
  uint8_t *buf = message->data;
  size_t remaining = message->length;
  while (bytes_sent < (int)message->length) {
    buf += bytes_sent;
    remaining -= bytes_sent;
    x = sendto(sock, buf, remaining, 0, receiver, sizeof(struct sockaddr));
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
  PRINT("\n");
#endif /* OC_DEBUG */

  struct sockaddr receiver;
  memset(&receiver, 0, sizeof(struct sockaddr));
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
    struct sockaddr_in6 *r = net_sin6(&receiver);
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
  // TODO: implement sending of multicast message
  OC_ERR("Not implemented");
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
    OC_ERR("Failed to allocate memory for network interface callback");
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
    OC_ERR("Failed to allocate memory for session event callback");
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
  struct sockaddr_in *addr;
  OC_DBG("Initializing IPv4 connectivity for device %zd", dev->device);

  // Initialize IPv4 socket
  memset(&dev->server4, 0, sizeof(struct sockaddr_storage));
  addr = (struct sockaddr_in *)&dev->server4;
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = INADDR_ANY;
  addr->sin_port = 0;

  dev->server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->server4_sock < 0) {
    OC_ERR("Failed to create IPv4 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (bind(dev->server4_sock, (struct sockaddr *)&dev->server4, sizeof(dev->server4)) == -1) {
    OC_ERR("Failed to bind the IPv4 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server4);
  if (getsockname(dev->server4_sock, (struct sockaddr *)&dev->server4, &socklen) == -1) {
    OC_ERR("Failed to get the IPv4 socket name for device %zd: %d", dev->device, errno);
    return -1;
  }
  addr = (struct sockaddr_in *)&dev->server4;
  dev->port4 = ntohs(addr->sin_port);

  // Initialize IPv4 multicast socket
  memset(&dev->mcast4, 0, sizeof(struct sockaddr_storage));
  addr = (struct sockaddr_in *)&dev->mcast4;
  addr->sin_family = AF_INET;
  addr->sin_port = htons(OCF_PORT_UNSECURED);
  addr->sin_addr.s_addr = INADDR_ANY;

  dev->mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->mcast4_sock < 0) {
    OC_ERR("Failed to create IPv4 multicast socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  int on = 1;
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
    OC_ERR("Failed to set the reuseaddr option on the IPv4 multicast socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (bind(dev->mcast4_sock, (struct sockaddr *)&dev->mcast4, sizeof(dev->mcast4)) == -1) {
    OC_ERR("Failed to bind the IPv4 multicast socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (configure_mcast_socket(dev->mcast4_sock, AF_INET) < 0) {
    OC_ERR("Failed to configure the IPv4 multicast socket for device %zd", dev->device);
    return -1;
  }

#ifdef OC_SECURITY
  // Initialize secure IPv4 socket
  memset(&dev->secure4, 0, sizeof(struct sockaddr_storage));
  addr = (struct sockaddr_in *)&dev->secure4;
  addr->sin_family = AF_INET;
  addr->sin_port = 0;
  addr->sin_addr.s_addr = INADDR_ANY;

  dev->secure4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure4_sock < 0) {
    OC_ERR("Failed to create secure IPv4 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (bind(dev->secure4_sock, (struct sockaddr *)&dev->secure4, sizeof(dev->secure4)) == -1) {
    OC_ERR("Failed to bind the secure IPv4 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  socklen = sizeof(dev->secure4);
  if (getsockname(dev->secure4_sock, (struct sockaddr *)&dev->secure4, &socklen) == -1) {
    OC_ERR("Failed to get the secure IPv4 socket name for device %zd: %d", dev->device, errno);
    return -1;
  }
  addr = (struct sockaddr_in *)&dev->secure4;
  dev->dtls4_port = ntohs(addr->sin_port);
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized IPv4 connectivity for device %zd", dev->device);
  return 0;
}
#endif

static void
net_mgmt_event_if_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event, struct net_if *iface)
{
  switch(mgmt_event)
  {
  case NET_EVENT_IF_UP:
  {
    OC_DBG("event: NET_EVENT_IF_UP");
    process_interface_change_event(iface, NETWORK_INTERFACE_UP);
  }
  break;
  case NET_EVENT_IF_DOWN:
  {
    OC_DBG("event: NET_EVENT_IF_DOWN");
    process_interface_change_event(iface, NETWORK_INTERFACE_DOWN);
  }
  break;
  default:
    OC_WRN("unhandled event: 0x%x", mgmt_event);
    break;
  }
}

int
oc_connectivity_init(size_t device)
{
  struct sockaddr_in6 *addr;
  OC_DBG("Initializing connectivity for device %zd", device);

  ip_context_t *dev = (ip_context_t *)oc_memb_alloc(&ip_context_s);
  if (!dev) {
    oc_abort("Insufficient memory");
  }
  oc_list_add(ip_contexts, dev);
  dev->device = device;
  OC_LIST_STRUCT_INIT(dev, eps);

  if (pthread_mutex_init(&dev->rfds_mutex, NULL) != 0) {
    OC_ERR("Failed to initialize mutex for receive file descriptors for device %zd", dev->device);
    oc_abort("Failed to initialize mutex");
  }

  if (zsock_socketpair(AF_UNIX, SOCK_STREAM, 0, dev->shutdown_pipe) < 0) {
    OC_ERR("Failed to create the shutdown_pipe socketpair: %d", errno);
    return -1;
  }

  if (set_nonblock_socket(dev->shutdown_pipe[0]) < 0) {
    OC_ERR("Could not set shutdown_pipe[0] to non-blocking mode: %d", errno);
    return -1;
  }

  // Initialize IPv6 socket
  memset(&dev->server, 0, sizeof(struct sockaddr_storage));
  addr = (struct sockaddr_in6 *)&dev->server;
  addr->sin6_family = AF_INET6;
  addr->sin6_port = 0;
  addr->sin6_addr = in6addr_any;

  dev->server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->server_sock < 0) {
    OC_ERR("Failed to create IPv6 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  int sockopt_on = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &sockopt_on, sizeof(sockopt_on)) == -1) {
    OC_ERR("Failed to set the IPv6 only option on the IPv6 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (bind(dev->server_sock, (struct sockaddr *)&dev->server, sizeof(dev->server)) == -1) {
    OC_ERR("Failed to bind the IPv6 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server, &socklen) == -1) {
    OC_ERR("Failed to get the IPv6 socket name for device %zd: %d", dev->device, errno);
    return -1;
  }
  addr = (struct sockaddr_in6 *)&dev->server;
  dev->port = ntohs(addr->sin6_port);

  // Initialize IPv6 multicast socket
  memset(&dev->mcast, 0, sizeof(struct sockaddr_storage));
  addr = (struct sockaddr_in6 *)&dev->mcast;
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons(OCF_PORT_UNSECURED);
  addr->sin6_addr = in6addr_any;

  dev->mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->server_sock < 0) {
    OC_ERR("Failed to create IPv6 multicast socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, &sockopt_on, sizeof(sockopt_on)) == -1) {
    OC_ERR("Failed to set the reuseaddr option on the IPv6 multicast socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast, sizeof(dev->mcast)) == -1) {
    OC_ERR("Failed to bind the IPv6 multicast socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (configure_mcast_socket(dev->mcast_sock, AF_INET6) < 0) {
    OC_ERR("Failed to configure the IPv6 multicast socket for device %zd", dev->device);
    return -1;
  }

#ifdef OC_SECURITY
  // Initialize secure IPv6 socket
  memset(&dev->secure, 0, sizeof(struct sockaddr_storage));
  addr = (struct sockaddr_in6 *)&dev->secure;
  // TODO: The following 3 lines cause a "Unaligned memory access" CPU fault
//  addr->sin6_family = AF_INET6;
//  addr->sin6_port = 0;
//  addr->sin6_addr = in6addr_any;

  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock < 0) {
    OC_ERR("Failed to create secure IPv6 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (setsockopt(dev->secure_sock, IPPROTO_IPV6, IPV6_V6ONLY, &sockopt_on, sizeof(sockopt_on)) == -1) {
    OC_ERR("Failed to set the IPv6 only option on the secure IPv6 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure, sizeof(dev->secure)) == -1) {
    OC_ERR("Failed to bind the secure IPv6 socket for device %zd: %d", dev->device, errno);
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure, &socklen) == -1) {
    OC_ERR("Failed to get the secure IPv6 socket name for device %zd: %d", dev->device, errno);
    return -1;
  }
  addr = (struct sockaddr_in6 *)&dev->secure;
  dev->dtls_port = ntohs(addr->sin6_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Failed to initialize IPv4 connectivity for device %zd", dev->device);
    return -1;
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

  /* Register network management event callbacks to listen for network interface changes.
   */
  if (!ifchange_initialized) {
    net_mgmt_init_event_callback(&net_mgmt_event_if_cb, net_mgmt_event_if_handler, NET_EVENT_IF_UP | NET_EVENT_IF_DOWN);
    net_mgmt_add_event_callback(&net_mgmt_event_if_cb);
#ifdef OC_NETWORK_MONITOR
    if (!check_new_ip_interfaces()) {
      OC_ERR("Check for new IP interfaces failed");
      return -1;
    }
#endif /* OC_NETWORK_MONITOR */
    ifchange_initialized = true;
  }

  int ret = pthread_attr_init(&oc_network_thread_attr);
  if (ret != 0) {
    OC_ERR("Failed to initialize network thread for device %zd: pthread_attr_init() failed: %d", dev->device, errno);
    return -1;
  }
  ret = pthread_attr_setstack(&oc_network_thread_attr, &oc_network_thread_stack, NETWORK_THREAD_STACKSIZE);
  if (ret != 0) {
    OC_ERR("Failed to initialize network thread for device %zd: pthread_attr_setstack() failed: %d", dev->device, errno);
    return -1;
  }
  ret = pthread_create(&dev->event_thread, &oc_network_thread_attr, &network_event_thread, dev);
  if (ret != 0) {
    OC_ERR("Failed to initialize network thread for device %zd: pthread_create() failed: %d", dev->device, errno);
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
      ret = -1;
    }
  }

  return ret;
}
#endif /* OC_DNS_LOOKUP */

int
set_nonblock_socket(int sockfd)
{
  int flags = zsock_fcntl(sockfd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  return zsock_fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
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
