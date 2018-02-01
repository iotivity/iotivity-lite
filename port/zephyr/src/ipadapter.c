/*
// Copyright (c) 2016 Intel Corporation
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

#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include <errno.h>
#include <stdio.h>
#include <zephyr.h>

#include <net/net_context.h>
#include <net/net_core.h>
#include <net/net_if.h>
#include <net/net_pkt.h>

/* Server's receive socket */
static struct net_context *udp_recv6;

/* "All OCF nodes" multicast address and port */
#define OCF_MCAST_IP6ADDR                                                      \
  {                                                                            \
    {                                                                          \
      {                                                                        \
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58             \
      }                                                                        \
    }                                                                          \
  }
static struct in6_addr in6addr_mcast = OCF_MCAST_IP6ADDR;
#define OCF_MCAST_PORT (5683)
/* Multicast receive socket */
static struct net_context *mcast_recv6;
static struct sockaddr_in6 mcast_addr6;
static struct sockaddr_in6 my_addr6;

static struct in6_addr in6addr_my;

#ifdef OC_SECURITY
/* DTLS receive socket */
static struct net_context *dtls_recv6;
static struct sockaddr_in6 dtls_addr6;
#define MY_DTLS_PORT (56789)
#endif /* OC_SECURITY */

/* For synchronizing the network receive thread with IoTivity-Constrained's
 * event loop.
 */
static struct k_sem sem;

void
oc_network_event_handler_mutex_init(void)
{
  k_sem_init(&sem, 0, 1);
  k_sem_give(&sem);
}

void
oc_network_event_handler_mutex_lock(void)
{
  k_sem_take(&sem, K_FOREVER);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  k_sem_give(&sem);
}

void oc_network_event_handler_mutex_destroy(void) {}

static void oc_network_receive(struct net_context *context, struct net_pkt *pkt,
                               int status, void *user_data) {
  oc_message_t *message = oc_allocate_message();

  if (message) {
    uint16_t pos;
    struct net_udp_hdr *udp =
      (struct net_udp_hdr *)((u8_t *)(NET_IPV6_HDR(pkt)) +
                             sizeof(struct net_ipv6_hdr));
    size_t bytes_read = net_pkt_appdatalen(pkt);
    if (bytes_read < 0) {
      oc_message_unref(message);
      return;
    }

    size_t offset_from_start = net_pkt_get_len(pkt) - bytes_read;
    bytes_read = (bytes_read < OC_PDU_SIZE) ? bytes_read : OC_PDU_SIZE;
    struct net_buf *frag = net_frag_read(pkt->frags, offset_from_start, &pos,
                                         bytes_read, message->data);
    if (!frag && pos == 0xffff) {
      net_pkt_unref(pkt);
      oc_message_unref(message);
      return;
    }

    message->length = bytes_read;
    if (user_data != NULL)
      message->endpoint.flags = IPV6 | SECURED;
    else
      message->endpoint.flags = IPV6;
    memcpy(message->endpoint.addr.ipv6.address, &NET_IPV6_HDR(pkt)->src, 16);
    message->endpoint.addr.ipv6.scope = 0;
    message->endpoint.addr.ipv6.port = ntohs(udp->src_port);
    message->endpoint.device = 0;

    OC_DBG("oc_network_receive: received %d bytes\n", (int)message->length);
#ifdef OC_DEBUG
    OC_DBG("oc_network_receive: incoming message: ");
    PRINTipaddr(message->endpoint);
    OC_DBG("\n");
#endif

    oc_network_event(message);
  }

  net_pkt_unref(pkt);
}

static inline void
udp_sent(struct net_context *context, int status, void *token, void *user_data)
{
  if (!status) {
    OC_DBG("oc_send_buffer: sent %d bytes\n", POINTER_TO_UINT(token));
  } else if (status < 0) {
    OC_DBG("oc_send_buffer: failed: (%d)\n", status);
  }
}

void
oc_send_buffer(oc_message_t *message)
{
#ifdef OC_DEBUG
  OC_DBG("oc_send_buffer: outgoing message: ");
  PRINTipaddr(message->endpoint);
  OC_DBG("\n");
#endif

  /* Populate destination address structure */
  struct sockaddr_in6 peer_addr;
  memcpy(peer_addr.sin6_addr.in6_u.u6_addr8,
         message->endpoint.addr.ipv6.address, 16);
  peer_addr.sin6_family = AF_INET6;
  peer_addr.sin6_port = htons(message->endpoint.addr.ipv6.port);

  /* Network buffer to hold data to be sent */
  struct net_pkt *send_pkt;
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
    send_pkt = net_pkt_get_tx(dtls_recv6, K_NO_WAIT);
  } else
#endif /* OC_SECURITY */
  {
    send_pkt = net_pkt_get_tx(udp_recv6, K_NO_WAIT);
  }
  if (!send_pkt) {
    OC_WRN("oc_send_buffer: cannot acquire send_pkt\n");
    return;
  }

  bool status = net_pkt_append_all(send_pkt, message->length, message->data, K_NO_WAIT);
  if (!status) {
    OC_WRN("oc_send_buffer: cannot populate send_pkt\n");
    return;
  }

  int ret = net_context_sendto(
    send_pkt, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in6),
    udp_sent, 0, UINT_TO_POINTER(net_pkt_get_len(send_pkt)), NULL);
  if (ret < 0) {
    OC_WRN("oc_send_buffer: cannot send data to peer (%d)\n", ret);
    net_pkt_unref(send_pkt);
  }
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  (void)device;
  oc_init_endpoint_list();
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(oc_endpoint_t));
  ep.flags = IPV6;
  net_addr_pton(AF_INET6, CONFIG_NET_APP_MY_IPV6_ADDR, ep.addr.ipv6.address);
  ep.addr.ipv6.port = ntohs(my_addr6.sin6_port);
  ep.device = 0;
  oc_add_endpoint_to_list(&ep);
#ifdef OC_SECURITY
  oc_endpoint_t ep_sec;
  memset(&ep_sec, 0, sizeof(oc_endpoint_t));
  ep_sec.flags = IPV6 | SECURED;
  net_addr_pton(AF_INET6, CONFIG_NET_APP_MY_IPV6_ADDR,
                ep_sec.addr.ipv6.address);
  ep_sec.addr.ipv6.port = ntohs(dtls_addr6.sin6_port);
  ep_sec.device = 0;
  oc_add_endpoint_to_list(&ep_sec);
#endif /* OC_SECURITY */
  return oc_get_endpoint_list();
}

int
oc_connectivity_init(int device)
{
  (void)device;
  int ret;

  /* Record OCF's multicast address with network interface */
  net_if_ipv6_maddr_add(net_if_get_default(), &in6addr_mcast);

  net_ipaddr_copy(&mcast_addr6.sin6_addr, &in6addr_mcast);
  mcast_addr6.sin6_family = AF_INET6;
  mcast_addr6.sin6_port = htons(OCF_MCAST_PORT);

  /* Wildcard address set for server with randomly chosen port */
  my_addr6.sin6_family = AF_INET6;

  /* Add unicast IPV6 address to interface so that node can communicate */
  /* Would be good to have the address auto-configured in case some router is
   * distributing pre-fixes*/
  if (net_addr_pton(AF_INET6, CONFIG_NET_APP_MY_IPV6_ADDR, &in6addr_my) < 0) {
    NET_ERR("Invalid IPv6 address %s", CONFIG_NET_APP_MY_IPV6_ADDR);
  }

#ifdef OC_DEBUG
  struct net_if_addr *ifaddr =
#endif
    net_if_ipv6_addr_add(net_if_get_default(), &in6addr_my, NET_ADDR_MANUAL, 0);
#ifdef OC_DEBUG
  OC_DBG("=====>>>Interface unicast address added @ %p\n", ifaddr);
#endif

#ifdef OC_SECURITY
  dtls_addr6.sin6_port = htons(MY_DTLS_PORT);
  dtls_addr6.sin6_family = AF_INET6;
#endif /* OC_SECURITY */

  ret = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &udp_recv6);
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: cannot get UDP network context for server"
           "receive (%d)\n",
           ret);
    goto error;
  }

  ret = net_context_bind(udp_recv6, (struct sockaddr *)&my_addr6,
                         sizeof(struct sockaddr_in6));
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: cannot bind UDP port %d to server's network"
           "context (%d)\n",
           ntohs(my_addr6.sin6_port), ret);
    goto error;
  }

  ret = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &mcast_recv6);
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: cannot get UDP network context for OCF"
           "multicast receive (%d)\n",
           ret);
    goto error;
  }

  ret = net_context_bind(mcast_recv6, (struct sockaddr *)&mcast_addr6,
                         sizeof(struct sockaddr_in6));
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: cannot bind OCF multicast network context"
           "(%d)\n",
           ret);
    goto error;
  }

#ifdef OC_SECURITY
  ret = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &dtls_recv6);
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: cannot get DTLS network context"
           "(%d)\n",
           ret);
    goto error;
  }

  ret = net_context_bind(dtls_recv6, (struct sockaddr *)&dtls_addr6,
                         sizeof(struct sockaddr_in6));
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: cannot bind DTLS network context"
           "(%d)\n",
           ret);
    goto error;
  }
#endif /* OC_SECURITY */

  ret = net_context_recv(mcast_recv6, oc_network_receive, 0, NULL);
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: net_context_recv error from multicast socket:"
           "(%d)\n",
           ret);
    goto error;
  }

  ret = net_context_recv(udp_recv6, oc_network_receive, 0, NULL);
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: net_context_recv error from server socket:"
           "(%d)\n",
           ret);
    goto error;
  }

#ifdef OC_SECURITY
  static uint16_t dtls_port = MY_DTLS_PORT;
  ret = net_context_recv(dtls_recv6, oc_network_receive, 0, &dtls_port);
  if (ret < 0) {
    OC_WRN("oc_connectivity_init: net_context_recv error from DTLS socket:"
           "(%d)\n",
           ret);
    goto error;
  }
#endif /* OC_SECURITY */

  OC_DBG("oc_connectivity_init: successfully initialized connectivity\n");
  return 0;

error:
  OC_ERR("oc_connectivity_init: failed to initialize connectivity\n");
  return -1;
}

void
oc_connectivity_shutdown(int device)
{
  (void)device;
#ifdef OC_SECURITY
  net_context_put(dtls_recv6);
#endif /* OC_SECURITY */
  net_context_put(udp_recv6);
  net_context_put(mcast_recv6);
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  oc_send_buffer(message);
}
#endif /* OC_CLIENT */
