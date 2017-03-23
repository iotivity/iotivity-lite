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
#include "port/oc_connectivity.h"

#include <errno.h>
#include <sections.h>
#include <stdio.h>
#include <zephyr.h>

#include <net/nbuf.h>
#include <net/net_context.h>
#include <net/net_core.h>
#include <net/net_if.h>

#if defined(CONFIG_NET_L2_BLUETOOTH)
#include <bluetooth/bluetooth.h>
#include <gatt/ipss.h>
#endif

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

#ifdef OC_SECURITY
/* DTLS receive socket */
static struct net_context *dtls_recv6;
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

static void
oc_network_receive(struct net_context *context, struct net_buf *buf, int status,
                   void *user_data)
{
  oc_message_t *message = oc_allocate_message();

  if (message) {
    uint16_t pos;
    size_t bytes_read = net_nbuf_appdatalen(buf);
    size_t offset_from_start = net_buf_frags_len(buf) - bytes_read;
    bytes_read = (bytes_read < OC_PDU_SIZE) ? bytes_read : OC_PDU_SIZE;
    struct net_buf *frag = net_nbuf_read(buf->frags, offset_from_start, &pos,
                                         bytes_read, message->data);
    if (!frag && pos == 0xffff) {
      net_nbuf_unref(buf);
      oc_message_unref(message);
      return;
    }

    message->length = bytes_read;
    if (user_data != NULL)
      message->endpoint.flags = IPV6 | SECURED;
    else
      message->endpoint.flags = IPV6;
    memcpy(message->endpoint.addr.ipv6.address, &NET_IPV6_BUF(buf)->src, 16);
    message->endpoint.addr.ipv6.scope = 0;
    message->endpoint.addr.ipv6.port = ntohs(NET_UDP_BUF(buf)->src_port);

    PRINT("oc_network_receive: received %d bytes\n", (int)message->length);
    PRINT("oc_network_receive: incoming message: ");
    PRINTipaddr(message->endpoint);
    PRINT("\n");

    oc_network_event(message);
  }

  net_nbuf_unref(buf);
}

static inline void
udp_sent(struct net_context *context, int status, void *token, void *user_data)
{
  if (!status)
    PRINT("oc_send_buffer: sent %d bytes\n", POINTER_TO_UINT(token));
  else
    PRINT("oc_send_buffer: failed: (%d)\n", status);
}

void
oc_send_buffer(oc_message_t *message)
{
  PRINT("oc_send_buffer: outgoing message: ");
  PRINTipaddr(message->endpoint);
  PRINT("\n");

  /* Populate destination address structure */
  struct sockaddr_in6 peer_addr;
  memcpy(peer_addr.sin6_addr.in6_u.u6_addr8,
         message->endpoint.addr.ipv6.address, 16);
  peer_addr.sin6_family = AF_INET6;
  peer_addr.sin6_port = htons(message->endpoint.addr.ipv6.port);

  /* Network buffer to hold data to be sent */
  struct net_buf *send_buf;
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
    send_buf = net_nbuf_get_tx(dtls_recv6, K_NO_WAIT);
  } else
#endif /* OC_SECURITY */
  {
    send_buf = net_nbuf_get_tx(udp_recv6, K_NO_WAIT);
  }
  if (!send_buf) {
    OC_WRN("oc_send_buffer: cannot acquire send_buf\n");
    return;
  }

  bool status = net_nbuf_append(send_buf, message->length, message->data, K_NO_WAIT);
  if (!status) {
    OC_WRN("oc_send_buffer: cannot populate send_buf\n");
    return;
  }

  int ret = net_context_sendto(
    send_buf, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in6),
    udp_sent, 0, UINT_TO_POINTER(net_buf_frags_len(send_buf)), NULL);
  if (ret < 0) {
    OC_WRN("oc_send_buffer: cannot send data to peer (%d)\n", ret);
    net_nbuf_unref(send_buf);
  }
}

int
oc_connectivity_init(void)
{
  int ret;
  static struct sockaddr_in6 mcast_addr6 = { 0 };
  static struct sockaddr_in6 my_addr6 = { 0 };
#ifdef OC_SECURITY
  static struct sockaddr_in6 dtls_addr6 = { 0 };
#endif /* OC_SECURITY */

#if defined(CONFIG_NET_L2_BLUETOOTH)
  if (bt_enable(NULL)) {
    OC_WRN("oc_connectivity_init: bluetooth initialization failed\n");
    return -1;
  }
  ipss_init();
  ipss_advertise();
#endif

  /* Record OCF's multicast address with network interface */
  net_if_ipv6_maddr_add(net_if_get_default(), &in6addr_mcast);

  net_ipaddr_copy(&mcast_addr6.sin6_addr, &in6addr_mcast);
  mcast_addr6.sin6_family = AF_INET6;
  mcast_addr6.sin6_port = htons(OCF_MCAST_PORT);

  /* Wildcard address set for server with randomly chosen port */
  my_addr6.sin6_family = AF_INET6;

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
oc_connectivity_shutdown(void)
{
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

#ifdef OC_SECURITY
uint16_t
oc_connectivity_get_dtls_port(void)
{
  return MY_DTLS_PORT;
}
#endif /* OC_SECURITY */
