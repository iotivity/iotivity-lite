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

#include <zephyr.h>
#include <stddef.h>
#include <stdint.h>

#include <net/ip_buf.h>
#include <net/net_core.h>
#include <net/net_socket.h>
#include "port/oc_connectivity.h"
#include "oc_buffer.h"

#define RECV_FIBER_STACK_SIZE 600
static char stack1[RECV_FIBER_STACK_SIZE];
static char stack2[RECV_FIBER_STACK_SIZE];

#define NODE_PORT (53810)
#define COAP_PORT_UNSECURED (5683)

static struct net_addr node_addr = { .in6_addr = IN6ADDR_ANY_INIT,
				     .family = AF_INET6 };
static struct net_context *recv_ctx = NULL;
#define COAP_ALL_NODES_LL { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } } }
static struct net_addr coap_wk = { .in6_addr = COAP_ALL_NODES_LL,
				   .family = AF_INET6 };
static struct net_context *multicast_ctx = NULL;
static struct net_addr ipv6_any = { .in6_addr = IN6ADDR_ANY_INIT,
				    .family = AF_INET6 };
static struct net_context *peer_ctx = NULL;
static struct net_addr peer_addr;
static int terminate;

void
net_buf_to_oc_message(struct net_buf *buf)
{
  oc_message_t *message = oc_allocate_message();
  if (message) {
    memcpy(message->data, ip_buf_appdata(buf), ip_buf_appdatalen(buf));
    message->length = ip_buf_appdatalen(buf);
    message->endpoint.flags = IP;
    memcpy(message->endpoint.ipv6_addr.address,
	   NET_BUF_IP(buf)->srcipaddr.u8,
	   16);
    message->endpoint.ipv6_addr.scope = 0;
    message->endpoint.ipv6_addr.port =
      uip_ntohs(NET_BUF_UDP(buf)->srcport);

    PRINT("Incoming message from: ");
    PRINTipaddr(message->endpoint);
    PRINT(":%d\n", message->endpoint.ipv6_addr.port);

    oc_network_event(message);
  }
}

static struct nano_sem sem;

void
oc_network_event_handler_mutex_init()
{
  nano_sem_init(&sem);
  nano_sem_give(&sem);
}

void
oc_network_event_handler_mutex_lock()
{
  nano_sem_take(&sem, TICKS_UNLIMITED);
}

void
oc_network_event_handler_mutex_unlock()
{
  nano_sem_give(&sem);
}

void
multicast_recv()
{
  static struct net_buf *buf;
  while (!terminate) {
    buf = net_receive(multicast_ctx, TICKS_UNLIMITED);
    if (buf) {
      net_buf_to_oc_message(buf);
      ip_buf_unref(buf);
    }
  }
}

void
server_recv()
{
  static struct net_buf *buf;
  while (!terminate) {
    buf = net_receive(recv_ctx, TICKS_UNLIMITED);
    if (buf) {
      net_buf_to_oc_message(buf);
      ip_buf_unref(buf);
    }
  }
}

static void
get_response_context(oc_ipv6_addr_t *remote)
{
  memcpy(peer_addr.in6_addr.s6_addr, remote->address, 16);
  peer_addr.family = AF_INET6;

  if (peer_ctx)
    net_context_put(peer_ctx);

  peer_ctx = net_context_get(IPPROTO_UDP,
			     &peer_addr, remote->port,
			     &node_addr, NODE_PORT);
}

void
oc_send_buffer(oc_message_t * message)
{
  PRINT("Outgoing message to: ");
  PRINTipaddr(message->endpoint);
  PRINT(":%d\n", message->endpoint.ipv6_addr.port);

  get_response_context(&message->endpoint.ipv6_addr);

  if (peer_ctx) {
    static struct net_buf *buf;
    buf = ip_buf_get_tx(peer_ctx);
    if (buf) {
      uint8_t *ptr = net_buf_add(buf, message->length);
      memcpy(ptr, message->data, message->length);
      ip_buf_appdatalen(buf) = message->length;
      if (net_send(buf) < 0) {
	ip_buf_unref(buf);
      }
    }
  }
}

int
oc_connectivity_init()
{
  net_init();

  recv_ctx = net_context_get(IPPROTO_UDP,
			     &ipv6_any, 0,
			     &node_addr, NODE_PORT);
  multicast_ctx = net_context_get(IPPROTO_UDP,
				  &ipv6_any, 0,
				  &coap_wk, COAP_PORT_UNSECURED);

  task_fiber_start(&stack1[0], RECV_FIBER_STACK_SIZE,
		   (nano_fiber_entry_t)server_recv, 0, 0, 7, 0);

  task_fiber_start(&stack2[0], RECV_FIBER_STACK_SIZE,
		   (nano_fiber_entry_t)multicast_recv, 0, 0, 7, 0);

  LOG("Successfully initialized connectivity\n");

  return 1;
}

void
oc_connectivity_shutdown()
{
  terminate = 1;
  net_context_put(recv_ctx);
  net_context_put(multicast_ctx);
}

void
oc_send_multicast_message(oc_message_t *message)
{
  oc_send_buffer(message);
}

//TODO:
uint16_t
oc_connectivity_get_dtls_port()
{
  return 0;
}
