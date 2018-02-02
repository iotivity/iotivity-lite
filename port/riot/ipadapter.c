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

#include "mutex.h"
#include "net/af.h"
#include "net/conn/udp.h"
#include "net/gnrc/conn.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/rpl.h"
#include "net/gnrc/udp.h"
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include "thread.h"

static volatile bool terminate;

#define OCF_MCAST_PORT_UNSECURED (5683)
#define OCF_SERVER_PORT_UNSECURED (56789)

static uint8_t buffer1[OC_PDU_SIZE];
static uint8_t buffer2[OC_PDU_SIZE];

static char _recv_stack[THREAD_STACKSIZE_DEFAULT];
static char _mcast_stack[THREAD_STACKSIZE_DEFAULT];

static kernel_pid_t recv_thread;
static kernel_pid_t mcast_thread;
static kernel_pid_t interface_pid;

static uint8_t local_addr[16];

static mutex_t mutex;

void
oc_network_event_handler_mutex_init(void)
{
  mutex_init(&mutex);
}

void
oc_network_event_handler_mutex_lock(void)
{
  mutex_lock(&mutex);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  mutex_unlock(&mutex);
}

void oc_network_event_handler_mutex_destroy(void) {}

void oc_send_buffer(oc_message_t *message) {
  OC_DBG("Outgoing message to ");
  OC_LOGipaddr(message->endpoint);
  OC_DBG("\n");

  conn_udp_sendto(message->data, message->length, local_addr, 16,
                  message->endpoint.addr.ipv6.address, 16, AF_INET6,
                  OCF_SERVER_PORT_UNSECURED, message->endpoint.addr.ipv6.port);
}

void
handle_incoming_message(uint8_t *buffer, int *size, uint8_t *addr,
                        uint16_t *port)
{
  oc_message_t *message = oc_allocate_message();

  if (message) {
    memcpy(message->data, buffer, *size);
    message->length = *size;
    message->endpoint.flags = IPV6;
    memcpy(message->endpoint.addr.ipv6.address, addr, 16);
    message->endpoint.addr.ipv6.port = *port;

    OC_DBG("Incoming message from ");
    OC_LOGipaddr(message->endpoint);
    OC_DBG("\n");

    oc_network_event(message);
  }
}

void *
server_receive_thread(void *arg)
{
  (void)arg;

  uint8_t remote_addr[16] = { 0 };
  size_t remote_addr_len;
  uint16_t remote_port;

  conn_udp_t conn;
  int n = conn_udp_create(&conn, local_addr, sizeof(local_addr), AF_INET6,
                          OCF_SERVER_PORT_UNSECURED);

  if (n != 0) {
    PRINT("ipadapter: failed to register server receive socket\n");
    return NULL;
  }

  while (!terminate) {
    PRINT("ipadapter: waiting for server requests...\n");
    n = conn_udp_recvfrom(&conn, (char *)buffer1, OC_PDU_SIZE, remote_addr,
                          &remote_addr_len, &remote_port);
    if (n < 0) {
      PRINT("ipadapter_server_recv: error in conn_udp_recvfrom().n=%u\n", n);
      continue;
    }

    PRINT("ipadapter: got server request\n");
    handle_incoming_message(buffer1, &n, remote_addr, &remote_port);
  }

  return NULL;
}

void *
multicast_receive_thread(void *arg)
{
  (void)arg;

  uint8_t wk_addr[16] = { 0xff, 0x02, 0, 0, 0, 0, 0,    0,
                          0,    0,    0, 0, 0, 0, 0x01, 0x58 };
  static uint8_t addr[16];
  uint8_t remote_addr[16] = { 0 };
  size_t remote_addr_len;
  uint16_t remote_port;

  conn_udp_t conn;

  int n = conn_udp_create(&conn, addr, sizeof(addr), AF_INET6,
                          OCF_MCAST_PORT_UNSECURED);

  if (n != 0) {
    PRINT("ipadapter: failed to register multicast receive socket\n");
    return NULL;
  }

  ipv6_addr_t *if_addr =
    gnrc_ipv6_netif_add_addr(interface_pid, (ipv6_addr_t *)&wk_addr, 128, 0);

  if (if_addr == NULL) {
    PRINT("ipadapter: error.. could not join multicast group\n");
    return NULL;
  }

  gnrc_ipv6_netif_addr_get(if_addr)->valid = UINT32_MAX;
  gnrc_ipv6_netif_addr_get(if_addr)->preferred = UINT32_MAX;

  while (!terminate) {
    PRINT("ipadapter: waiting for multicast requests...\n");
    n = conn_udp_recvfrom(&conn, (char *)buffer2, OC_PDU_SIZE, remote_addr,
                          &remote_addr_len, &remote_port);
    if (n < 0) {
      PRINT("ipadapter_multicast_recv: error in conn_udp_recvfrom().n=%u\n", n);
      continue;
    }

    PRINT("ipadapter: got multicast request\n");
    handle_incoming_message(buffer2, &n, remote_addr, &remote_port);
  }

  return NULL;
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  (void)device;
  oc_init_endpoint_list();
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(oc_endpoint_t));
  ep.flags = IPV6;

  gnrc_ipv6_netif_t *iface = gnrc_ipv6_netif_get(interface_pid);
  gnrc_ipv6_netif_addr_t *addr = &iface->addrs[1];
  memcpy(ep.addr.ipv6.address, addr->addr.u8, 16);

  ep.addr.ipv6.port = OCF_SERVER_PORT_UNSECURED;
  ep.device = 0;
  oc_add_endpoint_to_list(&ep);
  return oc_get_endpoint_list();
}

int
oc_connectivity_init(int device)
{
  (void)device;
  kernel_pid_t interfaces[GNRC_NETIF_NUMOF];
  size_t if_num = gnrc_netif_get(interfaces);

  if (if_num == 0) {
    PRINT("ipadapter: error.. no available network interface\n");
    return -1;
  }

  interface_pid = interfaces[0];

  gnrc_ipv6_netif_init_by_dev();

  recv_thread =
    thread_create(_recv_stack, sizeof(_recv_stack), 1, 0, server_receive_thread,
                  NULL, "Server receive thread");

  mcast_thread =
    thread_create(_mcast_stack, sizeof(_mcast_stack), 0, 0,
                  multicast_receive_thread, NULL, "Multicast receive thread");

  return 0;
}

void
oc_connectivity_shutdown(int device)
{
  (void)device;
  terminate = true;
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  oc_send_buffer(message);
}
#endif /* OC_CLIENT */
