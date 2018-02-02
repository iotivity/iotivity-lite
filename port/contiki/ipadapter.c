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

#include "contiki.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/rpl/rpl.h"
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include "simple-udp.h"

#define OCF_MCAST_PORT_UNSECURED (5683)
#define OCF_SERVER_PORT_UNSECURED (56789)

static struct simple_udp_connection server, mcast;
PROCESS(ip_adapter_process, "IP Adapter");
static uip_ipaddr_t ipaddr, mcastaddr;

void
handle_incoming_message(uint8_t *buffer, int size, uint8_t *addr, uint16_t port)
{
  oc_message_t *message = oc_allocate_message();

  if (message) {
    size_t bytes_read = size;
    bytes_read = (bytes_read < OC_PDU_SIZE) ? bytes_read : OC_PDU_SIZE;
    memcpy(message->data, buffer, bytes_read);
    message->length = bytes_read;
    message->endpoint.flags = IPV6;
    memcpy(message->endpoint.addr.ipv6.address, addr, 16);
    message->endpoint.addr.ipv6.port = port;

    OC_DBG("Incoming message from ");
    OC_LOGipaddr(message->endpoint);
    OC_DBG("\n");

    oc_network_event(message);
    return;
  }

  OC_WRN("ipadapter: No free RX/TX buffers to handle incoming message\n");
}

static void
receive(struct simple_udp_connection *c, const uip_ipaddr_t *sender_addr,
        uint16_t sender_port, const uip_ipaddr_t *receiver_addr,
        uint16_t receiver_port, const uint8_t *data, uint16_t datalen)
{
  OC_DBG(
    "ipadapter: Incoming message from network...dispatch for processing\n");
  handle_incoming_message((uint8_t *)data, datalen, (uint8_t *)sender_addr,
                          sender_port);
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  (void)device;
  oc_init_endpoint_list();
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(oc_endpoint_t));
  ep.flags = IPV6;
  memcpy(ep.addr.ipv6.address, ipaddr.u8, 16);
  ep.addr.ipv6.port = OCF_SERVER_PORT_UNSECURED;
  ep.device = 0;
  oc_add_endpoint_to_list(&ep);
  return oc_get_endpoint_list();
}

static uip_ipaddr_t *
set_global_address(void)
{
  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  /*
   * Joining the OCF multicast group at ff0x::158
   */
  uip_ip6addr(&mcastaddr, 0xff02, 0, 0, 0, 0, 0, 0, 0x0158);
  uip_ds6_maddr_t *rv = uip_ds6_maddr_add(&mcastaddr);
  if (rv)
    OC_DBG("Joined OCF multicast group\n");
  else
    OC_WRN("Failed to join OCF multicast group\n");

  return &ipaddr;
}

static void
create_rpl_dag(uip_ipaddr_t *ipaddr)
{
  struct uip_ds6_addr *root_if;
  root_if = uip_ds6_addr_lookup(ipaddr);
  if (root_if != NULL) {
    rpl_dag_t *dag;
    uip_ipaddr_t prefix;
    rpl_set_root(RPL_DEFAULT_INSTANCE, ipaddr);
    dag = rpl_get_any_dag();
    uip_ip6addr(&prefix, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &prefix, 64);
    OC_DBG("Created new RPL DAG\n");
  } else {
    OC_WRN("Failed to create new RPL DAG\n");
  }
}

PROCESS_THREAD(ip_adapter_process, ev, data)
{
  static uip_ipaddr_t *ipaddr;

  PROCESS_BEGIN();

  ipaddr = set_global_address();

  create_rpl_dag(ipaddr);

  simple_udp_register(&mcast, OCF_MCAST_PORT_UNSECURED, NULL, 0, receive);

  simple_udp_register(&server, OCF_SERVER_PORT_UNSECURED, NULL, 0, receive);

  OC_DBG("ipadapter: Initialized ip_adapter_process\n");
  while (ev != PROCESS_EVENT_EXIT) {
    PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}

void
oc_send_buffer(oc_message_t *message)
{
  OC_DBG("Outgoing message to ");
  OC_LOGipaddr(message->endpoint);
  OC_DBG("\n");

  simple_udp_sendto_port(
    &server, message->data, message->length,
    (const uip_ipaddr_t *)message->endpoint.addr.ipv6.address,
    message->endpoint.addr.ipv6.port);
}

int
oc_connectivity_init(int device)
{
  (void)device;
  process_start(&ip_adapter_process, NULL);
  return 0;
}

void
oc_connectivity_shutdown(int device)
{
  (void)device;
  process_exit(&ip_adapter_process);
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  oc_send_buffer(message);
}
#endif /* OC_CLIENT */

/*
 * oc_network_event_handler_mutex_* are defined only to comply with the
 * connectivity interface, but are not used since the adapter process does
 * not preempt the process running the event loop.
*/
void
oc_network_event_handler_mutex_init(void)
{
}

void
oc_network_event_handler_mutex_lock(void)
{
}

void oc_network_event_handler_mutex_unlock(void) {}

void oc_network_event_handler_mutex_destroy(void) {}
