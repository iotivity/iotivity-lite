/*
// Copyright 2018 Oleksandr Grytsov
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
#include "oc_log.h"

#include <openthread/ip6.h>
#include <openthread/thread.h>
#include <openthread/udp.h>

extern otInstance *ot_instance;

static otUdpSocket unicast_socket;
static otUdpSocket multicast_socket;

#define OCF_MCAST_PORT_UNSECURED (5683)
#define OCF_SERVER_PORT_UNSECURED (56789)

static void udp_receive_cbk(void *context, otMessage *ot_message,
                            const otMessageInfo *ot_message_info)
{
  (void)context;

  OC_DBG("Receive udp cbk\n");

  oc_message_t *oc_message = oc_allocate_message();

  if (oc_message) {
    uint16_t payloadLength = otMessageGetLength(ot_message) -
                             otMessageGetOffset(ot_message);
    if (otMessageRead(ot_message, otMessageGetOffset(ot_message),
                      oc_message->data, payloadLength) != payloadLength) {
      OC_ERR("Can't read message\n");
      return;
    }
    oc_message->length = payloadLength;
    oc_message->endpoint.flags = IPV6;
    memcpy(oc_message->endpoint.addr.ipv6.address,
	   ot_message_info->mPeerAddr.mFields.m8, OT_IP6_ADDRESS_SIZE);
    oc_message->endpoint.addr.ipv6.port = ot_message_info->mPeerPort;

    OC_DBG("Incoming message from ");
    OC_LOGipaddr(oc_message->endpoint);
    OC_DBG("\n");

    oc_network_event(oc_message);
  }
}

oc_endpoint_t *
oc_connectivity_get_endpoints(int device)
{
  (void)device;

  oc_init_endpoint_list();

  oc_endpoint_t ep;

  memset(&ep, 0, sizeof(oc_endpoint_t));

  const otNetifAddress *address = otIp6GetUnicastAddresses(ot_instance);

  while(address) {
    ep.flags = IPV6;
    memcpy(ep.addr.ipv6.address, address->mAddress.mFields.m8,
           OT_IP6_ADDRESS_SIZE);
    ep.addr.ipv6.port = OCF_SERVER_PORT_UNSECURED;
    ep.device = 0;

    OC_DBG("Endpoint ");
    OC_LOGipaddr(ep);
    OC_DBG("\n");

    oc_add_endpoint_to_list(&ep);

    address = address->mNext;
  }
  return oc_get_endpoint_list();
}

void
oc_send_buffer(oc_message_t *message)
{
  otMessage *ot_message = otUdpNewMessage(ot_instance, true);

  if (!ot_message) {
    OC_ERR("No more buffer to send\n");
    return;
  }

  if (otMessageAppend(ot_message,
                      message->data, message->length) != OT_ERROR_NONE) {
    OC_ERR("Can't append message\n");
    return;
  }

  otMessageInfo message_info;

  memset(&message_info, 0, sizeof(otMessageInfo));

  message_info.mInterfaceId = OT_NETIF_INTERFACE_ID_THREAD;

  memcpy(&message_info.mPeerAddr.mFields, message->endpoint.addr.ipv6.address,
	 OT_IP6_ADDRESS_SIZE);
  message_info.mPeerPort = message->endpoint.addr.ipv6.port;

  OC_DBG("Send message to ");
  OC_LOGipaddr(message->endpoint);
  OC_DBG("\n");

  if (otUdpSend(&unicast_socket, ot_message, &message_info) != OT_ERROR_NONE) {
    OC_ERR("Can't send message\n");
    return;
  }
}

int
oc_connectivity_init(int device)
{
  (void)device;

  OC_DBG("Connectivity init\n");

  otIp6Address maddr;

  if (otIp6AddressFromString("ff02::158", &maddr) != OT_ERROR_NONE) {
    OC_ERR("Can't convert mcast address\n");
    return -1;
  }

  if (otIp6SubscribeMulticastAddress(ot_instance, &maddr) != OT_ERROR_NONE) {
    OC_ERR("Can't subscribe mcast address\n");
    return -1;
  }

  if (otUdpOpen(ot_instance, &unicast_socket,
                udp_receive_cbk, NULL) != OT_ERROR_NONE) {
    OC_ERR("Can't open unicast socket\n");
    return -1;
  }

  otSockAddr sockaddr;

  memset(&sockaddr, 0, sizeof(otSockAddr));

  sockaddr.mPort = OCF_SERVER_PORT_UNSECURED;

  if (otUdpBind(&unicast_socket, &sockaddr) != OT_ERROR_NONE) {
    OC_ERR("Can't bind unicast port\n");
    return -1;
  }

  if (otUdpOpen(ot_instance, &multicast_socket,
                udp_receive_cbk, NULL) != OT_ERROR_NONE) {
    OC_ERR("Can't open multicast socket\n");
    return -1;
  }

  sockaddr.mPort = OCF_MCAST_PORT_UNSECURED;

  if (otUdpBind(&multicast_socket, &sockaddr) != OT_ERROR_NONE) {
    OC_ERR("Can't bind multicast port\n");
    return -1;
  }

  return 0;
}

void
oc_connectivity_shutdown(int device)
{
  (void)device;

  OC_DBG("Connectivity shutdown: %d\n", device);

  otIp6SetEnabled(ot_instance, false);
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  OC_DBG("Send discovery request\n");

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
  OC_DBG("Network mutex init\n");
}

void
oc_network_event_handler_mutex_lock(void)
{
  OC_DBG("Network mutex lock\n");
}

void
oc_network_event_handler_mutex_unlock(void)
{
  OC_DBG("Network mutex unlock\n");
}

void
oc_network_event_handler_mutex_destroy(void)
{
  OC_DBG("Network mutex destroy\n");
}
