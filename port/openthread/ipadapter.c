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
#include "port/oc_log.h"

#include <openthread/ip6.h>
#include <openthread/thread.h>
#include <openthread/udp.h>

extern otInstance *ot_instance;

static otUdpSocket unicast_socket;
static otUdpSocket multicast_socket;

#define OCF_MCAST_PORT_UNSECURED (5683)
#define OCF_SERVER_PORT_UNSECURED (56789)

static oc_endpoint_t *eps;

static void
udp_receive_cbk(void *context, otMessage *ot_message,
                const otMessageInfo *ot_message_info)
{
  (void)context;

  OC_DBG("Receive udp cbk");

  oc_message_t *oc_message = oc_allocate_message();

  if (oc_message) {
    uint16_t payloadLength = otMessageGetLength(ot_message) -
                             otMessageGetOffset(ot_message);
    if (otMessageRead(ot_message, otMessageGetOffset(ot_message),
                      oc_message->data, payloadLength) != payloadLength) {
      OC_ERR("Can't read message");
      return;
    }
    oc_message->length = payloadLength;
    oc_message->endpoint.flags = IPV6;
    memcpy(oc_message->endpoint.addr.ipv6.address,
           ot_message_info->mPeerAddr.mFields.m8, OT_IP6_ADDRESS_SIZE);
    oc_message->endpoint.addr.ipv6.port = ot_message_info->mPeerPort;

#ifdef OC_DEBUG
    PRINT("Incoming message from ");
    PRINTipaddr(message->endpoint);
    PRINT("\n\n");
#endif /* OC_DEBUG */

    oc_network_event(oc_message);
  }
}

static void
free_endpoints(void)
{
  oc_endpoint_t *ep = eps, *next;
  while (ep != NULL) {
    next = ep->next;
    oc_free_endpoint(ep);
    ep = next;
  }
}

oc_endpoint_t *
oc_connectivity_get_endpoints(size_t device)
{
  (void)device;
  const otNetifAddress *address;

  // We want our endpoints to use the latest IP addresses from OpenThread.
  // Therefore, we must first free the list of endpoints.
  while (eps) {
    oc_endpoint_t *next_endpoint;
    next_endpoint = eps->next;
    oc_free_endpoint(eps);
    eps = next_endpoint;
  }

  address = otIp6GetUnicastAddresses(OT_INSTANCE);
  while (address) {
    oc_endpoint_t *ep = oc_new_endpoint();
    // No more memory left for endpoints, so return the list.
    if (!ep) {
      return eps;
    }
    // Save the head of the list, if it hasn't been saved yet.
    if (!eps) {
      eps = ep;
    }

    // Populate the contents of the endpoint.
    ep->flags = IPV6;
    memcpy(ep->addr.ipv6.address, address->mAddress.mFields.m8,
           OT_IP6_ADDRESS_SIZE);
    ep->addr.ipv6.port = OCF_SERVER_PORT_UNSECURED;
    ep->device = 0;

    OC_DBG("Endpoint");
    OC_LOGipaddr(*ep);
    address = address->mNext;
  }
  return eps;
}

int
oc_send_buffer(oc_message_t *message)
{
  otMessage *ot_message = otUdpNewMessage(ot_instance, true);

  if (!ot_message) {
    OC_ERR("No more buffer to send");
    return -1;
  }

  if (otMessageAppend(ot_message,
                      message->data, message->length) != OT_ERROR_NONE) {
    OC_ERR("Can't append message");
    return -1;
  }

  otMessageInfo message_info;

  memset(&message_info, 0, sizeof(otMessageInfo));

  message_info.mInterfaceId = OT_NETIF_INTERFACE_ID_THREAD;

  memcpy(&message_info.mPeerAddr.mFields, message->endpoint.addr.ipv6.address,
	 OT_IP6_ADDRESS_SIZE);
  message_info.mPeerPort = message->endpoint.addr.ipv6.port;

#ifdef OC_DEBUG
  PRINT("Outgoing message to ");
  PRINTipaddr(message->endpoint);
  PRINT("\n\n");
#endif /* OC_DEBUG */

  if (otUdpSend(&unicast_socket, ot_message, &message_info) != OT_ERROR_NONE) {
    OC_ERR("Can't send message");
    return -1;
  }
  return 0;
}

int
oc_connectivity_init(size_t device)
{
  (void)device;

  OC_DBG("Connectivity init");

  otIp6Address maddr;

  if (otIp6AddressFromString("ff02::158", &maddr) != OT_ERROR_NONE) {
    OC_ERR("Can't convert mcast address");
    return -1;
  }

  if (otIp6SubscribeMulticastAddress(ot_instance, &maddr) != OT_ERROR_NONE) {
    OC_ERR("Can't subscribe mcast address");
    return -1;
  }

  if (otUdpOpen(ot_instance, &unicast_socket,
                udp_receive_cbk, NULL) != OT_ERROR_NONE) {
    OC_ERR("Can't open unicast socket");
    return -1;
  }

  otSockAddr sockaddr;

  memset(&sockaddr, 0, sizeof(otSockAddr));

  sockaddr.mPort = OCF_SERVER_PORT_UNSECURED;

  if (otUdpBind(&unicast_socket, &sockaddr) != OT_ERROR_NONE) {
    OC_ERR("Can't bind unicast port");
    return -1;
  }

  if (otUdpOpen(ot_instance, &multicast_socket,
                udp_receive_cbk, NULL) != OT_ERROR_NONE) {
    OC_ERR("Can't open multicast socket");
    return -1;
  }

  sockaddr.mPort = OCF_MCAST_PORT_UNSECURED;

  if (otUdpBind(&multicast_socket, &sockaddr) != OT_ERROR_NONE) {
    OC_ERR("Can't bind multicast port");
    return -1;
  }
  return 0;
}

void
oc_connectivity_shutdown(size_t device)
{
  (void)device;

  OC_DBG("Connectivity shutdown: %d", device);

  otIp6SetEnabled(ot_instance, false);
  free_endpoints();
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  OC_DBG("Send discovery request");

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
  OC_DBG("Network mutex init");
}

void
oc_network_event_handler_mutex_lock(void)
{
  OC_DBG("Network mutex lock");
}

void
oc_network_event_handler_mutex_unlock(void)
{
  OC_DBG("Network mutex unlock");
}

void
oc_network_event_handler_mutex_destroy(void)
{
  OC_DBG("Network mutex destroy");
}
