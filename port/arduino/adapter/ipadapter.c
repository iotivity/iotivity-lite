/******************************************************************
*
* Copyright 2018 iThemba LABS All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

*    http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
******************************************************************/
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "ipcontext.h"
#include "util/oc_process.h"
#include "util/oc_etimer.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "ethadapter_utils.h"

OC_PROCESS(ip_adapter_process, "IP Adapter");
OC_LIST(ip_contexts);
OC_MEMB(ip_context_s, ip_context_t, OC_MAX_NUM_DEVICES);
OC_MEMB(device_eps, oc_endpoint_t, 2*OC_MAX_NUM_DEVICES); // fix

void
oc_network_event_handler_mutex_init(void){}

void
oc_network_event_handler_mutex_lock(void){}

void
oc_network_event_handler_mutex_unlock(void){}

void oc_network_event_handler_mutex_destroy(void) {}

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

static void
free_endpoints_list(ip_context_t *dev)
{
  oc_endpoint_t *ep = oc_list_pop(dev->eps);

  while (ep != NULL) {
    oc_memb_free(&device_eps, ep);
    ep = oc_list_pop(dev->eps);
  }
}
/*We not handling potential change of network interface as yet*/
static void
get_interface_addresses(ip_context_t *dev, uint16_t port, bool secure)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(oc_endpoint_t));
  ep.flags = IPV4;
  oc_ard_get_iface_addr(ep.addr.ipv4.address);
  ep.addr.ipv4.port = port;
  if (secure) {
    ep.flags |= SECURED;
  }
  oc_endpoint_t *new_ep = oc_memb_alloc(&device_eps);
  if (!new_ep) {
    return;
  }
  memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
  oc_list_add(dev->eps, new_ep);
}

static void
refresh_endpoints_list(ip_context_t *dev)
{
  free_endpoints_list(dev);
  get_interface_addresses(dev, dev->port4, false);
#ifdef OC_SECURITY
  get_interface_addresses(dev, dev->dtls4_port, true);
#endif /* OC_SECURITY */
}

oc_endpoint_t *
oc_connectivity_get_endpoints(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  if (!dev) {
    return NULL;
  }
  if (oc_list_length(dev->eps) == 0) {
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev);
    oc_network_event_handler_mutex_unlock();
  }
  return oc_list_head(dev->eps);
}

int oc_send_buffer(oc_message_t *message) {
  PRINT("Outgoing message to: ");
  PRINTipaddr(message->endpoint);
  PRINT("\r\n");
  uint8_t send_sock = 0;
  uint16_t send_port = 0;
  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);
#ifdef OC_CLIENT
  if (message->endpoint.flags & DISCOVERY) {
      send_sock = dev->mcast4_sock;
      send_port = (uint16_t)OCF_MCAST_PORT_UNSECURED;
  } else {
#ifdef OC_SECURITY
      if (message->endpoint.flags & SECURED) {
        send_sock = dev->secure4_sock;
      } else
#else
        send_sock = dev->server4_sock;
#endif
      send_port = message->endpoint.addr.ipv4.port;
  }
#endif

#ifdef OC_SERVER
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
    send_sock = dev->secure4_sock;
  } else
#else
  {
    send_sock = dev->server4_sock;
  }
#endif
    send_sock = dev->server4_sock;
    send_port = message->endpoint.addr.ipv4.port;
#endif
  ard_send_data(send_sock, message->endpoint.addr.ipv4.address, &send_port,
                         message->data, message->length);
  return message->length;
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  oc_send_buffer(message);
}
#endif /* OC_CLIENT */

int
oc_connectivity_init(size_t device)
{
  OC_DBG("Initializing IPv4 connectivity for device %d", device);
  ip_context_t *dev = (ip_context_t *)oc_memb_alloc(&ip_context_s);
  if (!dev) {
    oc_abort("drained mem");
  }
  oc_list_add(ip_contexts, dev);
  dev->device = device;
  OC_LIST_STRUCT_INIT(dev, eps);

  uint16_t mcast_port = (uint16_t)OCF_MCAST_PORT_UNSECURED;
  dev->port4 = (uint16_t)OCF_PORT_UNSECURED;
  dev->server4_sock = start_udp_server(&dev->port4);
#ifdef OC_SERVER
  dev->mcast4_sock = start_udp_mcast_server(OCF_IPv4_MULTICAST, &mcast_port, &mcast_port);
#endif
#ifdef OC_CLIENT
  dev->mcast4_sock = start_udp_mcast_server(OCF_IPv4_MULTICAST, &mcast_port, &dev->port4);
#endif
#ifdef OC_SECURITY
    dev->dtls4_port = (uint16_t)OCF_PORT_SECURED;
    dev->secure4_sock = start_udp_server(&dev->dtls4_port);
#endif
  oc_process_start(&ip_adapter_process, dev);

  OC_DBG("=======ip port info.========");
  OC_DBG("  ipv4 port   : %u", dev->port4);
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %u", dev->dtls4_port);
#endif
  OC_DBG("Successfully initialized connectivity for device %d", device);
  return 0;
}

void
oc_connectivity_shutdown(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  oc_process_exit(&ip_adapter_process);
  close(dev->server4_sock);
  close(dev->mcast4_sock);
#ifdef OC_SECURITY
  close(dev->secure4_sock);
#endif /* OC_SECURITY */
  free_endpoints_list(dev);
  oc_list_remove(ip_contexts, dev);
  oc_memb_free(&ip_context_s, dev);
  OC_DBG("oc_connectivity_shutdown for device %d", device);
}

static adapter_receive_state_t
oc_udp_receive_message(ip_context_t *dev, sdset_t *sds, oc_message_t *message)
{

  // unsecure unicast reception
  if (!SD_ISSET(dev->server4_sock, sds)) {
      int count = recv_msg(&dev->server4_sock,message->endpoint.addr.ipv4.address,
                          &message->endpoint.addr.ipv4.port, message->data, sds->rcv_size);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4;
    SD_SET(dev->server4_sock, sds);
    return ADAPTER_STATUS_RECEIVE;
  }
  // multcast reception
  if (!SD_ISSET(dev->mcast4_sock, sds)) {
      int count = recv_msg(&dev->mcast4_sock,message->endpoint.addr.ipv4.address,
                          &message->endpoint.addr.ipv4.port, message->data, sds->rcv_size);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | MULTICAST;
    SD_SET(dev->mcast4_sock, sds);
    return ADAPTER_STATUS_RECEIVE;
  }
#ifdef OC_SECURITY
  if (!SD_ISSET(dev->secure4_sock, sds)) {
      int count = recv_msg(&dev->secure4_sock,message->endpoint.addr.ipv4.address,
                          &message->endpoint.addr.ipv4.port, message->data, sds->rcv_size);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }
    message->length = (size_t)count;
    message->endpoint.flags = IPV4 | SECURED;
    message->encrypted = 1;
    SD_SET(dev->secure4_sock, sds);
    return ADAPTER_STATUS_RECEIVE;
  }
#endif
  return ADAPTER_STATUS_NONE;
}

static void
oc_udp_add_socks_to_SD_SET(ip_context_t *dev)
{
  SD_ZERO(&dev->rsds);
  OC_DBG("reset sockets descriptor: %d", dev->rsds.sdsset);
  SD_SET(dev->server4_sock, &dev->rsds);
  SD_SET(dev->mcast4_sock, &dev->rsds);
#ifdef OC_SECURITY
  SD_SET(dev->secure4_sock, &dev->rsds);
#endif
}

OC_PROCESS_THREAD(ip_adapter_process, ev, data)
{
  static struct oc_etimer et;
  uint8_t i = 0, n = 0;
  OC_PROCESS_BEGIN();
  static uint8_t maxsd;
  static ip_context_t *dev;
  static sdset_t setsds;
  while (ev != OC_PROCESS_EVENT_EXIT) {
    oc_etimer_set(&et, (oc_clock_time_t)0.01);

    if(ev == OC_PROCESS_EVENT_INIT){

      dev = (ip_context_t *)data;
      oc_udp_add_socks_to_SD_SET(dev);
      memcpy(&setsds, &dev->rsds, sizeof(sdset_t));
      maxsd =  (dev->server4_sock > dev->mcast4_sock) ? dev->server4_sock : dev->mcast4_sock;
#ifdef OC_SECURITY
      maxsd = (dev->secure4_sock > dev->mcast4_sock) ? dev->secure4_sock : dev->mcast4_sock;
#endif
      OC_DBG("ipadapter: Initialized ip_adapter_process");
    }
    else if(ev == OC_PROCESS_EVENT_TIMER){
      n = select( maxsd + 1 , &setsds);
      if(n > 0) {
        for(i = 0; i < n; i++) {

          oc_message_t *message = oc_allocate_message();
          if (!message) {
            break;
          }
          message->endpoint.device = dev->device;
          if (oc_udp_receive_message(dev, &setsds, message) ==
            ADAPTER_STATUS_RECEIVE) {
            goto common;
          }
          oc_message_unref(message);
          continue;
        common:
          PRINT("Incoming message of size %u bytes from ", message->length);
          PRINTipaddr(message->endpoint);
          PRINT("\r\n");
          oc_network_event(message);
        }
      }
    }
    OC_PROCESS_WAIT_EVENT();
  }
 OC_PROCESS_END();
}
