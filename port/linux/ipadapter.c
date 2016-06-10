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

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>
#include "oc_buffer.h"
#include "port/oc_connectivity.h"
#include <assert.h>
#include <ifaddrs.h>
#include <net/if.h>

struct sockaddr_storage mcast, server, client;
int server_sock = -1, mcast_sock = -1, terminate;

#ifdef OC_SECURITY 
struct sockaddr_storage secure;
int secure_sock = -1;
uint16_t dtls_port = 0;

uint16_t
oc_connectivity_get_dtls_port()
{
  return dtls_port;
}
#endif /* OC_SECURITY */

void
oc_poll_network()
{
  struct sockaddr_in6 *c = (struct sockaddr_in6*)&client;
  size_t len = sizeof(client);
  fd_set rfds;
  struct timeval tv;
  
  tv.tv_sec = 0;
  tv.tv_usec = 10000;

  FD_ZERO(&rfds);
  FD_SET(server_sock, &rfds);
  FD_SET(mcast_sock, &rfds);

#ifdef OC_SECURITY  
  FD_SET(secure_sock, &rfds);    
#endif
  
  int ret = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);

  if (ret > 0) {
    oc_message_t *message  = oc_allocate_message();
    if (!message) {
      LOG("No more free RX/TX buffers to process request\n");
      return;
    }
    LOG("Received network request ");

#ifdef OC_SECURITY    
    if(FD_ISSET(secure_sock, &rfds)) {
      LOG("on secure socket\n");
      message->length = recvfrom(secure_sock, message->data,
				 MAX_PAYLOAD_SIZE, 0,
				 (struct sockaddr*)&client, &len);
      message->endpoint.flags = IP | SECURED; //Fix
    }
#endif /* OC_SECURITY */
    
    if(FD_ISSET(server_sock, &rfds)) {
      LOG("on server socket\n");
      message->length = recvfrom(server_sock, message->data,
				 MAX_PAYLOAD_SIZE, 0,
				 (struct sockaddr*)&client, &len);
      message->endpoint.flags = IP;
    }
    if(FD_ISSET(mcast_sock, &rfds)) {
      LOG("on multicast socket\n");
      message->length = recvfrom(mcast_sock, message->data,
				 MAX_PAYLOAD_SIZE, 0,
				 (struct sockaddr*)&client, &len);
      message->endpoint.flags = IP;
    }
    
    memcpy(message->endpoint.ipv6_addr.address, c->sin6_addr.s6_addr,
	   sizeof(c->sin6_addr.s6_addr));
    message->endpoint.ipv6_addr.scope = c->sin6_scope_id;
    message->endpoint.ipv6_addr.port = ntohs(c->sin6_port);
    
    PRINT("Incoming message from\n");
    PRINTipaddr(message->endpoint);
    PRINT(":%d\n", message->endpoint.ipv6_addr.port);
    
    oc_recv_message(message);
  }
}

void
oc_send_buffer(oc_message_t * message)
{
  PRINT("Outgoing message to ");
  PRINTipaddr(message->endpoint);
  PRINT(":%d\n", message->endpoint.ipv6_addr.port);

  struct sockaddr_storage receiver;
  struct sockaddr_in6 *r = (struct sockaddr_in6*)&receiver;
  memcpy(r->sin6_addr.s6_addr, message->endpoint.ipv6_addr.address,
	 sizeof(r->sin6_addr.s6_addr));
  r->sin6_family = AF_INET6;
  r->sin6_port = htons(message->endpoint.ipv6_addr.port);
  r->sin6_scope_id = message->endpoint.ipv6_addr.scope;
  int send_sock = -1;
  
#ifdef OC_SECURITY  
  if (message->endpoint.flags & SECURED)
    send_sock = secure_sock;
  else
#endif /* OC_SECURITY */    
    send_sock = server_sock;
  
  int bytes_sent = 0;
  while (bytes_sent < message->length) {
    int x = sendto(send_sock, message->data + bytes_sent,
		   message->length - bytes_sent, 0,
		   (struct sockaddr*)&receiver,
		   sizeof(receiver));
    bytes_sent += x;
  }
  PRINT("%d bytes sent\n", bytes_sent);  
}

void
oc_send_multicast_message(oc_message_t *message)
{
    struct ifaddrs *ifs = NULL, *interface = NULL;     
    if (getifaddrs(&ifs) < 0) {
      LOG("error querying interfaces: %d\n", errno);
      goto done;	 
    }	
    for (interface = ifs; interface != NULL; interface = interface->ifa_next)
    {
      if (!interface->ifa_flags & IFF_UP ||
	  interface->ifa_flags & IFF_LOOPBACK)
	continue;   
      if (interface->ifa_addr &&
	  interface->ifa_addr->sa_family == AF_INET6) {
	struct sockaddr_in6* addr =
	  (struct sockaddr_in6*)interface->ifa_addr;
	if(IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
	  int mif = addr->sin6_scope_id;
	  if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mif,
			 sizeof(mif)) == -1) {
	    LOG("ERROR setting socket option for default IPV6_MULTICAST_IF: %d\n", errno);
	    goto done;
	  }
	  oc_send_buffer(message);
	}
      }
    }
 done:    
    freeifaddrs(ifs);
}

int
oc_connectivity_init()
{
  memset(&mcast, 0, sizeof(struct sockaddr_storage));
  memset(&server, 0, sizeof(struct sockaddr_storage));

  struct sockaddr_in6 *m = (struct sockaddr_in6*)&mcast;
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(COAP_PORT_UNSECURED);
  m->sin6_addr = in6addr_any;
	
  struct sockaddr_in6 *l = (struct sockaddr_in6*)&server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;

#ifdef OC_SECURITY
  memset(&secure, 0, sizeof(struct sockaddr_storage));  
  struct sockaddr_in6 *sm = (struct sockaddr_in6*)&secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_port = 0;
  sm->sin6_addr = in6addr_any;
#endif /* OC_SECURITY */
  
  server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  
  if(server_sock < 0 || mcast_sock < 0) {
    LOG("ERROR creating server sockets\n");
    return -1;
  }
  
#ifdef OC_SECURITY   
  secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (secure_sock < 0) {
    LOG("ERROR creating secure socket\n");
    return -1;
  }
#endif /* OC_SECURITY */
  
  if(bind(server_sock, (struct sockaddr*)&server, sizeof(server)) == -1) {
    LOG("ERROR binding server socket %d\n", errno);
    return -1;
  }
	
  struct ipv6_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  if(inet_pton(AF_INET6, ALL_COAP_NODES_V6, (void*)&mreq.ipv6mr_multiaddr)
     != 1) {
    LOG("ERROR setting mcast addr\n");
    return -1;
  }	
  mreq.ipv6mr_interface = 0;	
  if(setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
		sizeof(mreq)) == -1) {
    LOG("ERROR setting mcast join option %d\n", errno);
    return -1;
  }
  int reuse = 1;
  if(setsockopt(mcast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
		sizeof(reuse)) == -1) {
    LOG("ERROR setting reuseaddr option %d\n", errno);
    return -1;
  }
  if(bind(mcast_sock, (struct sockaddr*)&mcast, sizeof(mcast)) == -1) {
    LOG("ERROR binding mcast socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY  
  if(setsockopt(secure_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
		sizeof(reuse)) == -1) {
    LOG("ERROR setting reuseaddr option %d\n", errno);
    return -1;
  }
  if(bind(secure_sock, (struct sockaddr*)&secure, sizeof(secure)) == -1) {
    LOG("ERROR binding smcast socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(secure);  
  if (getsockname(secure_sock,
		  (struct sockaddr*)&secure,
		  &socklen) == -1) {
    LOG("ERROR obtaining secure socket information %d\n", errno);
    return -1;
  }
  
  dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */
  
  LOG("Successfully initialized connectivity\n");
  return 1;
}

void
oc_connectivity_shutdown()
{
  close(server_sock);
  close(mcast_sock);
  
#ifdef OC_SECURITY
  close(secure_sock);
#endif /* OC_SECURITY */
  
  LOG("oc_connectivity_shutdown\n");
}
