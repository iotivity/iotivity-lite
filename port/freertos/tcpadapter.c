/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "tcpadapter.h"
#include "ipcontext.h"
#include "messaging/coap/coap.h"
#include "oc_endpoint.h"
#include "util/oc_memb.h"
#include "port/oc_assert.h"

#ifdef OC_TCP

#define OC_TCP_LISTEN_BACKLOG 3

#define TLS_HEADER_SIZE 5

typedef struct tcp_session
{
  struct tcp_session *next;
  oc_endpoint_t endpoint;
  int sock;
} tcp_session_t;

OC_LIST(session_list);
OC_MEMB(tcp_session_s, tcp_session_t, OC_MAX_TCP_PEERS);

#ifndef DISABLE_TCP_SERVER
static int
configure_tcp_socket(int sock, void *sock_info)
{
  oc_abort(__func__);
  return 0;
}

static int
get_assigned_tcp_port(int sock, void *sock_info)
{
  oc_abort(__func__);    
  return 0;
}
#endif /* DISABLE_TCP_SERVER */

void
oc_tcp_add_socks_to_fd_set(ip_context_t *dev)
{
  oc_abort(__func__);
}

static int
add_new_session(int sock, const oc_endpoint_t *endpoint)
{
  oc_abort(__func__);
  return 0;
}

static int
accecpt_new_session(ip_context_t *dev, int fd, void *setfds,
                    oc_endpoint_t *endpoint)
{
  oc_abort(__func__);
  return 0;
}

static tcp_session_t *
find_session_by_endpoint(oc_endpoint_t *endpoint)
{
  tcp_session_t *session = oc_list_head(session_list);
  oc_abort(__func__);  
  return session;
}

static tcp_session_t *
get_ready_to_read_session(void *setfds)
{
  tcp_session_t *session = oc_list_head(session_list);
  oc_abort(__func__);
  return session;
}

static size_t
get_total_length_from_header(oc_message_t *message, oc_endpoint_t *endpoint)
{
  size_t total_length = 0;
  oc_abort(__func__);
  return total_length;
}

tcp_receive_state_t
oc_tcp_receive_message(ip_context_t *dev, void* fds, oc_message_t *message)
{
  oc_abort(__func__);
  return TCP_STATUS_RECEIVE;
}

static int
get_session_socket(oc_endpoint_t *endpoint)
{
  int sock = -1;
  oc_abort(__func__);  
  return sock;
}

static int
initiate_new_session(ip_context_t *dev, oc_endpoint_t *endpoint,
                     const void *receiver)
{
  int sock = -1;
  oc_abort(__func__);  
  return sock;
}

int
oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                   const void *receiver)
{
  oc_abort(__func__);
  return -1;
}

#ifndef DISABLE_TCP_SERVER
#ifdef OC_IPV4
static int
tcp_connectivity_ipv4_init(ip_context_t *dev)
{
  oc_abort(__func__);
  return 0;
}
#endif /* OC_IPV4 */
#endif /* DISABLE_TCP_SERVER */

int
oc_tcp_connectivity_init(ip_context_t *dev)
{
  oc_abort(__func__);
  return 0;
}

void
oc_tcp_connectivity_shutdown(ip_context_t *dev)
{
  oc_abort(__func__);
}

#endif /* OC_TCP */
