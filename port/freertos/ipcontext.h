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

#ifndef IPCONTEXT_H
#define IPCONTEXT_H

#include <stddef.h>
#include <stdint.h>

#ifdef OC_TCP
typedef struct tcp_context_t {
  void* server;
  int server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  void* secure;
  int secure_sock;
  uint16_t tls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  void* server4;
  int server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  void* secure4;
  int secure4_sock;
  uint16_t tls4_port;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  int connect_pipe[2];
} tcp_context_t;
#endif

typedef struct ip_context_t {
  struct ip_context_t *next;
  int mcast_sock;
  int server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  void* secure;
  int secure_sock;
  uint16_t dtls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  void* mcast4;
  void* server4;
  int mcast4_sock;
  int server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  void* secure4;
  int secure4_sock;
  uint16_t dtls4_port;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#ifdef OC_TCP
  tcp_context_t tcp;
#endif
  int terminate;
  size_t device;
  int shutdown_pipe[2];
} ip_context_t;

#endif /* IPCONTEXT_H */
