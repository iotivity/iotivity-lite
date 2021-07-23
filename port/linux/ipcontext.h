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

#include "oc_endpoint.h"
#include <pthread.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
  ADAPTER_STATUS_NONE = 0, /* Nothing happens */
  ADAPTER_STATUS_ACCEPT,   /* Receiving no meaningful data */
  ADAPTER_STATUS_RECEIVE,  /* Receiving meaningful data */
  ADAPTER_STATUS_ERROR     /* Error */
} adapter_receive_state_t;

#ifdef OC_TCP
typedef struct tcp_context_t
{
  struct sockaddr_storage server;
  int server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  struct sockaddr_storage secure;
  int secure_sock;
  uint16_t tls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  struct sockaddr_storage server4;
  int server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  struct sockaddr_storage secure4;
  int secure4_sock;
  uint16_t tls4_port;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  int connect_pipe[2];
} tcp_context_t;
#endif

typedef struct ip_context_t {
  struct ip_context_t *next;
  OC_LIST_STRUCT(eps);
  struct sockaddr_storage mcast;
  struct sockaddr_storage server;
  int mcast_sock;
  int server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  struct sockaddr_storage secure;
  int secure_sock;
  uint16_t dtls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  struct sockaddr_storage mcast4;
  struct sockaddr_storage server4;
  int mcast4_sock;
  int server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  struct sockaddr_storage secure4;
  int secure4_sock;
  uint16_t dtls4_port;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#ifdef OC_TCP
  tcp_context_t tcp;
#endif
  pthread_t event_thread;
  int terminate;
  size_t device;
  pthread_mutex_t rfds_mutex;
  fd_set rfds;
  int shutdown_pipe[2];
} ip_context_t;

/** 
 * Set a given file descriptor to a set (dev->rfds) under the mutex(rfds_mutex). 
 *
 * @param[in] dev the device network context.
 * @param[in] sockfd the file descriptor.
 */
void ip_context_rfds_fd_set(ip_context_t* dev,int sockfd);

/**
 * Remove a given file descriptor from a set (dev->rfds) under the mutex(rfds_mutex).
 *
 * @param[in] dev the device network context.
 * @param[in] sockfd the file descriptor.
 */
void ip_context_rfds_fd_clr(ip_context_t* dev, int sockfd);

/**
 * Make a copy of file descriptor set (dev->rfds) under the mutex(rfds_mutex). 
 * 
 * @param[in] dev the device network context.
 * 
 * @return a copy of file descriptor set.
 */
fd_set ip_context_rfds_fd_copy(ip_context_t* dev);

#ifdef __cplusplus
}
#endif

#endif /* IPCONTEXT_H */
