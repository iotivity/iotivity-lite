/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
#include "socklistener.h"
#include "util/oc_atomic.h"
#ifdef OC_TCP
#include "tcpcontext.h"
#endif /* OC_TCP */
#include <pthread.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ADAPTER_STATUS_NONE = 0, /* Nothing happens */
  ADAPTER_STATUS_ACCEPT,   /* Receiving no meaningful data */
  ADAPTER_STATUS_RECEIVE,  /* Receiving meaningful data */
  ADAPTER_STATUS_ERROR     /* Error */
} adapter_receive_state_t;

typedef enum {
  IP_CONTEXT_FLAG_REFRESH_ENDPOINT_LIST =
    1 << 0, ///< used to signal that endpoint list needs to be refreshed
} ip_context_flags_t;

typedef struct ip_context_t
{
  struct ip_context_t *next;
  OC_LIST_STRUCT(eps); /// < not thread-safe, must be used only from main thread
  int mcast_sock;
  oc_sock_listener_t server;
#ifdef OC_SECURITY
  oc_sock_listener_t secure;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  int mcast4_sock;
  oc_sock_listener_t server4;
#ifdef OC_SECURITY
  oc_sock_listener_t secure4;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#ifdef OC_TCP
  tcp_context_t tcp;
#endif /* OC_TCP */
  pthread_t event_thread;
  OC_ATOMIC_INT8_T terminate;
  size_t device;
  pthread_mutex_t rfds_mutex;
  fd_set rfds;
  int wakeup_pipe[2];
  OC_ATOMIC_INT8_T flags;
} ip_context_t;

/**
 * Set a given file descriptor to a set of read descriptors (dev->rfds) under
 * the mutex(rfds_mutex).
 *
 * @param[in] dev the device network context.
 * @param[in] sockfd the file descriptor.
 */
void ip_context_rfds_fd_set(ip_context_t *dev, int sockfd);

/**
 * Remove a given file descriptor from a set (dev->rfds) under the
 * mutex(rfds_mutex).
 *
 * @param[in] dev the device network context.
 * @param[in] sockfd the file descriptor.
 */
void ip_context_rfds_fd_clr(ip_context_t *dev, int sockfd);

/**
 * Make a copy of file descriptor set (dev->rfds) under the mutex(rfds_mutex).
 *
 * @param[in] dev the device network context.
 *
 * @return a copy of file descriptor set.
 */
fd_set ip_context_rfds_fd_copy(ip_context_t *dev);

#ifdef __cplusplus
}
#endif

#endif /* IPCONTEXT_H */
