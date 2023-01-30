/****************************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#ifndef TCPCONTEXT_H
#define TCPCONTEXT_H

#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <stdint.h>

#ifdef OC_TCP

#ifdef __cplusplus
extern "C" {
#endif

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
  pthread_mutex_t cfds_mutex;
  fd_set cfds; //< set of tcp sockets waiting for connection
} tcp_context_t;

/**
 * Set a given file descriptor to a set of descriptors waiting for connect
 * (dev->cfds) under the mutex(cfds_mutex).
 *
 * @param[in] dev the device tcp context.
 * @param[in] sockfd the file descriptor.
 */
void tcp_context_cfds_fd_set(tcp_context_t *dev, int sockfd);

/**
 * Remove a given file descriptor from a set (dev->cfds) under the
 * mutex(cfds_mutex).
 *
 * @param[in] dev the device tcp context.
 * @param[in] sockfd the file descriptor.
 */
void tcp_context_cfds_fd_clr(tcp_context_t *dev, int sockfd);

/**
 * Make a copy of file descriptor set (dev->cfds) under the mutex(cfds_mutex).
 *
 * @param[in] dev the device tcp context.
 *
 * @return a copy of file descriptor set.
 */
fd_set tcp_context_cfds_fd_copy(tcp_context_t *dev);

#ifdef __cplusplus
}
#endif

#endif /* OC_TCP */

#endif /* TCPCONTEXT_H */
