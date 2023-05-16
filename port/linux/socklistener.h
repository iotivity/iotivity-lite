/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#ifndef SOCKLISTENER_H
#define SOCKLISTENER_H

#include "util/oc_compiler.h"

#include <stdint.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_sock_listener_t
{
  int sock;
} oc_sock_listener_t;

/**
 * @brief Close socket listener
 *
 * @param server socket listener
 */
void oc_sock_listener_close(oc_sock_listener_t *server) OC_NONNULL();

/**
 * @brief Set socket listener to fd_set
 *
 * @param server socket listener
 * @param rfds set of file descriptors
 */
void oc_sock_listener_fd_set(const oc_sock_listener_t *server, fd_set *rfds)
  OC_NONNULL();

/**
 * @brief Check if socket listener is set in fd_set
 *
 * @param server socket listener
 * @param rfds set of file descriptors
 * @return true if socket listener is set in fd_set
 */
bool oc_sock_listener_fd_isset(const oc_sock_listener_t *server,
                               const fd_set *rfds) OC_NONNULL();

/**
 * @brief Get port of socket listener
 *
 * @param server socket listener
 * @return port of socket listener
 */
int oc_sock_listener_get_port(const oc_sock_listener_t *server) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* SOCKLISTENER_H */
