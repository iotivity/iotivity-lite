/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

#ifndef TCP_ADAPTER_H
#define TCP_ADAPTER_H

#include "ipcontext.h"
#include "tcpcontext.h"

#ifdef OC_TCP

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize all TCP members of the device network context.
 *
 * @param dev the device network context (cannot be NULL)
 * @return 0 on success
 * @return -1 on error
 */
int tcp_connectivity_init(ip_context_t *dev);

/**
 * @brief Deinitialize all TCP members of the device network context.
 *
 * @param dev the device network context (cannot be NULL)
 */
void tcp_connectivity_shutdown(ip_context_t *dev);

/**
 * @brief Add all TCP sockets and signal pipe to read fd set.
 *
 * @param dev the device network context (cannot be NULL)
 */
void tcp_add_socks_to_rfd_set(ip_context_t *dev);

/**
 * @brief Handle data available on the signal pipe (dev->connect_pipe).
 *
 * @param dev the device network context (cannot be NULL)
 * @return ADAPTER_STATUS_ERROR on read error
 * @return ADAPTER_STATUS_RECEIVE on success
 */
adapter_receive_state_t tcp_receive_signal(const tcp_context_t *dev);

#ifdef __cplusplus
}
#endif

#endif /* OC_TCP */

#endif /* TCP_ADAPTER_H */
