/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef IPADAPTER_H
#define IPADAPTER_H

#include "ipcontext.h"
#include "oc_endpoint.h"
#include <sys/socket.h>

/**
 * @brief Add or remove file descriptor flags.
 *
 * Functions gets the current file descriptor flags, removes the to_remove
 * flags, then adds the to_add flags and updates the file descriptor flags with
 * this new value.
 *
 * @param sockfd file descriptor
 * @param to_add flags to be added
 * @param to_remove flags to be removed
 * @return >0 on success, the current file descriptor flags
 * @return -1 on failure
 */
int oc_set_fd_flags(int sockfd, int to_add, int to_remove);

/**
 * @brief Extract socket address from the endpoint.
 *
 * @param[in] endpoint endpoint with address
 * @param[out] addr ipv4 or ipv6 address extracted from the endpoint
 * @return true on success
 * @return false on failure
 */
bool oc_get_socket_address(const oc_endpoint_t *endpoint,
                           struct sockaddr_storage *addr);

/**
 * @brief Get ip context for device.
 */
ip_context_t *oc_get_ip_context_for_device(size_t device);

#endif /* IPADAPTER_H */
