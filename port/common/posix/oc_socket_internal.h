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

#ifndef PORT_POSIX_OC_SOCKET_INTERNAL_H
#define PORT_POSIX_OC_SOCKET_INTERNAL_H

#include "oc_endpoint.h"
#include "util/oc_compiler.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#else /* !_WIN32 */
#include <sys/socket.h>
#endif /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Extract socket address from the endpoint.
 *
 * @param endpoint endpoint with address (cannot be NULL)
 * @return IPv4 or IPv6 address extracted from the endpoint (cannot be NULL)
 */
struct sockaddr_storage oc_socket_get_address(const oc_endpoint_t *endpoint)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PORT_POSIX_OC_SOCKET_INTERNAL_H */
