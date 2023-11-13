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

#include "port/common/posix/oc_socket_internal.h"

#include <assert.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <ws2tcpip.h>
#else /* !_WIN32 */
#include <netinet/in.h>
#endif /* _WIN32 */

struct sockaddr_storage
oc_socket_get_address(const oc_endpoint_t *endpoint)
{
  assert(endpoint != NULL);

  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));

#ifdef OC_IPV4
  if ((endpoint->flags & IPV4) != 0) {
    struct sockaddr_in *r = (struct sockaddr_in *)&addr;
    memcpy(&r->sin_addr.s_addr, endpoint->addr.ipv4.address,
           sizeof(r->sin_addr.s_addr));
    r->sin_family = AF_INET;
    r->sin_port = htons(endpoint->addr.ipv4.port);
    return addr;
  }
#endif /* OC_IPV4 */
  struct sockaddr_in6 *r = (struct sockaddr_in6 *)&addr;
  memcpy(r->sin6_addr.s6_addr, endpoint->addr.ipv6.address,
         sizeof(r->sin6_addr.s6_addr));
  r->sin6_family = AF_INET6;
  r->sin6_port = htons(endpoint->addr.ipv6.port);
  r->sin6_scope_id = endpoint->addr.ipv6.scope;
  return addr;
}
