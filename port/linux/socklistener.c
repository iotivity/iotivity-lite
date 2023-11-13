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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "port/oc_log_internal.h"
#include "socklistener.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

void
oc_sock_listener_close(oc_sock_listener_t *server)
{
  if (server->sock >= 0) {
    close(server->sock);
  }
  server->sock = -1;
}

void
oc_sock_listener_fd_set(const oc_sock_listener_t *server, fd_set *rfds)
{
  if (server->sock >= 0) {
    FD_SET(server->sock, rfds);
  }
}

bool
oc_sock_listener_fd_isset(const oc_sock_listener_t *server, const fd_set *rfds)
{
  return (server->sock >= 0 && FD_ISSET(server->sock, rfds));
}

int
oc_sock_listener_get_port(const oc_sock_listener_t *server)
{
  if (server->sock < 0) {
    return -1;
  }
  struct sockaddr_storage sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  socklen_t socklen = sizeof(sockaddr);
  if (getsockname(server->sock, (struct sockaddr *)&sockaddr, &socklen) == -1) {
    OC_ERR("obtaining socket information %d", errno);
    return -1;
  }

  switch (sockaddr.ss_family) {
#ifdef OC_IPV4
  case AF_INET:
    return (int)ntohs(((struct sockaddr_in *)&sockaddr)->sin_port);
#endif /* OC_IPV4 */
  case AF_INET6:
    return (int)ntohs(((struct sockaddr_in6 *)&sockaddr)->sin6_port);
  default:
    return -1;
  }
}
