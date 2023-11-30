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

#include "oc_endpoint.h"
#include "port/oc_ip_internal.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#endif /* _WIN32 */

#if defined(__unix__) || defined(__linux__) || defined(__ANDROID__)
#include <arpa/inet.h>
#endif /* __unix__ || __linux__ || __ANDROID__ */

#ifdef ESP_PLATFORM
#include <lwip/sockets.h>
#endif /* ESP_PLATFORM */

#include <assert.h>
#include <string.h>
#include <stdio.h>

int
oc_ipv6_address_to_string(const oc_ipv6_addr_t *ipv6, char *buffer,
                          size_t buffer_size)
{
  assert(ipv6 != NULL);
  assert(buffer != NULL);

  if (inet_ntop(AF_INET6, ipv6->address, buffer, (socklen_t)buffer_size) ==
      NULL) {
    return -1;
  }
  // safe: maximal IPv6 length is 45
  return (int)strlen(buffer);
}

int
oc_ipv6_address_and_port_to_string(const oc_ipv6_addr_t *ipv6, char *buffer,
                                   size_t buffer_size)
{
  assert(ipv6 != NULL);
  assert(buffer != NULL);
  // shortest valid IPv6 address with a port
  if (buffer_size < sizeof("[::1]:X")) {
    return -1;
  }
  size_t start = 0;
  buffer[start++] = '[';
  int written =
    oc_ipv6_address_to_string(ipv6, &buffer[start], buffer_size - start);
  if (written < 0) {
    return -1;
  }
  start += (size_t)written;
  size_t remaining_space = buffer_size - start;
  written = snprintf(&buffer[start], remaining_space, "]:%u", ipv6->port);
  if (written < 0 || (size_t)written >= remaining_space) {
    return -1;
  }
  return (int)(start + written);
}

#ifdef OC_IPV4

int
oc_ipv4_address_to_string(const oc_ipv4_addr_t *ipv4, char *buffer,
                          size_t buffer_size)
{
  assert(buffer != NULL);

  const uint8_t *addr = ipv4->address;
  int written = snprintf(buffer, buffer_size, "%u.%u.%u.%u", addr[0], addr[1],
                         addr[2], addr[3]);
  if ((written < 0) || (size_t)written >= buffer_size) {
    return -1;
  }
  return written;
}

int
oc_ipv4_address_and_port_to_string(const oc_ipv4_addr_t *ipv4, char *buffer,
                                   size_t buffer_size)
{
  assert(ipv4 != NULL);
  assert(buffer != NULL);

  int written = oc_ipv4_address_to_string(ipv4, buffer, buffer_size);
  if (written < 0) {
    return -1;
  }
  int ret = written;

  buffer_size -= written;
  written = snprintf(&buffer[written], buffer_size, ":%u", ipv4->port);
  if ((written < 0) || (size_t)written >= buffer_size) {
    return -1;
  }
  return ret + written;
}

#endif /* OC_IPV4 */
