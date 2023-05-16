/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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

#ifndef NETSOCKET_H
#define NETSOCKET_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a IPv6 UDP Datagram socket bound to all interfaces and a given
 * port.
 *
 * @param port selected port to use or 0 to let system choose a random port
 * @return >=0 on success
 * @return -1 on failure
 */
int oc_netsocket_create_ipv6(uint16_t port);

/**
 * @brief Create a IPv6 Multicast UDP Datagram socket bound to all interfaces
 * and a given port.
 *
 * @param port selected port to use or 0 to let system choose a random port
 * @return >=0 on success
 * @return -1 on failure
 */
int oc_netsocket_create_mcast_ipv6(uint16_t port);

/** Add IPv6 Multicast socket to defined CoAP IPv6 groups. */
bool oc_netsocket_add_sock_to_ipv6_mcast_group(int sock, int interface_index);

#ifdef OC_IPV4

/**
 * @brief Create a IPv4 UDP Datagram socket bound to all interfaces and a given
 * port.
 *
 * @param port selected port to use or 0 to let system choose a random port
 * @return >=0 on success
 * @return -1 on failure
 */
int oc_netsocket_create_ipv4(uint16_t port);

/**
 * @brief Create a IPv4 Multicast UDP Datagram socket bound to all interfaces
 * and a given port.
 *
 * @param port selected port to use or 0 to let system choose a random port
 * @return >=0 on success
 * @return -1 on failure
 */
int oc_netsocket_create_mcast_ipv4(uint16_t port);

/** Add IPv4 Multicast socket to a defined IPv4 group. */
bool oc_netsocket_add_sock_to_ipv4_mcast_group(int sock,
                                               const struct in_addr *local,
                                               int interface_index);

#endif /* OC_IPV4 */

#ifdef __cplusplus
}
#endif

#endif /* NETSOCKET_H */
