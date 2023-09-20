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

#ifndef PORT_COMMON_OC_IP_H
#define PORT_COMMON_OC_IP_H

#include "oc_endpoint.h"

#include "util/oc_compiler.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Convert an IPv6 address to a human readable string */
int oc_ipv6_address_to_string(const oc_ipv6_addr_t *ipv6, char *buffer,
                              size_t buffer_size) OC_NONNULL();

/** Convert an IPv6 address with port to a human readable string */
int oc_ipv6_address_and_port_to_string(const oc_ipv6_addr_t *ipv6, char *buffer,
                                       size_t buffer_size) OC_NONNULL();

#ifdef OC_IPV4

/** @brief Convert an IPv4 address to a human readable string */
int oc_ipv4_address_to_string(const oc_ipv4_addr_t *ipv4, char *buffer,
                              size_t buffer_size) OC_NONNULL();

/** Convert an IPv4 address with port to a human readable string */
int oc_ipv4_address_and_port_to_string(const oc_ipv4_addr_t *ipv4, char *buffer,
                                       size_t buffer_size) OC_NONNULL();

#endif /* OC_IPV4 */

#ifdef __cplusplus
}
#endif

#endif /* PORT_COMMON_OC_IP_H */
