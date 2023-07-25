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

#ifndef OC_ENDPOINT_INTERNAL_H
#define OC_ENDPOINT_INTERNAL_H

#include "oc_endpoint.h"
#include "util/oc_compiler.h"
#include "util/oc_macros_internal.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// maximal length of a valid IPv6 address
#define OC_IPV6_MAXADDRSTRLEN (46)
// maximal length of a valid IPv4 address
#define OC_IPV4_MAXADDRSTRLEN (16)

#define OC_SCHEME_COAP "coap://"
#define OC_SCHEME_COAPS "coaps://"
#define OC_SCHEME_COAP_TCP "coap+tcp://"
#define OC_SCHEME_COAPS_TCP "coaps+tcp://"

#define OC_SCHEME_OCF "ocf://"

typedef enum {
  OC_IPV6_ADDR_SCOPE_LOCAL = 0x01,
  OC_IPV6_ADDR_SCOPE_LINK_LOCAL = 0x02,
  OC_IPV6_ADDR_SCOPE_REALM_LOCAL = 0x03,
  OC_IPV6_ADDR_SCOPE_ADMIN_LOCAL = 0x04,
  OC_IPV6_ADDR_SCOPE_SITE_LOCAL = 0x05,
  OC_IPV6_ADDR_SCOPE_ORGANIZATION_LOCAL = 0x08,
  OC_IPV6_ADDR_SCOPE_GLOBAL = 0x0e,
} oc_ipv6_addr_scope_t;

/**
 * @brief Write the scheme string (including NUL terminator) for given transport
 * flags to buffer
 *
 * @param flags transport flags of an endpoint
 * @param buffer output buffer (if NULL the function returns the number of bytes
 * that would have been written, excluding the NUL terminator)
 * @param buffer_size size of output buffer
 * @return return number of written bytes (excluding the NUL terminator)
 * @return -1 for error
 */
int oc_endpoint_flags_to_scheme(unsigned flags, char *buffer,
                                size_t buffer_size);

/**
 * @brief Convert the endpoint to a human readable string (e.g.
 * "[fe::22]:1234")
 *
 * @param endpoint the endpoint (cannot be NULL)
 * @param buffer output buffer (cannot be NULL)
 * @param buffer_size size of output buffer
 * @return number of written bytes, -1 for error
 */
int oc_endpoint_address_and_port_to_cstring(const oc_endpoint_t *endpoint,
                                            char *buffer, size_t buffer_size)
  OC_NONNULL();

/** @brief Get host of the endpoint as string */
int oc_endpoint_host(const oc_endpoint_t *endpoint, char *buffer,
                     size_t buffer_size) OC_NONNULL();

/** @brief Get port of the endpoint */
int oc_endpoint_port(const oc_endpoint_t *endpoint) OC_NONNULL();

/** @brief Check for multicast endpoint
 *
 * @param endpoint endpoint to check
 * @return true if endpoint is non-NULL and has the MULTICAST flag set
 * @return false otherwise
 */
bool oc_endpoint_is_multicast(const oc_endpoint_t *endpoint);

/** @brief Check for unicast endpoint
 *
 * @param endpoint endpoint to check
 * @return true if endpoint is non-NULL and does not have the MULTICAST flag set
 * @return false otherwise
 */
bool oc_endpoint_is_unicast(const oc_endpoint_t *endpoint);

typedef struct oc_string64_s
{
  size_t size;
  char ptr[64];
} oc_string64_t;

#define oc_string64_cap(ocstring)                                              \
  (OC_ARRAY_SIZE((ocstring).ptr) - (ocstring).size)

/**
 * @brief convert the endpoint to a human readable string (e.g.
 * "coaps://[fe::22]:1234").
 *
 * @param endpoint the endpoint
 * @param endpoint_str endpoint as human readable string
 * @return true for success
 */
bool oc_endpoint_to_string64(const oc_endpoint_t *endpoint,
                             oc_string64_t *endpoint_str);

#ifdef __cplusplus
}
#endif

#endif /* OC_ENDPOINT_INTERNAL_H */
