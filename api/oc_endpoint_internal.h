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

/**
 * @brief Get scheme string for transport flags
 *
 * @param flags type of endpoint
 * @param buf to store the scheme
 * @param buf_len length of the buffer and will be set to the length of the
 * used/needed buffer.
 * @return return number of written bytes. -1 for error
 */
int oc_endpoint_flags_to_scheme(unsigned flags, char *buf, size_t buf_len);

/**
 * @brief Convert the endpoint to a human readable string (e.g.
 * "[fe::22]:1234")
 *
 * @param endpoint the endpoint
 * @param buffer output buffer
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
OC_API
bool oc_endpoint_to_string64(const oc_endpoint_t *endpoint,
                             oc_string64_t *endpoint_str);

#ifdef __cplusplus
}
#endif

#endif /* OC_ENDPOINT_INTERNAL_H */
