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

#include <stdint.h>

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

/** @brief Get scheme string for transport flags */
const char *oc_endpoint_flags_to_scheme(unsigned flags) OC_RETURNS_NONNULL;

/**
 * @brief Convert the endpoint to a human readable string (e.g.
 * "coaps://[fe::22]:/")
 *
 * @param endpoint the endpoint
 * @param buffer output buffer
 * @param buffer_size size of output buffer
 * @return int 0 success
 */
int oc_endpoint_to_cstring(const oc_endpoint_t *endpoint, char *buffer,
                           uint32_t buffer_size) OC_NONNULL();

/** @brief Get host of the endpoint as string */
int oc_endpoint_host(const oc_endpoint_t *endpoint, char *buffer,
                     uint32_t buffer_size) OC_NONNULL();

/** @brief Get port of the endpoint */
int oc_endpoint_port(const oc_endpoint_t *endpoint) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_ENDPOINT_INTERNAL_H */
