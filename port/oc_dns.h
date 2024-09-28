/****************************************************************************
 *
 * Copyright (c) 2016, 2018, 2020 Intel Corporation
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

/**
 * @file
 */

#ifndef OC_PORT_DNS_H
#define OC_PORT_DNS_H

#include "oc_endpoint.h"
#include "oc_export.h"
#include "oc_helpers.h"
#include "util/oc_features.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OC_DNS_LOOKUP

/**
 * @brief dns look up
 *
 * @param domain the url
 * @param addr the address
 * @param flags the transport flags
 * @return int 0 = success
 */
OC_API
int oc_dns_lookup(const char *domain, oc_string_t *addr, transport_flags flags);

#ifdef OC_DNS_CACHE

/**
 * @brief clear the DNS cache
 */
OC_API
void oc_dns_clear_cache(void);

#endif /* OC_DNS_CACHE */

#endif /* OC_DNS_LOOKUP */

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_DNS_H */
