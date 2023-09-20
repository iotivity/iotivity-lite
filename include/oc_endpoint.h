/****************************************************************************
 *
 * Copyright (c) 2017-2020 Intel Corporation
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
  @file
*/
#ifndef OC_ENDPOINT_H
#define OC_ENDPOINT_H

#include "oc_export.h"
#include "oc_helpers.h"
#include "oc_uuid.h"
#ifdef OC_OSCORE
#include "messaging/coap/oscore_constants.h"
#endif /* OC_OSCORE */
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OCF_VER_1_0_0 = 2048, OIC_VER_1_1_0 = 2112 } ocf_version_t;

/**
 * @brief ipv6 data structure
 *
 */
typedef struct
{
  uint16_t port;       ///< port number
  uint8_t address[16]; ///< address
  uint8_t scope;       ///< scope of the address (multicast)
} oc_ipv6_addr_t;

/**
 * @brief ipv4 data structure
 *
 */
typedef struct
{
  uint16_t port;      ///< port
  uint8_t address[4]; ///< address
} oc_ipv4_addr_t;

/**
 * @brief ble address data structure
 *
 */
typedef struct
{
  uint8_t type;       ///< type of address
  uint8_t address[6]; ///< ble address
} oc_le_addr_t;

/**
 * @brief transport flags (bit map)
 *
 */
typedef enum transport_flags {
  DISCOVERY = 1 << 0, ///< used for discovery
  SECURED = 1 << 1,   ///< secure communication
  IPV4 = 1 << 2,      ///< ipv4 communication
  IPV6 = 1 << 3,      ///< ipv6 communication
  TCP = 1 << 4,       ///< tcp communication
  GATT = 1 << 5,      ///< BLE GATT communication
  MULTICAST = 1 << 6, ///< multicast enabled
  ACCEPTED = 1 << 7   ///< accepted
} transport_flags;

/**
 * @brief the endpoint information
 *
 */
typedef struct oc_endpoint_t
{
  struct oc_endpoint_t *next; ///< pointer to the next structure
  size_t device;              ///< device index
  transport_flags flags;      ///< the transport flags
  oc_uuid_t di;               ///< device di
  union dev_addr {
    oc_ipv6_addr_t ipv6; ///< ipv6 address
    oc_ipv4_addr_t ipv4; ///< ipv4 address
    oc_le_addr_t bt;     ///< blue tooth address
  } addr, addr_local;
  unsigned interface_index; ///< interface index (valid intefaces are >0, 0
                            ///< means no index or error)
  uint8_t priority;         ///< priority
  ocf_version_t version;    ///< ocf version
#ifdef OC_OSCORE
  uint8_t piv[OSCORE_PIV_LEN];
  uint8_t piv_len;
#endif /* OC_OSCORE */
} oc_endpoint_t;

#define oc_make_ipv4_endpoint(__name__, __flags__, __port__, ...)              \
  oc_endpoint_t __name__ = { .flags = __flags__,                               \
                             .addr.ipv4 = { .port = __port__,                  \
                                            .address = { __VA_ARGS__ } } }
#define oc_make_ipv6_endpoint(__name__, __flags__, __port__, ...)              \
  oc_endpoint_t __name__ = { .flags = __flags__,                               \
                             .addr.ipv6 = { .port = __port__,                  \
                                            .address = { __VA_ARGS__ } } }

/**
 * @brief create new endpoint
 *
 * @return oc_endpoint_t* created new endpoint
 */
OC_API
oc_endpoint_t *oc_new_endpoint(void);

/**
 * @brief free endpoint
 *
 * @param endpoint endpoint to be freed
 */
OC_API
void oc_free_endpoint(oc_endpoint_t *endpoint);

/**
 * @brief set device identifier (di) for the endpoint
 *
 * @param endpoint endpoint (cannot be NULL)
 * @param di device identifier (cannot be NULL)
 */
OC_API
void oc_endpoint_set_di(oc_endpoint_t *endpoint, const oc_uuid_t *di)
  OC_NONNULL();

/**
 * @brief convert the endpoint to a human readable string (e.g.
 * "coaps://[fe::22]:1234")
 *
 * @param endpoint the endpoint
 * @param endpoint_str endpoint as human readable string
 * @return int 0 success
 */
OC_API
int oc_endpoint_to_string(const oc_endpoint_t *endpoint,
                          oc_string_t *endpoint_str);

/**
 * @brief convert the endpoint to a human readable string (e.g.
 * "coaps://[fe::22]:1234")
 *
 * @param endpoint the endpoint (cannot be NULL)
 * @param buffer output buffer (cannot be NULL)
 * @param buffer_size size of output buffer
 * @return number of written bytes, -1 for error
 */
OC_API
int oc_endpoint_to_cstring(const oc_endpoint_t *endpoint, char *buffer,
                           size_t buffer_size) OC_NONNULL();

/**
 * @brief string to endpoint
 *
 * @param endpoint_str the endpoint as string (e.g. "coaps://[fe::22]:/blah")
 * @param endpoint the address part of the string
 * @param uri the uri part of the endpoint
 * @return int 0 success
 */
OC_API
int oc_string_to_endpoint(const oc_string_t *endpoint_str,
                          oc_endpoint_t *endpoint, oc_string_t *uri);

/**
 * @brief parse path component (ie. the part after the first '/') of a uri
 *
 * @param endpoint_str uri to parse
 * @param[out] path output variable
 * @return 0 on success
 * @return -1 on failure
 */
OC_API
int oc_endpoint_string_parse_path(const oc_string_t *endpoint_str,
                                  oc_string_t *path);

/**
 * @brief is endpoint (ipv6) link local
 *
 * @param endpoint the endpoint to check
 * @return int 0 = endpoint is link local
 */
OC_API
int oc_ipv6_endpoint_is_link_local(const oc_endpoint_t *endpoint);

/**
 * @brief compare endpoint
 *
 * @param ep1 endpoint 1 to compare
 * @param ep2 endpoint 2 to compare
 * @return int 0 = equal
 */
OC_API
int oc_endpoint_compare(const oc_endpoint_t *ep1, const oc_endpoint_t *ep2);

/**
 * @brief compare address of the endpoint
 *
 * @param ep1 endpoint 1 to compare
 * @param ep2 endpoint 2 to compare
 * @return int 0 = equal
 */
OC_API
int oc_endpoint_compare_address(const oc_endpoint_t *ep1,
                                const oc_endpoint_t *ep2);

/**
 * @brief check if all fields of the endpoint struct are empty
 *
 * @param endpoint endpoint to check (cannot be NULL)
 * @return true all fields of the endpoint are empty
 * @return false otherwise
 */
OC_API
bool oc_endpoint_is_empty(const oc_endpoint_t *endpoint) OC_NONNULL();

/**
 * @brief set local address on endpoint from the first device endpoint with
 * matching flags and interface index
 *
 * @param[in,out] ep the endpoint (cannot be NULL)
 * @param interface_index the interface index
 */
OC_API
void oc_endpoint_set_local_address(oc_endpoint_t *ep, unsigned interface_index)
  OC_NONNULL();

/**
 * @brief copy endpoint
 *
 * @param dst destination endpoint (cannot be NULL)
 * @param src source endpoint (cannot be NULL)
 */
OC_API
void oc_endpoint_copy(oc_endpoint_t *dst, const oc_endpoint_t *src)
  OC_NONNULL();

/**
 * @brief copy list of endpoints
 *
 * @param dst destination list of endpoints (cannot be NULL)
 * @param src source list of endpoints
 *
 * @return 0 on success
 * @return -1 on failure
 */
OC_API
int oc_endpoint_list_copy(oc_endpoint_t **dst, const oc_endpoint_t *src)
  OC_NONNULL(1);

/**
 * @brief deallocate a linked list of endpoints
 *
 * @param eps linked list to deallocate
 */
OC_API
void oc_endpoint_list_free(oc_endpoint_t *eps);

#ifdef __cplusplus
}
#endif

#endif /* OC_ENDPOINT_H */
