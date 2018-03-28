/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_CONNECTIVITY_H
#define OC_CONNECTIVITY_H

#include "config.h"
#include "messaging/coap/conf.h"
#include "oc_network_events.h"
#include "port/oc_log.h"
#include "util/oc_process.h"
#include <stdint.h>

#ifndef OC_DYNAMIC_ALLOCATION
#ifndef OC_MAX_APP_DATA_SIZE
#error "Set OC_MAX_APP_DATA_SIZE in config.h"
#endif /* !OC_MAX_APP_DATA_SIZE */

#ifdef OC_BLOCK_WISE_SET_MTU
#define OC_BLOCK_WISE
#if OC_BLOCK_WISE_SET_MTU < (COAP_MAX_HEADER_SIZE + 16)
#error "OC_BLOCK_WISE_SET_MTU must be >= (COAP_MAX_HEADER_SIZE + 2^4)"
#endif /* OC_BLOCK_WISE_SET_MTU is too small */
#define OC_MAX_BLOCK_SIZE (OC_BLOCK_WISE_SET_MTU - COAP_MAX_HEADER_SIZE)
#define OC_BLOCK_SIZE                                                          \
  (OC_MAX_BLOCK_SIZE < 32                                                      \
     ? 16                                                                      \
     : (OC_MAX_BLOCK_SIZE < 64                                                 \
          ? 32                                                                 \
          : (OC_MAX_BLOCK_SIZE < 128                                           \
               ? 64                                                            \
               : (OC_MAX_BLOCK_SIZE < 256                                      \
                    ? 128                                                      \
                    : (OC_MAX_BLOCK_SIZE < 512                                 \
                         ? 256                                                 \
                         : (OC_MAX_BLOCK_SIZE < 1024                           \
                              ? 512                                            \
                              : (OC_MAX_BLOCK_SIZE < 2048 ? 1024 : 2048)))))))
#else /* OC_BLOCK_WISE_SET_MTU */
#define OC_BLOCK_SIZE (OC_MAX_APP_DATA_SIZE)
#endif /* !OC_BLOCK_WISE_SET_MTU */

enum
{
#ifdef OC_SECURITY
  OC_PDU_SIZE = (2 * OC_BLOCK_SIZE + COAP_MAX_HEADER_SIZE)
#else  /* OC_SECURITY */
  OC_PDU_SIZE = (OC_BLOCK_SIZE + COAP_MAX_HEADER_SIZE)
#endif /* !OC_SECURITY */
};
#else /* !OC_DYNAMIC_ALLOCATION */
#include "oc_buffer_settings.h"
#define OC_PDU_SIZE (oc_get_mtu_size())
#define OC_BLOCK_SIZE (oc_get_block_size())
#define OC_MAX_APP_DATA_SIZE (oc_get_max_app_data_size())
#endif /* OC_DYNAMIC_ALLOCATION */

typedef struct
{
  uint16_t port;
  uint8_t address[16];
  uint8_t scope;
} oc_ipv6_addr_t;

typedef struct
{
  uint16_t port;
  uint8_t address[4];
} oc_ipv4_addr_t;

typedef struct
{
  uint8_t type;
  uint8_t address[6];
} oc_le_addr_t;

typedef struct oc_endpoint_t
{
  struct oc_endpoint_t *next;
  int device;
  enum transport_flags
  {
    DISCOVERY = 1 << 0,
    SECURED = 1 << 1,
    IPV4 = 1 << 2,
    IPV6 = 1 << 3,
    TCP = 1 << 4,
    GATT = 1 << 5,
    MULTICAST = 1 << 6
  } flags;

  union dev_addr
  {
    oc_ipv6_addr_t ipv6;
    oc_ipv4_addr_t ipv4;
    oc_le_addr_t bt;
  } addr;
  uint8_t priority;
  ocf_version_t version;
} oc_endpoint_t;

#define oc_make_ipv4_endpoint(__name__, __flags__, __port__, ...)              \
  oc_endpoint_t __name__ = {.flags = __flags__,                                \
                            .addr.ipv4 = {.port = __port__,                    \
                                          .address = { __VA_ARGS__ } } }
#define oc_make_ipv6_endpoint(__name__, __flags__, __port__, ...)              \
  oc_endpoint_t __name__ = {.flags = __flags__,                                \
                            .addr.ipv6 = {.port = __port__,                    \
                                          .address = { __VA_ARGS__ } } }

struct oc_message_s
{
  struct oc_message_s *next;
  oc_endpoint_t endpoint;
  size_t length;
  uint8_t ref_count;
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *data;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t data[OC_PDU_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */
};

void oc_send_buffer(oc_message_t *message);

int oc_connectivity_init(int device);

void oc_connectivity_shutdown(int device);

void oc_send_discovery_request(oc_message_t *message);

oc_endpoint_t *oc_connectivity_get_endpoints(int device);

#endif /* OC_CONNECTIVITY_H */
