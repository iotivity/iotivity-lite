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
/**
  @file
*/
#ifndef OC_CONNECTIVITY_H
#define OC_CONNECTIVITY_H

#include "messaging/coap/conf.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_network_events.h"
#include "oc_session_events.h"
#include "port/oc_log.h"
#include "util/oc_process.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OC_DYNAMIC_ALLOCATION
#ifndef OC_MAX_APP_DATA_SIZE
#error "Set OC_MAX_APP_DATA_SIZE in oc_config.h"
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

enum {
#ifdef OC_TCP // TODO: need to check about tls packet.
  OC_PDU_SIZE = (OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE)
#else /* OC_TCP */
#ifdef OC_SECURITY
  OC_PDU_SIZE = (2 * OC_BLOCK_SIZE + COAP_MAX_HEADER_SIZE)
#else  /* OC_SECURITY */
  OC_PDU_SIZE = (OC_BLOCK_SIZE + COAP_MAX_HEADER_SIZE)
#endif /* !OC_SECURITY */
#endif /* !OC_TCP */
};
#else /* !OC_DYNAMIC_ALLOCATION */
#ifdef __cplusplus
}
#endif
#include "oc_buffer_settings.h"
#ifdef __cplusplus
extern "C" {
#endif
#ifdef OC_TCP
#define OC_PDU_SIZE (oc_get_max_app_data_size() + COAP_MAX_HEADER_SIZE)
#else /* OC_TCP */
#define OC_PDU_SIZE (oc_get_mtu_size())
#endif /* !OC_TCP */
#define OC_BLOCK_SIZE (oc_get_block_size())
#define OC_MAX_APP_DATA_SIZE (oc_get_max_app_data_size())
#endif /* OC_DYNAMIC_ALLOCATION */

struct oc_message_s
{
  struct oc_message_s *next;
  struct oc_memb *pool;
  oc_endpoint_t endpoint;
  size_t length;
  uint8_t ref_count;
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *data;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t data[OC_PDU_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */
#ifdef OC_TCP
  size_t read_offset;
#endif /* OC_TCP */
#ifdef OC_SECURITY
  uint8_t encrypted;
#endif
};

int oc_send_buffer(oc_message_t *message);

int oc_connectivity_init(size_t device);

void oc_connectivity_shutdown(size_t device);

void oc_send_discovery_request(oc_message_t *message);

void oc_connectivity_end_session(oc_endpoint_t *endpoint);

#ifdef OC_DNS_LOOKUP
int oc_dns_lookup(const char *domain, oc_string_t *addr,
                  enum transport_flags flags);
#ifdef OC_DNS_CACHE
void oc_dns_clear_cache(void);
#endif /* OC_DNS_CACHE */
#endif /* OC_DNS_LOOKUP */

oc_endpoint_t *oc_connectivity_get_endpoints(size_t device);

void handle_network_interface_event_callback(oc_interface_event_t event);

void handle_session_event_callback(const oc_endpoint_t *endpoint,
                                   oc_session_state_t state);

#ifdef OC_TCP
/* TCP CSM states */
typedef enum { CSM_NONE, CSM_SENT, CSM_DONE, CSM_ERROR = 255 } tcp_csm_state_t;

tcp_csm_state_t oc_tcp_get_csm_state(oc_endpoint_t *endpoint);
int oc_tcp_update_csm_state(oc_endpoint_t *endpoint, tcp_csm_state_t csm);
#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* OC_CONNECTIVITY_H */
