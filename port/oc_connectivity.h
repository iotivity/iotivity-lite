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

#ifndef OC_PORT_CONNECTIVITY_H
#define OC_PORT_CONNECTIVITY_H

#include "messaging/coap/conf.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_export.h"
#include "oc_network_events.h"
#include "oc_session_events.h"
#include "port/oc_log_internal.h"
#include "util/oc_atomic.h"
#include "util/oc_features.h"
#include "util/oc_process.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OC_DYNAMIC_ALLOCATION
#ifndef OC_MAX_APP_DATA_SIZE
#error "Set OC_MAX_APP_DATA_SIZE in oc_config.h"
#endif /* !OC_MAX_APP_DATA_SIZE */
#define OC_MIN_APP_DATA_SIZE OC_MAX_APP_DATA_SIZE

#ifdef OC_BLOCK_WISE_SET_MTU
#ifndef OC_BLOCK_WISE
#error "OC_BLOCK_WISE must be defined"
#endif /* OC_BLOCK_WISE */
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
#ifdef OC_OSCORE
  OC_PDU_SIZE = (OC_MAX_APP_DATA_SIZE + 2 * COAP_MAX_HEADER_SIZE)
#else  /* OC_OSCORE */
  OC_PDU_SIZE = (OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE)
#endif /* !OC_OSCORE */
#else  /* OC_TCP */
#ifdef OC_SECURITY
#ifdef OC_OSCORE
  OC_PDU_SIZE = (OC_BLOCK_SIZE + 2 * COAP_MAX_HEADER_SIZE)
#else  /* OC_OSCORE */
  OC_PDU_SIZE = (OC_BLOCK_SIZE + COAP_MAX_HEADER_SIZE)
#endif /* !OC_OSCORE */
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
#ifdef OC_OSCORE
#define OC_PDU_SIZE (oc_get_max_app_data_size() + 2 * COAP_MAX_HEADER_SIZE)
#else /* OC_OSCORE */
#define OC_PDU_SIZE (oc_get_max_app_data_size() + COAP_MAX_HEADER_SIZE)
#endif /* !OC_OSCORE */
#else  /* OC_TCP */
#define OC_PDU_SIZE (oc_get_mtu_size())
#endif /* !OC_TCP */
#define OC_BLOCK_SIZE (oc_get_block_size())
#define OC_MAX_APP_DATA_SIZE (oc_get_max_app_data_size())
#define OC_MIN_APP_DATA_SIZE (oc_get_min_app_data_size())
#endif /* OC_DYNAMIC_ALLOCATION */

typedef struct oc_message_s
{
  struct oc_message_s *next;
  struct oc_memb *pool;
  oc_endpoint_t endpoint;
  size_t length;
  OC_ATOMIC_UINT8_T ref_count;
#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_INOUT_BUFFER_SIZE
  uint8_t data[OC_INOUT_BUFFER_SIZE];
#else  /* OC_INOUT_BUFFER_SIZE */
  uint8_t *data;
#endif /* !OC_INOUT_BUFFER_SIZE */
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t data[OC_PDU_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */
#ifdef OC_TCP
  size_t read_offset;
#endif /* OC_TCP */
#ifdef OC_SECURITY
  uint8_t encrypted;
#endif /* OC_SECURITY */
} oc_message_t;

/**
 * @brief send buffer
 *
 * @param message message to send
 * @return int >=0 number of sent bytes
 * @return int -1 on error
 */
int oc_send_buffer(oc_message_t *message);

/**
 * @brief send discovery request
 *
 * @param message the message
 */
void oc_send_discovery_request(oc_message_t *message);

/**
 * @brief end session for the specific endpoint
 *
 * @param endpoint the endpoint to close the session for
 */
void oc_connectivity_end_session(const oc_endpoint_t *endpoint);

#ifdef OC_DNS_LOOKUP
/**
 * @brief dns look up
 *
 * @param domain the url
 * @param addr the address
 * @param flags the transport flags
 * @return int 0 = success
 */
int oc_dns_lookup(const char *domain, oc_string_t *addr, transport_flags flags);
#ifdef OC_DNS_CACHE
/**
 * @brief clear the DNS cache
 *
 */
void oc_dns_clear_cache(void);
#endif /* OC_DNS_CACHE */
#endif /* OC_DNS_LOOKUP */

/**
 * @brief retrieve list of endpoints for the device
 *
 * @param device the device index
 * @return oc_endpoint_t* list of endpoints
 */
oc_endpoint_t *oc_connectivity_get_endpoints(size_t device);

#ifdef OC_TCP
typedef enum {
  OC_TCP_SOCKET_STATE_CONNECTING = 1, // connection is waiting to be established
  OC_TCP_SOCKET_STATE_CONNECTED,      // connection was established
} oc_tcp_socket_state_t;

typedef enum {
  OC_TCP_SOCKET_ERROR = -1,               // general error
  OC_TCP_SOCKET_ERROR_NOT_CONNECTED = -2, // tcp socket is not connected
  OC_TCP_SOCKET_ERROR_TIMEOUT = -3,       // connection timed out
  OC_TCP_SOCKET_ERROR_EXISTS_CONNECTING =
    -4, // waiting connection for given address already exists
  OC_TCP_SOCKET_ERROR_EXISTS_CONNECTED =
    -5, // ongoing connection for given address already exists
} oc_tcp_socket_error_t;

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
typedef void (*on_tcp_connect_t)(const oc_endpoint_t *endpoint, int state,
                                 void *user_data);

/**
 * @brief Try to establish a TCP connection to given endpoint.
 *
 * @param endpoint endpoint to which to connect (cannot be NULL)
 * @param on_tcp_connect user function invoked after the connection is
 * asynchronously created by this call (ie. call returned value
 * OC_TCP_SOCKET_STATE_CONNECTING). Possible values of the state parameter of
 * the on_tcp_connect call:
 *   - OC_TCP_SOCKET_STATE_CONNECTED - connection to endpoint was succesfully
 * established
 *   - OC_TCP_SOCKET_ERROR_TIMEOUT - attempts to connect to endpoint timed out
 *   - OC_TCP_SOCKET_ERROR - attempts to connect to endpoint failed
 * @param on_tcp_connect_data data provided to the on_tcp_connect callback (you
 * must ensure a correct lifetime, for given address the callback will be
 * invoked just once)
 * @return OC_TCP_SOCKET_ERROR_EXISTS_CONNECTING connection waiting to be
 * established already exists
 * @return OC_TCP_SOCKET_ERROR_EXISTS_CONNECTED ongoing connection already
 * exists
 * @return OC_TCP_SOCKET_ERROR on other error
 * @return OC_TCP_SOCKET_STATE_CONNECTING connection was not established
 * immediately. Representation was created and sent to the network thread, which
 * will wait for the connection to be established or to timeout. In both cases
 * on_tcp_connect will be invoke (if it is defined) with the appropriate
 * arguments.
 * @return OC_TCP_SOCKET_STATE_CONNECTED connection for the endpoint was
 * established without delay (the on_tcp_connect and on_tcp_connect_data
 * arguments used in this invocation will be ignored)
 */
OC_API
int oc_tcp_connect(oc_endpoint_t *endpoint, on_tcp_connect_t on_tcp_connect,
                   void *on_tcp_connect_data);

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

/**
 * @brief Get state of TCP connection for given endpoint
 *
 * @param endpoint the endpoint (cannot be NULL)
 * @return OC_TCP_SOCKET_STATE_CONNECTED TCP connection exists and it is ongoing
 * @return OC_TCP_SOCKET_STATE_CONNECTING TCP connection is waiting to be
 * established
 * @return -1 otherwise
 */
OC_API
int oc_tcp_connection_state(const oc_endpoint_t *endpoint);

/**
 * @brief The CSM states
 */
typedef enum {
  CSM_NONE,       ///< None
  CSM_SENT,       ///< Send
  CSM_DONE,       ///< Done
  CSM_ERROR = 255 ///< Error
} tcp_csm_state_t;

/**
 * @brief retrieve the csm state
 *
 * @param endpoint the endpoint
 * @return tcp_csm_state_t the cms state
 */
OC_API
tcp_csm_state_t oc_tcp_get_csm_state(const oc_endpoint_t *endpoint);

/**
 * @brief update the csm state on the tcp connection
 *
 * @param endpoint the endpoint
 * @param csm the cms state
 * @return int 0 = success
 */
OC_API
int oc_tcp_update_csm_state(const oc_endpoint_t *endpoint, tcp_csm_state_t csm);
#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_CONNECTIVITY_H */
