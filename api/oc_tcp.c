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

#include "util/oc_features.h"

#ifdef OC_TCP
#include <assert.h>
#include "messaging/coap/coap_internal.h"
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include "oc_tcp_internal.h"
#include "util/oc_atomic.h"
#ifdef OC_SECURITY
#include <mbedtls/ssl.h>
#ifdef OC_OSCORE
#include "messaging/coap/oscore_internal.h"
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

#include "port/oc_allocator_internal.h"
#include "util/oc_memb.h"

OC_MEMB(g_oc_tcp_on_connect_event_s, oc_tcp_on_connect_event_t,
        OC_MAX_TCP_PEERS); ///< guarded by oc_network_event_handler_mutex

static oc_tcp_on_connect_event_t *
oc_tcp_on_connect_event_allocate(void)
{
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_lock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_tcp_on_connect_event_t *event =
    (oc_tcp_on_connect_event_t *)oc_memb_alloc(&g_oc_tcp_on_connect_event_s);
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_unlock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  return event;
}

oc_tcp_on_connect_event_t *
oc_tcp_on_connect_event_create(const oc_endpoint_t *endpoint, int state,
                               on_tcp_connect_t fn, void *fn_data)
{
  oc_tcp_on_connect_event_t *event = oc_tcp_on_connect_event_allocate();
  if (event == NULL) {
    OC_ERR("could not allocate new TCP on connect object");
    return NULL;
  }
  memcpy(&event->endpoint, endpoint, sizeof(oc_endpoint_t));
  event->state = state;
  event->fn = fn;
  event->fn_data = fn_data;
  return event;
}

void
oc_tcp_on_connect_event_free(oc_tcp_on_connect_event_t *event)
{
  if (event == NULL) {
    return;
  }
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_lock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_memb_free(&g_oc_tcp_on_connect_event_s, event);
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_unlock();
#endif /* !OC_DYNAMIC_ALLOCATION */
}

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

static OC_ATOMIC_UINT32_T g_tcp_session_id = 0;

uint32_t
oc_tcp_get_new_session_id(void)
{
  uint32_t v = OC_ATOMIC_INCREMENT32(g_tcp_session_id);
  return (v == 0) ? OC_ATOMIC_INCREMENT32(g_tcp_session_id) : v;
}

bool
oc_tcp_is_valid_header(const uint8_t *data, size_t data_size, bool is_tls)
{
#ifdef OC_SECURITY
#define SSL_MAJOR_VERSION_3 (3)
#define SSL_MINOR_VERSION_1 (1)
#define SSL_MINOR_VERSION_2 (2)
#define SSL_MINOR_VERSION_3 (3)
#define SSL_MINOR_VERSION_4 (4)
  if (is_tls) {
    if (data_size < 3) {
      OC_ERR("TLS header too short: %zu", data_size);
      return false;
    }
    // Parse the header fields
    uint8_t type = data[0];
    uint8_t major_version = data[1];
    uint8_t minor_version = data[2];
    OC_DBG("TLS header: record type: %d, major %d, minor %d", type,
           major_version, minor_version);
    // Validate the header fields
    switch (type) {
    case MBEDTLS_SSL_MSG_HANDSHAKE:
    case MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC:
    case MBEDTLS_SSL_MSG_ALERT:
    case MBEDTLS_SSL_MSG_APPLICATION_DATA:
    case MBEDTLS_SSL_MSG_CID:
      // Valid record type
      break;
    default:
      OC_ERR("invalid record type: %d", type);
      return false;
    }
    if (major_version != SSL_MAJOR_VERSION_3) {
      OC_ERR("invalid major version: %d", major_version);
      return false;
    }
    if (
      // TLS 1.0 - some implementations doesn't set the minor version (eg
      // golang)
      minor_version != SSL_MINOR_VERSION_1 &&
      // TLS 1.1
      minor_version != SSL_MINOR_VERSION_2 &&
      // TLS 1.2
      minor_version != SSL_MINOR_VERSION_3 &&
      // TLS 1.3
      minor_version != SSL_MINOR_VERSION_4) {
      OC_ERR("invalid minor version: %d", minor_version);
      return false;
    }
    return true;
  }
#else  /* !OC_SECURITY */
  (void)is_tls;
#endif /* OC_SECURITY */
  if (data_size < 1) {
    OC_ERR("TCP header too short: %zu", data_size);
    return false;
  }
  int token_len =
    (COAP_HEADER_TOKEN_LEN_MASK & data[0]) >> COAP_HEADER_TOKEN_LEN_POSITION;
  if (token_len > COAP_TOKEN_LEN) {
    OC_ERR("invalid token length: %d", token_len);
    // Invalid token length
    return false;
  }
  return true;
}

bool
oc_tcp_is_valid_message(oc_message_t *message)
{
  assert(message != NULL);
#ifdef OC_SECURITY
  if ((message->endpoint.flags & SECURED) != 0) {
    // validate TLS message before processing it by oc_tcp_is_valid_header
    return true;
  }
#ifdef OC_OSCORE
  if (oscore_is_oscore_message(message)) {
    // it is oscore message
    return true;
  }
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */
  // validate message message before processing it
  coap_packet_t packet;
  coap_status_t s =
    coap_tcp_parse_message(&packet, message->data, message->length, true);
  if (s != COAP_NO_ERROR) {
    OC_ERR("coap_tcp_parse_message failed: %d", s);
    return false;
  }
  return true;
}

long
oc_tcp_get_total_length_from_message_header(const oc_message_t *message)
{
  return oc_tcp_get_total_length_from_header(
    message->data, message->length, (message->endpoint.flags & SECURED) != 0);
}

long
oc_tcp_get_total_length_from_header(const uint8_t *data, size_t data_size,
                                    bool is_tls)
{
  if (!oc_tcp_is_valid_header(data, data_size, is_tls)) {
    OC_ERR("invalid header");
    return -1;
  }

#ifdef OC_SECURITY
#define OC_TLS_HEADER_SIZE (5)
  if (is_tls) {
    if (data_size < OC_TLS_HEADER_SIZE) {
      OC_ERR("TLS header too short: %zu", data_size);
      return -1;
    }
    //[3][4] bytes in tls header are tls payload length
    return OC_TLS_HEADER_SIZE + ((data[3] << 8) | data[4]);
  }
#endif /* OC_SECURITY */
  return coap_tcp_get_packet_size(data, data_size);
}

#endif /* OC_TCP */
