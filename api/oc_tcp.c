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
#include "messaging/coap/coap.h"
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include "oc_tcp_internal.h"
#ifdef OC_SECURITY
#include <mbedtls/ssl.h>
#ifdef OC_OSCORE
#include "messaging/coap/oscore.h"
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

bool
oc_tcp_is_valid_header(const oc_message_t *message)
{
  assert(message != NULL);
#ifdef OC_SECURITY
  if ((message->endpoint.flags & SECURED) != 0) {
    if (message->length < 3) {
      OC_ERR("TLS header too short: %lu", (long unsigned)message->length);
      return false;
    }
    // Parse the header fields
    uint8_t type = message->data[0];
    uint8_t major_version = message->data[1];
    uint8_t minor_version = message->data[2];
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
    if (major_version != MBEDTLS_SSL_MAJOR_VERSION_3) {
      OC_ERR("invalid major version: %d", major_version);
      return false;
    }
    if (
      // TLS 1.0 - some implementations doesn't set the minor version (eg
      // golang)
      minor_version != 1 &&
      // TLS 1.1
      minor_version != 2 &&
      // TLS 1.2
      minor_version != MBEDTLS_SSL_MINOR_VERSION_3 &&
      // TLS 1.3
      minor_version != MBEDTLS_SSL_MINOR_VERSION_4) {
      OC_ERR("invalid minor version: %d", minor_version);
      return false;
    }
    return true;
  }
#endif /* OC_SECURITY */
  int token_len = (COAP_HEADER_TOKEN_LEN_MASK & message->data[0]) >>
                  COAP_HEADER_TOKEN_LEN_POSITION;
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
  if (oscore_is_oscore_message(message) >= 0) {
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

#endif /* OC_TCP */
