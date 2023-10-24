/****************************************************************************
 *
 * Copyright (c) 2022 plgd.dev s.r.o.
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

#include "oc_endpoint.h"
#include "oc_udp_internal.h"
#include "messaging/coap/coap_internal.h"
#include "port/oc_connectivity.h"
#ifdef OC_SECURITY
#include <mbedtls/ssl.h>
#ifdef OC_OSCORE
#include "messaging/coap/oscore_internal.h"
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */

#include <assert.h>

bool
oc_udp_is_valid_message(oc_message_t *message)
{
  assert(message != NULL);
#ifdef OC_SECURITY
  if ((message->endpoint.flags & SECURED) != 0) {
    if (message->length < 3) {
      OC_ERR("invalid DTLS header length: %lu", (long unsigned)message->length);
      // Invalid DTLS header length
      return false;
    }

    // Parse the header fields
    uint8_t type = message->data[0];
    uint8_t major_version = 255 - message->data[1] + 2;
    uint8_t minor_version = 255 - message->data[2] + 1;
    OC_DBG("TLS header: record type: %d, major %d(%d), minor %d(%d)", type,
           major_version, message->data[1], minor_version, message->data[2]);
    if (major_version != MBEDTLS_SSL_MAJOR_VERSION_3) {
      OC_ERR("invalid major version: %d", major_version);
      // Invalid major version
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
      OC_WRN("invalid record type: %d", type);
      // mbedtls need to get invalid record type to handle it
    }
    return true;
  }
#ifdef OC_OSCORE
  if (oscore_is_oscore_message(message) >= 0) {
    // it is oscore message
    return true;
  }
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */
  coap_packet_t packet;
  coap_status_t s =
    coap_udp_parse_message(&packet, message->data, message->length, true);
  if (s == BAD_REQUEST_4_00) {
    OC_ERR("coap_udp_parse_message failed: %d", s);
    return false;
  }
  return true;
}
