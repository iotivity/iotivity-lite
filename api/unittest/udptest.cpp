/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_buffer.h"
#include "api/oc_udp_internal.h"
#include "port/oc_allocator_internal.h"
#include "port/oc_log_internal.h"

#if defined(OC_SECURITY) && defined(OC_OSCORE)
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/oscore_internal.h"
#endif /* OC_SECURITY && OC_OSCORE */

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>

#ifdef _WIN32
#include <WinSock2.h>
#endif /* _WIN32 */

#ifdef OC_SECURITY
#include <mbedtls/ssl.h>
#endif /* OC_SECURITY */

class UDPMessage : public testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif /* _WIN32 */
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
    oc_allocator_mutex_init();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX*/
  }

  static void TearDownTestCase()
  {
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
    oc_allocator_mutex_destroy();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
#ifdef _WIN32
    WSACleanup();
#endif /* _WIN32 */
  }

  static void ValidateMessage(bool exp, bool secure, const uint8_t *data,
                              size_t data_size)
  {
    oc_message_t *msg = oc_allocate_message();
    ASSERT_NE(nullptr, msg);
    int flags = IPV6;
    flags |= secure ? SECURED : 0;
    msg->endpoint.flags = static_cast<transport_flags>(flags);
    if (data_size > 0) {
      memcpy(msg->data, data, data_size);
    }
    msg->length = data_size;
    EXPECT_EQ(exp, oc_udp_is_valid_message(msg));
    oc_message_unref(msg);
  }

  static void ValidateMessage(bool exp, bool secure,
                              const std::vector<uint8_t> &data)
  {
    ValidateMessage(exp, secure, &data[0], data.size());
  }

#if defined(OC_SECURITY) && defined(OC_OSCORE)
  static void ValidateMessage(bool exp, bool secure, bool oscore,
                              coap_packet_t &packet)
  {
    std::array<uint8_t, 512> buffer{};
    size_t buffer_len = coap_oscore_serialize_message(
      &packet, &buffer[0], buffer.size(), true, true, oscore);
    ASSERT_LT(0, buffer_len);
    ValidateMessage(exp, secure, &buffer[0], buffer.size());
  }
#endif /* OC_SECURITY && OC_OSCORE */
};

TEST_F(UDPMessage, ValidateHeader)
{
  ValidateMessage(false, false, nullptr, 0);
  ValidateMessage(true, false, { 1 << COAP_HEADER_VERSION_POSITION, 2, 3, 4 });
  ValidateMessage(false, false, { 0xff, 2, 3, 4 });
#ifdef OC_SECURITY
  OC_DBG("ValidateMessage(true, true, {MBEDTLS_SSL_MSG_HANDSHAKE, "
         "255-MBEDTLS_SSL_MAJOR_VERSION_3+2, 255-1+1});");
  ValidateMessage(true, true,
                  { MBEDTLS_SSL_MSG_HANDSHAKE,
                    255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2, 255 - 1 + 1 });
  OC_DBG(
    "ValidateMessage(true, true, {MBEDTLS_SSL_MSG_HANDSHAKE, "
    "255-MBEDTLS_SSL_MAJOR_VERSION_3+2, 255-MBEDTLS_SSL_MINOR_VERSION_3+1});");
  ValidateMessage(true, true,
                  { MBEDTLS_SSL_MSG_HANDSHAKE,
                    255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2, 255 - 2 + 1 });
  OC_DBG(
    "ValidateMessage(true, true, {MBEDTLS_SSL_MSG_HANDSHAKE, "
    "255-MBEDTLS_SSL_MAJOR_VERSION_3+2, 255-MBEDTLS_SSL_MINOR_VERSION_3+1});");
  ValidateMessage(true, true,
                  { MBEDTLS_SSL_MSG_HANDSHAKE,
                    255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2,
                    255 - MBEDTLS_SSL_MINOR_VERSION_3 + 1 });
  OC_DBG(
    "ValidateMessage(true, true, {MBEDTLS_SSL_MSG_HANDSHAKE, "
    "255-MBEDTLS_SSL_MAJOR_VERSION_3+2, 255-MBEDTLS_SSL_MINOR_VERSION_4+1});");
  ValidateMessage(true, true,
                  { MBEDTLS_SSL_MSG_HANDSHAKE,
                    255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2,
                    255 - MBEDTLS_SSL_MINOR_VERSION_4 + 1 });
  OC_DBG("ValidateMessage(false, true, {MBEDTLS_SSL_MSG_HANDSHAKE, 0xff, "
         "255-MBEDTLS_SSL_MINOR_VERSION_3+1});");
  ValidateMessage(
    false, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, 0xff, 255 - MBEDTLS_SSL_MINOR_VERSION_3 + 1 });
  OC_DBG("ValidateMessage(false, true, {MBEDTLS_SSL_MSG_HANDSHAKE, "
         "255-MBEDTLS_SSL_MAJOR_VERSION_3+2, 128});");
  ValidateMessage(
    false, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, 255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2, 128 });
  OC_DBG("ValidateMessage(false, true, {MBEDTLS_SSL_MSG_HANDSHAKE, "
         "255-MBEDTLS_SSL_MAJOR_VERSION_3+2, 0xff});");
  ValidateMessage(
    false, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, 255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2 });
  OC_DBG(
    "ValidateMessage(false, true, {0xff, 255-MBEDTLS_SSL_MAJOR_VERSION_3+2, "
    "255-MBEDTLS_SSL_MINOR_VERSION_3+1});");
  // produces just warning
  ValidateMessage(true, true,
                  { 0xff, 255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2,
                    255 - MBEDTLS_SSL_MINOR_VERSION_3 + 1 });

#ifdef OC_OSCORE
  OC_DBG("ValidateMessage(true, false, true, oscorePacket);");
  coap_packet_t oscorePacket = {};
  coap_udp_init_message(&oscorePacket, COAP_TYPE_NON, COAP_GET, 0);
  coap_set_header_oscore(&oscorePacket, nullptr, 0, nullptr, 0, nullptr, 0);
  ValidateMessage(true, false, true, oscorePacket);
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */
}