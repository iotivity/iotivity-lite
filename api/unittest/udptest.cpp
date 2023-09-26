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
  void SetUp() override
  {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif /* _WIN32 */
#ifndef OC_DYNAMIC_ALLOCATION
    oc_allocator_mutex_init();
#endif /* !OC_DYNAMIC_ALLOCATION */
  }

  void TearDown() override
  {
#ifndef OC_DYNAMIC_ALLOCATION
    oc_allocator_mutex_destroy();
#endif /* !OC_DYNAMIC_ALLOCATION */
#ifdef _WIN32
    WSACleanup();
#endif /* _WIN32 */
  }

  static void ValidateMessage(bool exp, bool secure,
                              const std::vector<uint8_t> &data)
  {
    oc_message_t *msg = oc_allocate_message();
    msg->endpoint.flags = secure ? SECURED : (transport_flags)0;
    memcpy(msg->data, &data[0], data.size());
    msg->length = data.size();
    EXPECT_EQ(exp, oc_udp_is_valid_message(msg));
    oc_message_unref(msg);
  }
};

TEST_F(UDPMessage, ValidateHeader)
{
  ValidateMessage(true, false, { 1 << COAP_HEADER_VERSION_POSITION, 2, 3, 4 });
  ValidateMessage(false, false, { 0xff, 2, 3, 4 });
#ifdef OC_SECURITY
  OC_DBG(
    "ValidateMessage(true, true, {MBEDTLS_SSL_MSG_HANDSHAKE, "
    "255-MBEDTLS_SSL_MAJOR_VERSION_3+2, 255-MBEDTLS_SSL_MINOR_VERSION_3+1});");
  ValidateMessage(true, true,
                  { MBEDTLS_SSL_MSG_HANDSHAKE,
                    255 - MBEDTLS_SSL_MAJOR_VERSION_3 + 2,
                    255 - MBEDTLS_SSL_MINOR_VERSION_3 + 1 });
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
#endif /* OC_SECURITY */
}