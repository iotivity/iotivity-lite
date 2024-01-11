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

#ifdef OC_TCP

#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_buffer.h"
#include "api/oc_tcp_internal.h"
#include "messaging/coap/coap_internal.h"
#include "port/oc_allocator_internal.h"
#include "tests/gtest/Endpoint.h"
#include "util/oc_features.h"

#ifdef OC_OSCORE
#include "messaging/coap/oscore_internal.h"
#endif /* OC_OSCORE */

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <vector>

#ifdef _WIN32
#include <WinSock2.h>
#endif /* _WIN32 */

#ifdef OC_SECURITY
#include <mbedtls/ssl.h>
#endif /* OC_SECURITY */

class TCPMessage : public testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif /* _WIN32 */
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
    oc_allocator_mutex_init();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
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

  static void ValidateHeader(bool exp, bool secure, const uint8_t *data,
                             size_t data_size)
  {
    EXPECT_EQ(exp, oc_tcp_is_valid_header(data, data_size, secure));
  }

  static void ValidateHeader(bool exp, bool secure,
                             const std::vector<uint8_t> &data)
  {
    EXPECT_EQ(exp, oc_tcp_is_valid_header(&data[0], data.size(), secure));
  }

  static void ValidateMessage(bool exp, bool secure, const uint8_t *data,
                              size_t data_size)
  {
    oc_message_t *msg = oc_allocate_message();
    ASSERT_NE(nullptr, msg);
    int flags = IPV6 | TCP;
    flags |= secure ? SECURED : 0;
    msg->endpoint.flags = static_cast<transport_flags>(flags);
    if (data_size > 0) {
      memcpy(msg->data, data, data_size);
    }
    msg->length = data_size;
    EXPECT_EQ(exp, oc_tcp_is_valid_message(msg));
    oc_message_unref(msg);
  }

  static void ValidateMessage(bool exp, bool secure,
                              const std::vector<uint8_t> &data)
  {
    ValidateMessage(exp, secure, &data[0], data.size());
  }

  static void ValidateMessage(bool exp, bool secure, bool oscore,
                              coap_packet_t &packet)
  {
    std::array<uint8_t, 512> buffer{};
    size_t buffer_len = coap_oscore_serialize_message(
      &packet, &buffer[0], buffer.size(), true, true, oscore);
    ASSERT_LT(0, buffer_len);
    ValidateMessage(exp, secure, &buffer[0], buffer.size());
  }

  static void ValidateHeaderLength(long exp, bool secure, const uint8_t *data,
                                   size_t data_size)
  {
    EXPECT_EQ(exp,
              oc_tcp_get_total_length_from_header(data, data_size, secure));
  }

  static void ValidateHeaderLength(long exp, bool secure,
                                   const std::vector<uint8_t> &data)
  {
    ValidateHeaderLength(exp, secure, &data[0], data.size());
  }

  static void ValidateHeaderLength(long exp, bool secure, oc_message_t *msg)
  {
    int flags = IPV6 | TCP;
    flags |= secure ? SECURED : 0;
    msg->endpoint.flags = static_cast<transport_flags>(flags);
    EXPECT_EQ(exp, oc_tcp_get_total_length_from_message_header(msg));
  }
};

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

TEST_F(TCPMessage, CreateConnectEvent)
{
  auto ep = oc::endpoint::FromString("coap+tcp://[::1]:42");
  on_tcp_connect_t on_connect = [](const oc_endpoint_t *, int, void *) {
    // no-op
  };
  int data = 42;

  oc_tcp_on_connect_event_t *event = oc_tcp_on_connect_event_create(
    &ep, OC_TCP_SOCKET_STATE_CONNECTED, on_connect, &data);
  ASSERT_NE(nullptr, event);
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, event->state);
  EXPECT_EQ(0, memcmp(&ep, &event->endpoint, sizeof(oc_endpoint_t)));
  EXPECT_EQ(on_connect, event->fn);
  EXPECT_EQ(&data, event->fn_data);

  oc_tcp_on_connect_event_free(event);
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TCPMessage, CreateConnectEvent_FailAllocation)
{
  auto ep = oc::endpoint::FromString("coap+tcp://[::1]:42");

  std::vector<oc_tcp_on_connect_event_t *> events{};
  for (int i = 0; i < OC_MAX_TCP_PEERS; ++i) {
    oc_tcp_on_connect_event_t *event = oc_tcp_on_connect_event_create(
      &ep, OC_TCP_SOCKET_STATE_CONNECTED, nullptr, nullptr);
    ASSERT_NE(nullptr, event);
    events.push_back(event);
  }

  oc_tcp_on_connect_event_t *event = oc_tcp_on_connect_event_create(
    &ep, OC_TCP_SOCKET_STATE_CONNECTED, nullptr, nullptr);
  EXPECT_EQ(nullptr, event);

  for (auto e : events) {
    oc_tcp_on_connect_event_free(e);
  }
}

#endif /* !OC_DYNAMIC_ALLOCATION */

TEST_F(TCPMessage, FreeNullConnectEvent)
{
  oc_tcp_on_connect_event_free(nullptr);
}

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

TEST_F(TCPMessage, ValidateHeader)
{
  ValidateHeader(false, false, nullptr, 0);
  ValidateHeader(true, false, { 1, 2, 3, 4 });
  ValidateHeader(false, false, { 0xff, 2, 3, 4 });

#ifdef OC_SECURITY
#define SSL_MAJOR_VERSION_3 (3)
#define SSL_MINOR_VERSION_1 (1)
#define SSL_MINOR_VERSION_2 (2)
#define SSL_MINOR_VERSION_3 (3)
#define SSL_MINOR_VERSION_4 (4)
  ValidateHeader(false, true, nullptr, 0);
  ValidateHeader(
    true, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1 });
  ValidateHeader(
    true, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_2 });
  ValidateHeader(
    true, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3 });
  ValidateHeader(
    true, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_4 });
  ValidateHeader(false, true,
                 { MBEDTLS_SSL_MSG_HANDSHAKE, 0xff, SSL_MINOR_VERSION_3 });
  ValidateHeader(false, true,
                 { MBEDTLS_SSL_MSG_HANDSHAKE, SSL_MAJOR_VERSION_3, 0xff });
  ValidateHeader(false, true,
                 { MBEDTLS_SSL_MSG_HANDSHAKE, SSL_MAJOR_VERSION_3 });
  ValidateHeader(false, true,
                 { 0xff, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3 });
#endif /* OC_SECURITY */
}

TEST_F(TCPMessage, ValidateMessage)
{
#ifdef OC_SECURITY
  coap_packet_t tlsPacket = {};
  ValidateMessage(true, true, false, tlsPacket);
#ifdef OC_OSCORE
  coap_packet_t oscorePacket = {};
  coap_tcp_init_message(&oscorePacket, COAP_GET);
  coap_set_header_oscore(&oscorePacket, nullptr, 0, nullptr, 0, nullptr, 0);
  ValidateMessage(true, false, true, oscorePacket);
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */

  ValidateMessage(false, false, { 1, 2, 3, 4 });

  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, COAP_GET);
  ValidateMessage(true, false, false, packet);
}

TEST_F(TCPMessage, GetTotalLength)
{
  ValidateHeaderLength(-1, false, { 0xff, 2, 3, 4 });

  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 512> buffer{};
  size_t buffer_len =
    coap_serialize_message(&packet, buffer.data(), buffer.size());
  ASSERT_LT(0, buffer_len);
  ValidateHeaderLength(2, false, &buffer[0], buffer_len);

#ifdef OC_SECURITY
  ValidateHeaderLength(-1, true, { 1 });

  mbedtls_ssl_config conf;
  mbedtls_ssl_config_init(&conf);
  ASSERT_EQ(0, mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT));
#if MBEDTLS_VERSION_NUMBER <= 0x03010000
  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                               MBEDTLS_SSL_MINOR_VERSION_3);
#endif /* MBEDTLS_VERSION_NUMBER <= 0x03010000 */
  mbedtls_ssl_context ssl;
  mbedtls_ssl_init(&ssl);
  ASSERT_EQ(0, mbedtls_ssl_setup(&ssl, &conf));

  oc_message_t *message = oc_allocate_message();
  ASSERT_NE(nullptr, message);
  mbedtls_ssl_set_bio(
    &ssl, message,
    [](void *ctx, const unsigned char *buf, size_t len) {
      auto *msg = static_cast<oc_message_t *>(ctx);
      memcpy(msg->data, buf, len);
      msg->length = len;
      return static_cast<int>(len);
    },
    nullptr, nullptr);

#if MBEDTLS_VERSION_NUMBER <= 0x03010000
  ssl.major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
  ssl.minor_ver = MBEDTLS_SSL_MINOR_VERSION_3;
#else  /* MBEDTLS_VERSION_NUMBER > 0x03010000 */
  ssl.tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
#endif /* MBEDTLS_VERSION_NUMBER <= 0x03010000 */
  ssl.state = MBEDTLS_SSL_HANDSHAKE_OVER;
  std::vector<uint8_t> data{ 0x01, 0x02, 0x03, 0x04 };
  ASSERT_EQ(data.size(), mbedtls_ssl_write(&ssl, &data[0], data.size()));
  ValidateHeaderLength(/*OC_TLS_HEADER_SIZE*/ 5 + data.size(), true, message);

  oc_message_unref(message);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);

#define SSL_MAJOR_VERSION_3 (3)
#define SSL_MINOR_VERSION_3 (3)
  ValidateHeaderLength(
    -1, true,
    { MBEDTLS_SSL_MSG_HANDSHAKE, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3 });
#endif /* OC_SECURITY */
}

#endif /* OC_TCP */