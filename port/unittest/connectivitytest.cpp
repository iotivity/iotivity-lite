/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "api/oc_tcp_internal.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/coap_signal.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_network_monitor.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_atomic.h"
#include "util/oc_features.h"
#include "tests/gtest/Device.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <gtest/gtest.h>
#include <string>

static const size_t g_device = 0;

class TestConnectivity : public testing::Test {
public:
  void SetUp() override
  {
    is_callback_received.store(false);
    oc_network_event_handler_mutex_init();
  }

  void TearDown() override { oc_network_event_handler_mutex_destroy(); }

  static std::atomic<bool> is_callback_received;
};

std::atomic<bool> TestConnectivity::is_callback_received{ false };

TEST(TestConnectivity_init, oc_connectivity_init)
{
  int ret = oc_connectivity_init(g_device);
  EXPECT_EQ(0, ret);
  oc_connectivity_shutdown(g_device);
}

static void
interface_event_handler(oc_interface_event_t event)
{
  EXPECT_EQ(NETWORK_INTERFACE_UP, event);
  TestConnectivity::is_callback_received.store(true);
}

TEST_F(TestConnectivity, oc_add_network_interface_event_callback)
{
  int ret = oc_add_network_interface_event_callback(interface_event_handler);
  EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_network_interface_event_callback)
{
  oc_add_network_interface_event_callback(interface_event_handler);
  int ret = oc_remove_network_interface_event_callback(interface_event_handler);
  EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_network_interface_event_callback_invalid)
{
  int ret = oc_remove_network_interface_event_callback(interface_event_handler);
  EXPECT_EQ(-1, ret);
}

#ifdef OC_NETWORK_MONITOR
TEST_F(TestConnectivity, handle_network_interface_event_callback)
{
  oc_add_network_interface_event_callback(interface_event_handler);
  handle_network_interface_event_callback(NETWORK_INTERFACE_UP);
  EXPECT_EQ(true, is_callback_received);
}
#endif /* OC_NETWORK_MONITOR */

static void
session_event_handler(const oc_endpoint_t *ep, oc_session_state_t state)
{
  EXPECT_NE(nullptr, ep);
  EXPECT_EQ(OC_SESSION_CONNECTED, state);
  TestConnectivity::is_callback_received.store(true);
}

TEST_F(TestConnectivity, oc_add_session_event_callback)
{
  int ret = oc_add_session_event_callback(session_event_handler);
  EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_session_event_callback)
{
  oc_add_session_event_callback(session_event_handler);
  int ret = oc_remove_session_event_callback(session_event_handler);
  EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_session_event_callback_invalid)
{
  int ret = oc_remove_session_event_callback(session_event_handler);
  EXPECT_EQ(-1, ret);
}

#ifdef OC_SESSION_EVENTS
TEST_F(TestConnectivity, handle_session_event_callback)
{
  oc_add_session_event_callback(session_event_handler);
  oc_endpoint_t ep{};
  handle_session_event_callback(&ep, OC_SESSION_CONNECTED);
  EXPECT_EQ(true, is_callback_received);
}
#endif /* OC_SESSION_EVENTS */

#ifdef OC_TCP

TEST_F(TestConnectivity, oc_tcp_get_csm_state_P)
{
  oc_endpoint_t ep{};
  tcp_csm_state_t ret = oc_tcp_get_csm_state(&ep);

  EXPECT_EQ(CSM_NONE, ret);
}

TEST_F(TestConnectivity, oc_tcp_get_csm_state_N)
{
  tcp_csm_state_t ret = oc_tcp_get_csm_state(nullptr);

  EXPECT_EQ(CSM_ERROR, ret);
}

#endif /* OC_TCP */

class TestConnectivityWithServer : public testing::Test {
public:
  void SetUp() override
  {
    is_callback_received.store(false);
    ASSERT_TRUE(oc::TestDevice::StartServer());
  }

  void TearDown() override { oc::TestDevice::StopServer(); }

  static oc_endpoint_t *findEndpoint(size_t device);
  static oc_endpoint_t createEndpoint(const std::string &ep_str);

  static std::atomic<bool> is_callback_received;
};

std::atomic<bool> TestConnectivityWithServer::is_callback_received{ false };

oc_endpoint_t *
TestConnectivityWithServer::findEndpoint(size_t device)
{
  int flags = 0;
#ifdef OC_SECURITY
  flags |= SECURED;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  flags |= IPV4;
#endif /* OC_IPV4 */
#ifdef OC_TCP
  flags |= TCP;
#endif /* OC_TCP */

  oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(device, flags);
  EXPECT_NE(nullptr, ep);
  return ep;
}

oc_endpoint_t
TestConnectivityWithServer::createEndpoint(const std::string &ep_str)
{
  oc_string_t ep_ocstr;
  oc_new_string(&ep_ocstr, ep_str.c_str(), ep_str.length());
  oc_endpoint_t ep{};
  int ret = oc_string_to_endpoint(&ep_ocstr, &ep, nullptr);
  oc_free_string(&ep_ocstr);
  EXPECT_EQ(0, ret) << "cannot convert endpoint " << ep_str;
  return ep;
}

TEST_F(TestConnectivityWithServer, oc_connectivity_get_endpoints)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(g_device);
  EXPECT_NE(nullptr, ep);
}

#ifdef OC_TCP

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

static void
on_tcp_connect(const oc_endpoint_t *, int state, void *)
{
  OC_DBG("on_tcp_connect");
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, state);
  oc::TestDevice::Terminate();
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

TEST_F(TestConnectivityWithServer, oc_tcp_update_csm_state_P)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  int ret = oc_tcp_connect(ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_update_csm_state_P wait");
    oc::TestDevice::PoolEvents(10);
  }
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(ep));
#else  /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, ep, sizeof(oc_endpoint_t));
  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, CSM_7_01);
  std::array<uint8_t, 8> payload{ "connect" };
  packet.payload = payload.data();
  packet.payload_len = payload.size();
  msg->length = coap_serialize_message(&packet, msg->data);

  oc_send_buffer(msg);
  oc_message_unref(msg);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

  EXPECT_EQ(0, oc_tcp_update_csm_state(ep, CSM_DONE));
  EXPECT_EQ(CSM_DONE, oc_tcp_get_csm_state(ep));
}

TEST_F(TestConnectivityWithServer, oc_tcp_update_csm_state_N)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
  ASSERT_NE(nullptr, ep);

  oc_tcp_update_csm_state(ep, CSM_DONE);

  tcp_csm_state_t ret = oc_tcp_get_csm_state(ep);

  EXPECT_NE(CSM_DONE, ret);
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
TEST_F(TestConnectivityWithServer, oc_tcp_connect_fail)
{
  oc_endpoint_t ep =
    createEndpoint("coaps+tcp://[ff02::158]:12345"); // unreachable address
  EXPECT_EQ(-1, oc_tcp_connect(&ep, nullptr, this));
}

static void
on_tcp_connect_timeout(const oc_endpoint_t *, int state, void *)
{
  OC_DBG("on_tcp_connect_timeout");
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_TIMEOUT, state);
  TestConnectivityWithServer::is_callback_received.store(true);
  oc::TestDevice::Terminate();
}

TEST_F(TestConnectivityWithServer, oc_tcp_connect_timeout)
{
  oc_endpoint_t ep = createEndpoint(
    "coaps+tcp://[::1]:12345"); // reachable address, but inactive port
  // timeout 2s, 2 retries -> total 6s
  oc_tcp_set_connect_retry(2, 2);
  const unsigned connect_timeout = 6;
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTING,
            oc_tcp_connect(&ep, on_tcp_connect_timeout, this));

  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_NOT_CONNECTED, oc_send_buffer2(msg, false));
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, oc_tcp_connection_state(&ep));
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  EXPECT_EQ(OC_SEND_MESSAGE_QUEUED, oc_send_buffer2(msg, true));

  OC_DBG("oc_tcp_connect_timeout wait");
  oc::TestDevice::PoolEvents(connect_timeout + 2); // +2 to be sure

  EXPECT_EQ(-1, oc_tcp_connection_state(&ep));
  oc_message_unref(msg);

  // restore defaults
  oc_tcp_set_connect_retry(OC_TCP_CONNECT_RETRY_MAX_COUNT,
                           OC_TCP_CONNECT_RETRY_TIMEOUT);
}

TEST_F(TestConnectivityWithServer, oc_tcp_connect_repeat_fail)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
  int ret = oc_tcp_connect(ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_connect_repeat_fail wait");
    oc::TestDevice::PoolEvents(10);
  }
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(ep));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_EXISTS_CONNECTED,
            oc_tcp_connect(ep, nullptr, this));
}

TEST_F(TestConnectivityWithServer, oc_tcp_connecting_repeat_fail)
{
  oc_endpoint_t ep = createEndpoint(
    "coaps+tcp://[::1]:12345"); // reachable address, but inactive port
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, oc_tcp_connect(&ep, nullptr, this));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_EXISTS_CONNECTING,
            oc_tcp_connect(&ep, nullptr, this));
}

/** create a TCP session, wait for it to connect and send data */
TEST_F(TestConnectivityWithServer, oc_tcp_send_buffer2)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
  int ret = oc_tcp_connect(ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_send_buffer2 wait");
    oc::TestDevice::PoolEvents(5);
  }
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(ep));

  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, CSM_7_01);
  std::array<uint8_t, 5> payload{ "test" };
  packet.payload = payload.data();
  packet.payload_len = payload.size();

  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, ep, sizeof(oc_endpoint_t));
  msg->length = coap_serialize_message(&packet, msg->data);

  EXPECT_EQ(msg->length, oc_send_buffer2(msg, false));
  oc_message_unref(msg);
}

/** fail sending a message to an address without an ongoing or waiting TCP
 * session */
TEST_F(TestConnectivityWithServer, oc_tcp_send_buffer2_not_connected)
{
  oc_endpoint_t ep = createEndpoint("coaps+tcp://[ff02::158]:12345");
  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_NOT_CONNECTED, oc_send_buffer2(msg, true));

#ifdef OC_IPV4
  oc_endpoint_t ep_ipv4 = createEndpoint("coaps+tcp://1.1.1.1:12345");
  memcpy(&msg->endpoint, &ep_ipv4, sizeof(oc_endpoint_t));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_NOT_CONNECTED, oc_send_buffer2(msg, true));
#endif /* OC_IPV4 */

  oc_message_unref(msg);
}

#if defined(OC_DNS_LOOKUP) && (defined(OC_DNS_LOOKUP_IPV6) || defined(OC_IPV4))
/** connecting to existing but not listening endpoint should timeout after max
 * number of allowed retries  */
TEST_F(TestConnectivityWithServer, oc_tcp_send_buffer2_drop)
{
  // timeout 2s, 2 retries -> total 6s
  oc_tcp_set_connect_retry(2, 2);

  oc_endpoint_t ep = createEndpoint("coap+tcp://openconnectivity.org:3456");
  ASSERT_EQ(OC_TCP_SOCKET_STATE_CONNECTING,
            oc_tcp_connect(&ep, on_tcp_connect_timeout, this));

  while (!is_callback_received) {
    OC_DBG("oc_tcp_send_buffer2_drop wait");
    oc::TestDevice::PoolEvents(5);
  }

  // restore defaults
  oc_tcp_set_connect_retry(OC_TCP_CONNECT_RETRY_MAX_COUNT,
                           OC_TCP_CONNECT_RETRY_TIMEOUT);
}
#endif /* OC_DNS_LOOKUP && (OC_DNS_LOOKUP_IPV6 || OC_IPV4) */

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#endif /* OC_TCP */
