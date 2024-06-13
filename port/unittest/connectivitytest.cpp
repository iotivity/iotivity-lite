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

#include "api/oc_message_internal.h"
#include "api/oc_network_events_internal.h"
#include "api/oc_tcp_internal.h"
#include "api/oc_session_events_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/signal_internal.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_network_monitor.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_atomic.h"
#include "util/oc_features.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <gtest/gtest.h>
#include <optional>
#include <string>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID = 0;
static constexpr size_t kInvalidDeviceID = 42;

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

TEST(TestConnectivity_init, Default)
{
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(oc_connectivity_ports_t));
  int ret = oc_connectivity_init(kDeviceID, ports);
  EXPECT_EQ(0, ret);
  oc_connectivity_shutdown(kDeviceID);
}

TEST(TestConnectivity_init, TCPDisabled)
{
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(oc_connectivity_ports_t));
#ifdef OC_TCP
  ports.tcp.flags = OC_CONNECTIVITY_DISABLE_ALL_PORTS;
#endif /* OC_TCP */
#if defined(OC_IPV4)
  ports.udp.port4 = 5683;
#if defined(OC_SECURITY)
  ports.udp.secure_port4 = 5684;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  // ipv6
  ports.udp.port = 15683;
#if defined(OC_SECURITY)
  ports.udp.secure_port = 5684;
#endif /* OC_SECURITY */
  int ret = oc_connectivity_init(kDeviceID, ports);
  EXPECT_EQ(0, ret);
  oc_connectivity_shutdown(kDeviceID);
}

TEST(TestConnectivity_init, UDPDisabled)
{
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(oc_connectivity_ports_t));
  ports.udp.flags = OC_CONNECTIVITY_DISABLE_ALL_PORTS;
#ifdef OC_TCP
#if defined(OC_IPV4)
  ports.tcp.port4 = 5683;
#if defined(OC_SECURITY)
  ports.tcp.secure_port4 = 5684;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  // ipv6
  ports.tcp.port = 5683;
#if defined(OC_SECURITY)
  ports.tcp.secure_port = 5684;
#endif /* OC_SECURITY */
#endif /* OC_TCP */
  int ret = oc_connectivity_init(kDeviceID, ports);
  EXPECT_EQ(0, ret);
  oc_connectivity_shutdown(kDeviceID);
}

TEST(TestConnectivity_init, AllDisabled)
{
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(oc_connectivity_ports_t));
  ports.udp.flags = OC_CONNECTIVITY_DISABLE_ALL_PORTS;
#ifdef OC_TCP
  ports.tcp.flags = OC_CONNECTIVITY_DISABLE_ALL_PORTS;
#endif /* OC_TCP */
  int ret = oc_connectivity_init(kDeviceID, ports);
  EXPECT_EQ(0, ret);
  oc_connectivity_shutdown(kDeviceID);
}

TEST(TestConnectivity_shutdown, InvalidDevice)
{
  oc_connectivity_shutdown(kInvalidDeviceID);
}

TEST(TestConnectivity_wakeup, WakeupSuccess)
{
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(oc_connectivity_ports_t));
  oc_connectivity_init(kDeviceID, ports);
  oc_connectivity_wakeup(kDeviceID);
  oc_connectivity_shutdown(kDeviceID);
}

TEST(TestConnectivity_wakeup, WakeupInvalidDevice)
{
  oc_connectivity_ports_t ports;
  memset(&ports, 0, sizeof(oc_connectivity_ports_t));
  oc_connectivity_init(kDeviceID, ports);
  oc_connectivity_wakeup(kInvalidDeviceID);
  oc_connectivity_shutdown(kDeviceID);
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
  EXPECT_EQ(
    0, oc_remove_network_interface_event_callback(interface_event_handler));
}

TEST_F(TestConnectivity, oc_remove_network_interface_event_callback_fail)
{
  EXPECT_EQ(
    -1, oc_remove_network_interface_event_callback(interface_event_handler));
}

#ifdef OC_NETWORK_MONITOR
TEST_F(TestConnectivity, handle_network_interface_event_callback)
{
  oc_add_network_interface_event_callback(interface_event_handler);
  handle_network_interface_event_callback(NETWORK_INTERFACE_UP);
  EXPECT_EQ(true, is_callback_received);
}
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SESSION_EVENTS

static void
session_event_handler(const oc_endpoint_t *ep, oc_session_state_t state)
{
  EXPECT_NE(nullptr, ep);
  EXPECT_EQ(OC_SESSION_CONNECTED, state);
  TestConnectivity::is_callback_received.store(true);
}

TEST_F(TestConnectivity, oc_add_session_event_callback_fail)
{
  EXPECT_EQ(-1, oc_add_session_event_callback(nullptr));

#ifndef OC_DYNAMIC_ALLOCATION
  for (int i = 0; i < OC_MAX_SESSION_EVENT_CBS; ++i) {
    EXPECT_EQ(0, oc_add_session_event_callback(session_event_handler));
  }
  EXPECT_EQ(-1, oc_add_session_event_callback(session_event_handler));
#endif /* !OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestConnectivity, oc_add_session_event_callback)
{
  EXPECT_EQ(0, oc_add_session_event_callback(session_event_handler));
}

TEST_F(TestConnectivity, oc_remove_session_event_callback_fail)
{
  EXPECT_EQ(-1, oc_remove_session_event_callback(nullptr));
  EXPECT_EQ(-1, oc_remove_session_event_callback(session_event_handler));
}

TEST_F(TestConnectivity, oc_remove_session_event_callback)
{
  ASSERT_EQ(0, oc_add_session_event_callback(session_event_handler));
  int ret = oc_remove_session_event_callback(session_event_handler);
  EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, handle_session_event_callback)
{
  ASSERT_EQ(0, oc_add_session_event_callback(session_event_handler));
  oc_endpoint_t ep{};
  handle_session_event_callback(&ep, OC_SESSION_CONNECTED);
  EXPECT_EQ(true, is_callback_received);
}

TEST_F(TestConnectivity, oc_add_session_event_callback_v1_fail)
{
  EXPECT_EQ(-1, oc_add_session_event_callback_v1(nullptr, nullptr));
}

TEST_F(TestConnectivity, oc_add_session_event_callback_v1)
{
  auto empty_cb = [](const oc_endpoint_t *, oc_session_state_t, void *) {
    // no-op, just need a non-nil function
  };
  EXPECT_EQ(0, oc_add_session_event_callback_v1(empty_cb, nullptr));
}

TEST_F(TestConnectivity, handle_session_event_callback_find)
{
  auto empty_cb_v0_1 = [](const oc_endpoint_t *, oc_session_state_t) {
    // no-op, just need a unique memory address
  };
  ASSERT_EQ(0, oc_add_session_event_callback(empty_cb_v0_1));

  auto empty_cb_v1_1 = [](const oc_endpoint_t *, oc_session_state_t, void *) {
    // no-op, just need a unique memory address
  };
  char c1{};
  ASSERT_EQ(0, oc_add_session_event_callback_v1(empty_cb_v1_1, &c1));

#ifdef OC_DYNAMIC_ALLOCATION
  auto empty_cb_v0_2 = [](const oc_endpoint_t *, oc_session_state_t) {
    // no-op, just need a unique memory address
  };
  ASSERT_EQ(0, oc_add_session_event_callback(empty_cb_v0_2));

  auto empty_cb_v1_2 = [](const oc_endpoint_t *, oc_session_state_t, void *) {
    // no-op, just need a unique memory address
  };
  char c2{};
  ASSERT_EQ(0, oc_add_session_event_callback_v1(empty_cb_v1_2, &c2));
#endif /* OC_DYNAMIC_ALLOCATION */

  auto empty_cb_v0_3 = [](const oc_endpoint_t *, oc_session_state_t) {
    // no-op, just need a unique memory address
  };

  auto empty_cb_v1_3 = [](const oc_endpoint_t *, oc_session_state_t, void *) {
    // no-op, just need a unique memory address
  };

  EXPECT_EQ(nullptr, oc_session_event_callback_find(
                       oc_session_event_versioned_handler(empty_cb_v0_3),
                       nullptr, true));
  EXPECT_EQ(nullptr, oc_session_event_callback_find(
                       oc_session_event_versioned_handler_v1(empty_cb_v1_3),
                       nullptr, true));

  // v0
  oc_session_event_cb_t *cb = oc_session_event_callback_find(
    oc_session_event_versioned_handler(empty_cb_v0_1), nullptr, true);
  ASSERT_NE(nullptr, cb);
  EXPECT_EQ(empty_cb_v0_1, cb->vh.handler.v0);

#ifdef OC_DYNAMIC_ALLOCATION
  cb = oc_session_event_callback_find(
    oc_session_event_versioned_handler(empty_cb_v0_2), nullptr, true);
  ASSERT_NE(nullptr, cb);
  EXPECT_EQ(empty_cb_v0_2, cb->vh.handler.v0);
#endif /* OC_DYNAMIC_ALLOCATION */

  // v1
  cb = oc_session_event_callback_find(
    oc_session_event_versioned_handler_v1(empty_cb_v1_1), &c1, false);
  ASSERT_NE(nullptr, cb);
  EXPECT_EQ(empty_cb_v1_1, cb->vh.handler.v1);

#ifdef OC_DYNAMIC_ALLOCATION
  cb = oc_session_event_callback_find(
    oc_session_event_versioned_handler_v1(empty_cb_v1_2), &c1, false);
  EXPECT_EQ(nullptr, cb);

  cb = oc_session_event_callback_find(
    oc_session_event_versioned_handler_v1(empty_cb_v1_2), nullptr, true);
  EXPECT_NE(nullptr, cb);
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestConnectivity, oc_remove_session_event_callback_v1_fail)
{
  auto empty_cb = [](const oc_endpoint_t *, oc_session_state_t, void *) {
    // no-op, just need a unique memory address
  };

  EXPECT_EQ(-1, oc_remove_session_event_callback_v1(nullptr, nullptr, false));
  EXPECT_EQ(OC_ERR_SESSION_EVENT_HANDLER_NOT_FOUND,
            oc_remove_session_event_callback_v1(empty_cb, nullptr, false));
}

TEST_F(TestConnectivity, oc_remove_session_event_callback_v1)
{
  auto empty_cb = [](const oc_endpoint_t *, oc_session_state_t) {
    // no-op, just need a unique memory address
  };
  ASSERT_EQ(0, oc_add_session_event_callback(empty_cb));

  auto empty_cb1 = [](const oc_endpoint_t *, oc_session_state_t, void *) {
    // no-op, just need a unique memory address
  };

#ifdef OC_DYNAMIC_ALLOCATION
  auto empty_cb2 = [](const oc_endpoint_t *, oc_session_state_t, void *) {
    // no-op, just need a unique memory address
  };
#endif /* OC_DYNAMIC_ALLOCATION */

  bool d1{};
  bool d2{};
  ASSERT_EQ(0, oc_add_session_event_callback_v1(empty_cb1, &d1));
  EXPECT_NE(0, oc_remove_session_event_callback_v1(empty_cb1, nullptr, false));
  EXPECT_NE(0, oc_remove_session_event_callback_v1(empty_cb1, &d2, false));
  EXPECT_EQ(0, oc_remove_session_event_callback_v1(empty_cb1, &d1, true));

#ifdef OC_DYNAMIC_ALLOCATION
  ASSERT_EQ(0, oc_add_session_event_callback_v1(empty_cb2, &d2));
  ASSERT_EQ(0, oc_add_session_event_callback_v1(empty_cb2, nullptr));
  EXPECT_EQ(0, oc_remove_session_event_callback_v1(empty_cb2, nullptr, true));
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestConnectivity, handle_session_event_callback_v1)
{
  auto cb = [](const oc_endpoint_t *ep, oc_session_state_t state,
               void *user_data) {
    EXPECT_NE(nullptr, ep);
    EXPECT_EQ(OC_SESSION_CONNECTED, state);
    *static_cast<bool *>(user_data) = true;
  };

  bool invoked{};
  ASSERT_EQ(0, oc_add_session_event_callback_v1(cb, &invoked));
  oc_endpoint_t ep{};
  handle_session_event_callback(&ep, OC_SESSION_CONNECTED);
  EXPECT_EQ(true, invoked);
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

  void TearDown() override
  {
    oc::TestDevice::Reset();
    oc::TestDevice::StopServer();
  }

  static std::optional<oc_endpoint_t> findEndpoint(size_t device);

  static std::atomic<bool> is_callback_received;

#ifdef OC_DYNAMIC_ALLOCATION
  static oc_message_t *CreateTestUdpMsg(const std::vector<uint8_t> &data);
  static oc_message_t *CreateValidTestUdpMsg(void);
  static oc_message_t *CreateInvalidTestUdpMsg(void);
#endif /* OC_DYNAMIC_ALLOCATION */
};

std::atomic<bool> TestConnectivityWithServer::is_callback_received{ false };

std::optional<oc_endpoint_t>
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

  auto ep = oc::TestDevice::GetEndpoint(device, flags, 0);
  EXPECT_TRUE(ep.has_value());
  return ep;
}

#ifdef OC_DYNAMIC_ALLOCATION
oc_message_t *
TestConnectivityWithServer::CreateTestUdpMsg(const std::vector<uint8_t> &data)
{
  oc_message_t *msg = oc_allocate_message();
  msg->endpoint.flags = IPV6;
  memcpy(msg->data, &data[0], data.size());
  msg->length = data.size();
  return msg;
}

oc_message_t *
TestConnectivityWithServer::CreateValidTestUdpMsg(void)
{
  const std::vector<uint8_t> data = { 1 << COAP_HEADER_VERSION_POSITION, 2, 3,
                                      4 };
  return TestConnectivityWithServer::CreateTestUdpMsg(data);
}

oc_message_t *
TestConnectivityWithServer::CreateInvalidTestUdpMsg(void)
{
  const std::vector<uint8_t> data = { 0xff, 2, 3, 4 };
  return TestConnectivityWithServer::CreateTestUdpMsg(data);
}
#endif /* OC_DYNAMIC_ALLOCATION */

TEST_F(TestConnectivityWithServer, oc_connectivity_get_endpoints)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(kDeviceID);
  EXPECT_NE(nullptr, ep);
}

#ifdef OC_DYNAMIC_ALLOCATION

TEST_F(TestConnectivityWithServer, oc_network_receive_event_valid)
{
  // verify initial size of event queue
  size_t initialCount = oc_network_get_event_queue_length(kDeviceID);
  EXPECT_EQ(initialCount, 0);

  // add a valid udp message to the queue
  oc_message_t *message = TestConnectivityWithServer::CreateValidTestUdpMsg();
  message->endpoint.device = kDeviceID;
  oc_network_receive_event(message);

  // verify the queue contains new message
  size_t eventCount = oc_network_get_event_queue_length(kDeviceID);
  EXPECT_EQ(eventCount, 1);
}

TEST_F(TestConnectivityWithServer, oc_network_receive_event_invalid)
{
  // verify initial size of event queue
  size_t initialCount = oc_network_get_event_queue_length(kDeviceID);
  EXPECT_EQ(initialCount, 0);

  // try to add an invalid udp message to the queue
  oc_message_t *message = TestConnectivityWithServer::CreateInvalidTestUdpMsg();
  message->endpoint.device = kDeviceID;
  oc_network_receive_event(message);

  // verify the queue is still empty
  size_t eventCount = oc_network_get_event_queue_length(kDeviceID);
  EXPECT_EQ(eventCount, 0);
}

TEST_F(TestConnectivityWithServer, oc_network_get_event_queue_length)
{
  constexpr size_t kDeviceA = kDeviceID;
  constexpr size_t kDeviceB = kDeviceID + 1;

  size_t eventCountA = oc_network_get_event_queue_length(kDeviceA);
  EXPECT_EQ(eventCountA, 0);
  size_t eventCountB = oc_network_get_event_queue_length(kDeviceB);
  EXPECT_EQ(eventCountB, 0);

  // add valid messages for kDeviceA and kDeviceB
  oc_message_t *messageA = TestConnectivityWithServer::CreateValidTestUdpMsg();
  messageA->endpoint.device = kDeviceA;
  oc_network_receive_event(messageA);
  oc_message_t *messageB = TestConnectivityWithServer::CreateValidTestUdpMsg();
  messageB->endpoint.device = kDeviceB;
  oc_network_receive_event(messageB);

  // verify msg count for kDeviceA and kDeviceB
  eventCountA = oc_network_get_event_queue_length(kDeviceA);
  EXPECT_EQ(eventCountA, 1);
  eventCountB = oc_network_get_event_queue_length(kDeviceB);
  EXPECT_EQ(eventCountB, 1);
}

TEST_F(TestConnectivityWithServer, oc_network_drop_receive_events)
{
  size_t eventCount = oc_network_get_event_queue_length(kDeviceID);
  EXPECT_EQ(eventCount, 0);

  // add max allowed amount of messages defined by
  // OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS
  for (size_t i = 0; i < OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS; ++i) {
    oc_message_t *message = TestConnectivityWithServer::CreateValidTestUdpMsg();
    message->endpoint.device = kDeviceID;
    oc_network_receive_event(message);
  }

  // verify all messages are in the queue
  eventCount = oc_network_get_event_queue_length(kDeviceID);
  EXPECT_EQ(eventCount, OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS);

  // remove all messages specified by endpoint
  oc_endpoint_t defaultEndPoint;
  memset(&defaultEndPoint, 0, sizeof(oc_endpoint_t));
  oc_message_t *message = TestConnectivityWithServer::CreateValidTestUdpMsg();
  defaultEndPoint = message->endpoint;
  size_t dropped = oc_network_drop_receive_events(&defaultEndPoint);
  oc_message_unref(message);

  // all messages are equeal -> verify they are all removed
  EXPECT_EQ(dropped, OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS);
  eventCount = oc_network_get_event_queue_length(kDeviceID);
  EXPECT_EQ(eventCount, 0);
}

#endif /* OC_DYNAMIC_ALLOCATION */

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
  auto epOpt = findEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  int ret = oc_tcp_connect(&ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_update_csm_state_P wait");
    oc::TestDevice::PoolEvents(10);
  }
#else  /* !OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, CSM_7_01);
  std::array<uint8_t, 8> payload{ "connect" };
  packet.payload = payload.data();
  packet.payload_len = payload.size();
  msg->length =
    coap_serialize_message(&packet, msg->data, oc_message_buffer_size(msg));

  oc_send_buffer(msg);
  ep.session_id = msg->endpoint.session_id;
  oc_message_unref(msg);
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#ifdef OC_TCP
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(&ep));
  ASSERT_NE(0, ep.session_id);
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_session_state(ep.session_id));
#endif /* OC_TCP */

  EXPECT_EQ(0, oc_tcp_update_csm_state(&ep, CSM_DONE));
  EXPECT_EQ(CSM_DONE, oc_tcp_get_csm_state(&ep));
}

TEST_F(TestConnectivityWithServer, oc_tcp_update_csm_state_N)
{
  auto epOpt = findEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  oc_tcp_update_csm_state(&ep, CSM_DONE);
  tcp_csm_state_t ret = oc_tcp_get_csm_state(&ep);
  EXPECT_NE(CSM_DONE, ret);
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
TEST_F(TestConnectivityWithServer, oc_tcp_connect_fail)
{
  oc_endpoint_t ep = oc::endpoint::FromString(
    "coaps+tcp://[ff02::158]:12345"); // unreachable address
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

#ifdef __linux__

// run on your linux machine:
// sudo ip6tables -I OUTPUT -p tcp --dport 12345 -j DROP

TEST_F(TestConnectivityWithServer, oc_tcp_connect_timeout)
{
  oc_endpoint_t ep = oc::endpoint::FromString(
    "coaps+tcp://[::1]:12345"); // reachable address, but inactive port
  // enough retries so they will run the whole duration of this test
  oc_tcp_set_connect_retry(0, 5);
  auto restore_defaults = []() {
    oc_tcp_set_connect_retry(OC_TCP_CONNECT_RETRY_MAX_COUNT,
                             OC_TCP_CONNECT_RETRY_TIMEOUT);
  };

  int ret = oc_tcp_connect(&ep, on_tcp_connect_timeout, this);
  if (ret == -1) {
    // sometimes on GitHub runner the network thread manages to execute all the
    // retries before the main thread runs again, which breaks the test, we
    // cannot guarantee the order of execution so we just exit
    restore_defaults();
    return;
  }

  ASSERT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, ret);

  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_NOT_CONNECTED, oc_send_buffer2(msg, false));
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, oc_tcp_connection_state(&ep));
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  EXPECT_EQ(OC_SEND_MESSAGE_QUEUED, oc_send_buffer2(msg, true));

  OC_DBG("oc_tcp_connect_timeout wait");
  oc::TestDevice::PoolEvents(10);

  EXPECT_EQ(-1, oc_tcp_connection_state(&ep));
  oc_message_unref(msg);

  restore_defaults();
}

TEST_F(TestConnectivityWithServer, oc_tcp_cleanup_waiting_session)
{
  auto addr = "coap+tcp://[::1]:12345";
  oc_endpoint_t ep1 =
    oc::endpoint::FromString(addr); // reachable address, but inactive port

  oc_tcp_connect_result_t ret1 =
    oc_tcp_connect_to_endpoint(&ep1, nullptr, nullptr);
  ASSERT_EQ(0, ret1.error);
  ASSERT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, ret1.state);
  ASSERT_NE(0, ret1.session_id);

  // disconnect is asynchronous, we should be able to open a new session to
  // the same endpoint
  oc_close_session(&ep1);

  oc_endpoint_t ep2 = oc::endpoint::FromString(addr);
  oc_tcp_connect_result_t ret2 =
    oc_tcp_connect_to_endpoint(&ep2, nullptr, nullptr);
  ASSERT_EQ(0, ret2.error);
  ASSERT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, ret2.state);
  ASSERT_NE(0, ret2.session_id);

  oc::TestDevice::PoolEventsMsV1(20ms);

  EXPECT_EQ(-1, oc_tcp_session_state(ret1.session_id));
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTING,
            oc_tcp_session_state(ret2.session_id));
}

#endif /* __linux__ */

TEST_F(TestConnectivityWithServer, oc_tcp_connect_repeat_fail)
{
  auto epOpt = findEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  int ret = oc_tcp_connect(&ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_connect_repeat_fail wait");
    oc::TestDevice::PoolEvents(10);
  }
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(&ep));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_EXISTS_CONNECTED,
            oc_tcp_connect(&ep, nullptr, this));
}

TEST_F(TestConnectivityWithServer, oc_tcp_connecting_repeat_fail)
{
  oc_endpoint_t ep = oc::endpoint::FromString(
    "coaps+tcp://[::1]:12345"); // reachable address, but inactive port
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, oc_tcp_connect(&ep, nullptr, this));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_EXISTS_CONNECTING,
            oc_tcp_connect(&ep, nullptr, this));
}

/** create a TCP session, wait for it to connect and send data */
TEST_F(TestConnectivityWithServer, oc_tcp_send_buffer2)
{
  auto epOpt = findEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  int ret = oc_tcp_connect(&ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_send_buffer2 wait");
    oc::TestDevice::PoolEvents(5);
  }
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(&ep));

  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, CSM_7_01);
  std::array<uint8_t, 5> payload{ "test" };
  packet.payload = payload.data();
  packet.payload_len = payload.size();

  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  msg->length =
    coap_serialize_message(&packet, msg->data, oc_message_buffer_size(msg));

  EXPECT_EQ(msg->length, oc_send_buffer2(msg, false));
  oc_message_unref(msg);
}

/** fail sending a message to an address without an ongoing or waiting TCP
 * session */
TEST_F(TestConnectivityWithServer, oc_tcp_send_buffer2_not_connected)
{
  oc_endpoint_t ep = oc::endpoint::FromString("coaps+tcp://[ff02::158]:12345");
  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_NOT_CONNECTED, oc_send_buffer2(msg, true));

#ifdef OC_IPV4
  oc_endpoint_t ep_ipv4 = oc::endpoint::FromString("coaps+tcp://1.1.1.1:12345");
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

  oc_endpoint_t ep =
    oc::endpoint::FromString("coap+tcp://openconnectivity.org:3456");
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
