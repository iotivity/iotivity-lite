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

#include "messaging/coap/coap.h"
#include "messaging/coap/coap_signal.h"
#include "port/oc_connectivity.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_atomic.h"
#include "util/oc_features.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_network_monitor.h"
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <gtest/gtest.h>
#include <pthread.h>
#include <string>

static const size_t g_device = 0;

class TestConnectivity : public testing::Test {
public:
  static pthread_mutex_t s_mutex;
  static pthread_cond_t s_cv;
  static oc_handler_t s_handler;
  static std::atomic<bool> s_terminate;
  static std::atomic<bool> s_is_callback_received;

  static int appInit(void) { return 0; }

  static void signalEventLoop(void) { pthread_cond_signal(&s_cv); }

  static oc_event_callback_retval_t quitEvent(void *)
  {
    s_terminate.store(true);
    return OC_EVENT_DONE;
  }

  static void poolEvents(uint16_t seconds)
  {
    s_terminate.store(false);
    oc_set_delayed_callback(nullptr, quitEvent, seconds);

    while (!s_terminate) {
      pthread_mutex_lock(&s_mutex);
      oc_clock_time_t next_event = oc_main_poll();
      if (s_terminate) {
        pthread_mutex_unlock(&s_mutex);
        break;
      }
      if (next_event == 0) {
        pthread_cond_wait(&s_cv, &s_mutex);
      } else {
        struct timespec ts;
        ts.tv_sec = (next_event / OC_CLOCK_SECOND);
        ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
        pthread_cond_timedwait(&s_cv, &s_mutex, &ts);
      }
      pthread_mutex_unlock(&s_mutex);
    }
  }

protected:
  void SetUp() override
  {
    s_is_callback_received.store(false);
    s_terminate.store(false);
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(0, oc_connectivity_init(g_device));
  }

  void TearDown() override
  {
    oc_connectivity_shutdown(g_device);
    oc_main_shutdown();
  }

public:
  static oc_endpoint_t *findEndpoint(size_t device);
  static oc_endpoint_t createEndpoint(const std::string &ep_str);
};

pthread_mutex_t TestConnectivity::s_mutex;
pthread_cond_t TestConnectivity::s_cv;
oc_handler_t TestConnectivity::s_handler;
std::atomic<bool> TestConnectivity::s_terminate{ false };
std::atomic<bool> TestConnectivity::s_is_callback_received{ false };

oc_endpoint_t *
TestConnectivity::findEndpoint(size_t device)
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

  oc_endpoint_t *ep = oc_connectivity_get_endpoints(device);
  while (ep != nullptr) {
    if (flags == 0 || (ep->flags & flags) == flags) {
      break;
    }
    ep = ep->next;
  }
  EXPECT_NE(nullptr, ep);
  return ep;
}

oc_endpoint_t
TestConnectivity::createEndpoint(const std::string &ep_str)
{
  oc_string_t ep_ocstr;
  oc_new_string(&ep_ocstr, ep_str.c_str(), ep_str.length());
  oc_endpoint_t ep;
  int ret = oc_string_to_endpoint(&ep_ocstr, &ep, nullptr);
  oc_free_string(&ep_ocstr);
  EXPECT_EQ(0, ret) << "cannot convert endpoint " << ep_str;
  return ep;
}

TEST(TestConnectivity_init, oc_connectivity_init)
{
  int ret = oc_connectivity_init(g_device);
  EXPECT_EQ(0, ret);
  oc_connectivity_shutdown(g_device);
}

TEST_F(TestConnectivity, oc_connectivity_get_endpoints)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(g_device);
  EXPECT_NE(nullptr, ep);
}

static void
interface_event_handler(oc_interface_event_t event)
{
  EXPECT_EQ(NETWORK_INTERFACE_UP, event);
  TestConnectivity::s_is_callback_received.store(true);
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
  EXPECT_EQ(true, s_is_callback_received);
}
#endif /* OC_NETWORK_MONITOR */

static void
session_event_handler(const oc_endpoint_t *ep, oc_session_state_t state)
{
  EXPECT_NE(nullptr, ep);
  EXPECT_EQ(OC_SESSION_CONNECTED, state);
  TestConnectivity::s_is_callback_received.store(true);
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
  oc_endpoint_t ep;
  handle_session_event_callback(&ep, OC_SESSION_CONNECTED);
  EXPECT_EQ(true, s_is_callback_received);
}
#endif /* OC_SESSION_EVENTS */

#ifdef OC_TCP
TEST_F(TestConnectivity, oc_tcp_get_csm_state_P)
{
  oc_endpoint_t ep;
  tcp_csm_state_t ret = oc_tcp_get_csm_state(&ep);

  EXPECT_EQ(CSM_NONE, ret);
}

TEST_F(TestConnectivity, oc_tcp_get_csm_state_N)
{
  tcp_csm_state_t ret = oc_tcp_get_csm_state(nullptr);

  EXPECT_EQ(CSM_ERROR, ret);
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
void
on_tcp_connect(const oc_endpoint_t *, int state, void *)
{
  OC_DBG("on_tcp_connect");
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, state);
  TestConnectivity::s_terminate.store(true);
}
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

TEST_F(TestConnectivity, oc_tcp_update_csm_state_P)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  int ret = oc_tcp_connect(ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_update_csm_state_P wait");
    poolEvents(10);
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

TEST_F(TestConnectivity, oc_tcp_update_csm_state_N)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
  ASSERT_NE(nullptr, ep);

  oc_tcp_update_csm_state(ep, CSM_DONE);

  tcp_csm_state_t ret = oc_tcp_get_csm_state(ep);

  EXPECT_NE(CSM_DONE, ret);
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
TEST_F(TestConnectivity, oc_tcp_connect_fail)
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
  TestConnectivity::s_is_callback_received.store(true);
  TestConnectivity::s_terminate.store(true);
}

TEST_F(TestConnectivity, oc_tcp_connect_timeout)
{
  oc_endpoint_t ep = createEndpoint(
    "coaps+tcp://[::1]:12345"); // reachable address, but inactive port
  oc_tcp_set_connect_retry(2, 2);
  // timeout 2s, 2 retries -> total 6s
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
  poolEvents(connect_timeout + 2); // +2 to be sure

  EXPECT_EQ(-1, oc_tcp_connection_state(&ep));
  oc_message_unref(msg);

  oc_tcp_set_connect_retry(OC_TCP_CONNECT_RETRY_MAX_COUNT,
                           OC_TCP_CONNECT_RETRY_TIMEOUT);
}

TEST_F(TestConnectivity, oc_tcp_connect_repeat_fail)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
  int ret = oc_tcp_connect(ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_connect_repeat_fail wait");
    poolEvents(10);
  }
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(ep));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_EXISTS_CONNECTED,
            oc_tcp_connect(ep, nullptr, this));
}

TEST_F(TestConnectivity, oc_tcp_connecting_repeat_fail)
{
  oc_endpoint_t ep = createEndpoint(
    "coaps+tcp://[::1]:12345"); // reachable address, but inactive port
  EXPECT_EQ(OC_TCP_SOCKET_STATE_CONNECTING, oc_tcp_connect(&ep, nullptr, this));
  EXPECT_EQ(OC_TCP_SOCKET_ERROR_EXISTS_CONNECTING,
            oc_tcp_connect(&ep, nullptr, this));
}

/** create a TCP session, wait for it to connect and send data */
TEST_F(TestConnectivity, oc_tcp_send_buffer2)
{
  oc_endpoint_t *ep = findEndpoint(g_device);
  int ret = oc_tcp_connect(ep, on_tcp_connect, this);
  EXPECT_LE(0, ret);
  if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
    OC_DBG("oc_tcp_send_buffer2 wait");
    poolEvents(5);
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
TEST_F(TestConnectivity, oc_tcp_send_buffer2_not_connected)
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
/** connecting to existing but not listening endpoint should timeout after 5
 * retries  */
TEST_F(TestConnectivity, oc_tcp_send_buffer2_drop)
{
  oc_endpoint_t ep = createEndpoint("coap+tcp://openconnectivity.org:3456");
  ASSERT_EQ(OC_TCP_SOCKET_STATE_CONNECTING,
            oc_tcp_connect(&ep, on_tcp_connect_timeout, this));

  while (!s_is_callback_received) {
    OC_DBG("oc_tcp_send_buffer2_drop wait");
    poolEvents(5);
  }
}
#endif /* OC_DNS_LOOKUP && (OC_DNS_LOOKUP_IPV6 || OC_IPV4) */

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
#endif /* OC_TCP */
