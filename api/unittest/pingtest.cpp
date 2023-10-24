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

#if defined(OC_CLIENT) && defined(OC_TCP)

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_event_callback_internal.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "tests/gtest/Device.h"
#include "util/oc_process.h"

#include <chrono>
#include <gtest/gtest.h>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };

class TestPingWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  static void dropOutgoingMessages()
  {
    OC_PROCESS_NAME(oc_message_buffer_handler);
    oc_process_drop(
      &oc_message_buffer_handler,
      [](oc_process_event_t, oc_process_data_t data, const void *) {
        auto *message = static_cast<oc_message_t *>(data);
        oc_message_unref(message);
        return true;
      },
      nullptr);
  }

  void TearDown() override
  {
    dropOutgoingMessages();
    oc_event_callbacks_shutdown();
    oc_client_cbs_shutdown();
  }
};

TEST_F(TestPingWithServer, Ping_InvalidInput)
{
  // invalid endpoint
  ASSERT_FALSE(oc_send_ping(
    true, nullptr, 0,
    [](oc_client_response_t *) {
      // no-op
    },
    nullptr));

  // invalid handler
  oc_endpoint_t endpoint{};
  ASSERT_FALSE(oc_send_ping(true, &endpoint, 0, nullptr, nullptr));
}

TEST_F(TestPingWithServer, Ping_NonTCPEndpoint)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, 0, TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  ASSERT_FALSE(oc_send_ping(
    true, &ep, 0,
    [](oc_client_response_t *) {
      // no-op
    },
    nullptr));
}

TEST_F(TestPingWithServer, Ping)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_send_ping(
    true, &ep, timeout.count(),
    [](oc_client_response_t *data) {
      oc::TestDevice::Terminate();
      EXPECT_EQ(data->code, OC_STATUS_OK);
      *static_cast<bool *>(data->user_data) = true;
    },
    &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestPingWithServer, PingTimeout)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_send_ping(
    true, &ep, timeout.count(),
    [](oc_client_response_t *data) {
      oc::TestDevice::Terminate();
      EXPECT_EQ(data->code, OC_PING_TIMEOUT);
      *static_cast<bool *>(data->user_data) = true;
    },
    &invoked));

  // drop the outgoing ping message, so that the server does not respond
  dropOutgoingMessages();

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

TEST_F(TestPingWithServer, Ping_FailRequestAllocation)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto timeout = 1s;
  // outgoing messages are limited to OC_MAX_NUM_CONCURRENT_REQUESTS
  for (size_t i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS; ++i) {
    ASSERT_TRUE(oc_send_ping(
      false, &ep, timeout.count(),
      [](oc_client_response_t *) {
        // no-op
      },
      nullptr));
  }

  EXPECT_FALSE(oc_send_ping(
    false, &ep, timeout.count(),
    [](oc_client_response_t *) {
      // no-op
    },
    nullptr));
}

TEST_F(TestPingWithServer, Ping_FailResponseAllocation)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto timeout = 1s;
  // oc_client_cb_s are limited to OC_MAX_NUM_CONCURRENT_REQUESTS+1
  for (size_t i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS + 1; ++i) {
    ASSERT_TRUE(oc_send_ping(
      false, &ep, timeout.count(),
      [](oc_client_response_t *) {
        // no-op
      },
      nullptr));

    // free up requests allocation
    dropOutgoingMessages();
  }
  EXPECT_FALSE(oc_send_ping(
    false, &ep, timeout.count(),
    [](oc_client_response_t *) {
      // no-op
    },
    nullptr));
}

#endif /* !OC_DYNAMIC_ALLOCATION */

#endif /* OC_CLIENT && OC_TCP */
