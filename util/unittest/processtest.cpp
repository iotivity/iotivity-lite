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

#include "api/oc_events_internal.h"
#include "api/oc_message_buffer_internal.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "util/oc_process.h"
#include "util/oc_process_internal.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

#include <chrono>
#include <gtest/gtest.h>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };

OC_PROCESS(test_process, "Testing process");

OC_PROCESS_THREAD(test_process, ev, data)
{
  (void)data;
  OC_PROCESS_POLLHANDLER([]() { OC_DBG("polling"); }());
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&test_process)) {
    OC_PROCESS_YIELD();
    OC_DBG("received event(%d)", (int)ev);
  }
  OC_PROCESS_END();
}

class TestProcess : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_process_init();
    oc_event_assign_oc_process_events();
  }

  static void TearDownTestCase()
  {
    oc_process_exit(&test_process);
    oc_process_shutdown();
  }
};

TEST_F(TestProcess, Start)
{
  EXPECT_EQ(0, oc_process_is_running(&test_process));

  oc_process_start(&test_process, nullptr);
  EXPECT_EQ(1, oc_process_is_running(&test_process));

  // multiple starts are ignored
  oc_process_start(&test_process, nullptr);
  EXPECT_EQ(1, oc_process_is_running(&test_process));

  oc_process_exit(&test_process);
  EXPECT_EQ(0, oc_process_is_running(&test_process));
}

#ifdef OC_SECURITY

TEST_F(TestProcess, IsClosingTLSSessions_F)
{
  EXPECT_FALSE(oc_process_is_closing_all_tls_sessions());
}

TEST_F(TestProcess, IsClosingTLSSessions)
{
  oc_message_buffer_handler_start();
  oc_close_all_tls_sessions_for_device_reset(kDeviceID);
  EXPECT_TRUE(oc_process_is_closing_all_tls_sessions());

  oc_message_buffer_handler_stop();
}

class TestProcessWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

TEST_F(TestProcessWithServer, IsClosingTLSSessionsOnForcedReset)
{
  ASSERT_FALSE(oc_process_is_closing_all_tls_sessions());

  ASSERT_TRUE(oc_reset_device_v1(kDeviceID, true));
  EXPECT_TRUE(oc_process_is_closing_all_tls_sessions());
  int repeats = 0;
  while (repeats < 100) {
    oc::TestDevice::PoolEventsMsV1(1ms);
    if (!oc_process_is_closing_all_tls_sessions()) {
      break;
    }
    ++repeats;
  }
  EXPECT_FALSE(oc_process_is_closing_all_tls_sessions());
}

#ifdef OC_TEST

TEST_F(TestProcessWithServer, IsClosingTLSSessionsOnDelayedReset)
{
  ASSERT_FALSE(oc_process_is_closing_all_tls_sessions());

  oc_pstat_set_reset_delay_ms(0);
  bool invoked = false;
  oc_set_factory_presets_cb(
    [](size_t, void *data) {
      *static_cast<bool *>(data) = true;
      EXPECT_TRUE(oc_process_is_closing_all_tls_sessions());
    },
    &invoked);

  ASSERT_TRUE(oc_reset_device_v1(kDeviceID, false));

  ASSERT_TRUE(oc_reset_in_progress(kDeviceID));
  oc::TestDevice::PoolEventsMsV1(1ms);
  ASSERT_FALSE(oc_reset_in_progress(kDeviceID));
  EXPECT_TRUE(invoked);

  // restore defaults
  oc_set_factory_presets_cb(nullptr, nullptr);
  oc_pstat_set_reset_delay_ms(OC_PSTAT_RESET_DELAY_MS);
}

#endif /* OC_TEST */

#endif /* OC_SECURITY */
