/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "utility.h"

#include "api/oc_events_internal.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Clock.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_process_internal.h"

#include <chrono>
#include <functional>
#include <gtest/gtest.h>

OC_PROCESS(oc_test_process, "Testing process");

using namespace std::chrono_literals;

class TestEventTimer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_clock_init();
    oc::SetTestStartTime();
    oc_process_init();
    oc_event_assign_oc_process_events();
    oc_process_start(&oc_etimer_process, nullptr);
    oc_process_start(&oc_test_process, nullptr);
  }

  static void TearDownTestCase()
  {
    oc_process_exit(&oc_test_process);
    oc_process_exit(&oc_etimer_process);
    oc_process_shutdown();
  }

  static oc_clock_time_t Poll()
  {
    oc_clock_time_t next_event = oc_etimer_request_poll();
    while (oc_process_run()) {
      next_event = oc_etimer_request_poll();
    }
    return next_event;
  }

  void SetUp() override { TestEventTimer::onEventTimer_ = nullptr; }

  void TearDown() override { oc::RestoreSystemTimeFromTestStartTime(); }

  static std::function<void(oc_etimer *etimer)> onEventTimer_;
};

std::function<void(oc_etimer *etimer)> TestEventTimer::onEventTimer_{};

OC_PROCESS_THREAD(oc_test_process, ev, data)
{
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&oc_test_process)) {
    OC_PROCESS_YIELD();

    OC_INFO("received event 0x%x", (int)ev);
    if (ev == OC_PROCESS_EVENT_TIMER) {
      if (TestEventTimer::onEventTimer_) {
        TestEventTimer::onEventTimer_(static_cast<oc_etimer *>(data));
      }
      continue;
    }
  }
  OC_PROCESS_END();
}

// Move the system time past the expiration time of the timer
//
// The timer shouldn't be affected by the changes to the system time and should
// expire only after the timer interval passes
TEST_F(TestEventTimer, ChangeSystemTimeForwards)
{
  oc_etimer et{};
  auto interval = oc::DurationToTicks(200ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process)

  oc_clock_time_t start = oc_clock_time();
  ASSERT_TRUE(oc::SetSystemTime(start, std::chrono::seconds{ 1 }));
  OC_INFO("time change");

  TestEventTimer::Poll();
  EXPECT_FALSE(oc_etimer_expired(&et));

  oc_clock_wait(interval + 10);
  TestEventTimer::Poll();
  EXPECT_TRUE(oc_etimer_expired(&et));
}

// Move the system time to the past
//
// The timer shouldn't be affected by the changes to the system time and should
// expire after the given interval passes regardless of the absolute time
TEST_F(TestEventTimer, ChangeSystemTimeBackwards)
{
  oc_etimer et{};
  auto interval = oc::DurationToTicks(200ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process)

  oc_clock_time_t start = oc_clock_time();
  ASSERT_TRUE(oc::SetSystemTime(start, std::chrono::seconds{ -1 }));
  OC_INFO("time change");

  TestEventTimer::Poll();
  ASSERT_FALSE(oc_etimer_expired(&et));

  oc_clock_wait(interval + 10);
  TestEventTimer::Poll();
  EXPECT_TRUE(oc_etimer_expired(&et));
}
