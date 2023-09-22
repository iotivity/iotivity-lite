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
#include "oc_buffer.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_process.h"
#include "util/oc_process_internal.h"

#include "tests/gtest/Clock.h"

#include <chrono>
#include <functional>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <memory>
#include <vector>

OC_PROCESS(oc_test_process_1, "Testing process 1");
OC_PROCESS(oc_test_process_2, "Testing process 2");

using namespace std::chrono_literals;

class TestEventTimer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_clock_init();
    oc_process_init();
    oc_event_assign_oc_process_events();
    oc_process_start(&oc_etimer_process, nullptr);
    oc_process_start(&oc_test_process_1, nullptr);
    oc_process_start(&oc_test_process_2, nullptr);
  }

  static void TearDownTestCase()
  {
    oc_process_exit(&oc_test_process_2);
    oc_process_exit(&oc_test_process_1);
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

  static std::function<void(oc_etimer *etimer)> onEventTimer_;
};

std::function<void(oc_etimer *etimer)> TestEventTimer::onEventTimer_{};

OC_PROCESS_THREAD(oc_test_process_1, ev, data)
{
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&oc_test_process_1)) {
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

OC_PROCESS_THREAD(oc_test_process_2, ev, data)
{
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&oc_test_process_2)) {
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

TEST_F(TestEventTimer, Set)
{
  oc_etimer et{};
  auto interval = oc::DurationToTicks(10ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  EXPECT_GE(oc_timer_now(), oc_etimer_start_time(&et));
  EXPECT_EQ(oc_etimer_start_time(&et) + interval,
            oc_etimer_expiration_time(&et));

  // clean-up
  oc_etimer_stop(&et);
}

TEST_F(TestEventTimer, MultipleSet)
{
  oc_etimer et1{};
  oc_etimer et2{};
  auto interval = oc::DurationToTicks(10ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et1, interval);
  oc_etimer_set(&et1, interval);
  oc_etimer_set(&et2, interval);
  oc_etimer_set(&et1, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  EXPECT_GE(oc_timer_now(), oc_etimer_start_time(&et1));
  EXPECT_EQ(oc_etimer_start_time(&et1) + interval,
            oc_etimer_expiration_time(&et1));

  // clean-up
  oc_etimer_stop(&et1);
  oc_etimer_stop(&et2);
}

#ifdef OC_TEST

TEST_F(TestEventTimer, ProcessTimeoutEvent)
{
  oc_etimer et{};
  auto interval = oc::DurationToTicks(1ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)
  // wait for timer to expire
  oc_clock_wait(2 * interval);

  int timeoutCount = 0;
  TestEventTimer::onEventTimer_ = [&timeoutCount](const oc_etimer *) {
    ++timeoutCount;
  };

  // fill the process event queue with junk events
  // for static allocated process event queue this means that the expired timer
  // won't be able to post OC_PROCESS_EVENT_TIMER currently, but it should be
  // retried and succeed eventually
  oc_process_num_events_t size = oc_process_num_events();
  for (size_t i = 0; i < size; ++i) {
    oc_process_post(&oc_etimer_process, OC_PROCESS_EVENT_CONTINUE, nullptr);
  }
  ASSERT_GE(size + 1, oc_process_nevents());

  while (oc_process_run() != 0) {
    oc_clock_wait(oc::DurationToTicks(1ms));
  }
  EXPECT_EQ(1, timeoutCount);
}

#endif /* OC_TEST */

// all timers associated with exited process should be removed
TEST_F(TestEventTimer, CleanUpExitedProcess)
{
  oc_etimer et1{};
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et1, oc::DurationToTicks(1ms));
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  oc_etimer et2{};
  oc_etimer et3{};
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_2)
  oc_etimer_set(&et2, oc::DurationToTicks(1ms));
  oc_etimer_set(&et3, oc::DurationToTicks(1ms));
  OC_PROCESS_CONTEXT_END(&oc_test_process_2)

  oc_etimer et4{};
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et4, oc::DurationToTicks(1ms));
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  oc_etimer et5{};
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_2)
  oc_etimer_set(&et5, oc::DurationToTicks(1ms));
  OC_PROCESS_CONTEXT_END(&oc_test_process_2)

  // et2, et3 and et5 should be removed
  oc_process_exit(&oc_test_process_2);

  int timeoutCount = 0;
  TestEventTimer::onEventTimer_ = [&timeoutCount](const oc_etimer *) {
    ++timeoutCount;
  };

  oc_clock_time_t next_event;
  do {
    next_event = TestEventTimer::Poll();
    oc_clock_time_t now = oc_timer_now();
    oc_clock_time_t wait = 0;
    if (next_event > now) {
      wait = next_event - now;
    }
    oc_clock_wait(wait);
  } while (next_event > 0);

  // et1 and et4 should timeout
  EXPECT_EQ(2, timeoutCount);

  oc_etimer_stop(&et1);
  oc_etimer_stop(&et4);
  // restore original state -> restart oc_test_process_2
  oc_process_start(&oc_test_process_2, nullptr);
}

TEST_F(TestEventTimer, TimersPending)
{
  EXPECT_FALSE(oc_etimer_pending());

  oc_etimer et1{};
  oc_etimer et2{};
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et1, oc::DurationToTicks(10ms));
  oc_etimer_set(&et2, oc::DurationToTicks(50ms));
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  EXPECT_TRUE(oc_etimer_pending());
  oc_clock_wait(
    oc_timer_remaining(&et1.timer) +
    oc::DurationToTicks(2ms)); // +10ms to be sure that the timer is invoked
  EXPECT_LT(0, TestEventTimer::Poll());
  EXPECT_TRUE(oc_etimer_pending());

  oc_etimer_stop(&et2);
  EXPECT_FALSE(oc_etimer_pending());
}

TEST_F(TestEventTimer, TimersNextExpirationTime)
{
  oc_etimer et1{};
  oc_etimer et2{};
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et1, oc::DurationToTicks(20ms));
  oc_etimer_set(&et2, oc::DurationToTicks(10ms));
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  oc_clock_time_t et2_exp = oc_timer_remaining(&et2.timer);
  ASSERT_NE(static_cast<oc_clock_time_t>(-1), et2_exp);
  oc_clock_time_t now = oc_timer_now();
  // et2 is expiring sooner, so the next expiration time should be based on et2
  oc_clock_time_t exp1 = oc_etimer_next_expiration_time();
  EXPECT_LE(exp1, now + et2_exp);

  oc_etimer_stop(&et2);
  // after stopping et2 it should be recalcuated based on et1
  oc_clock_time_t exp2 = oc_etimer_next_expiration_time();
  EXPECT_GT(exp2, exp1);

  now = oc_timer_now();
  ASSERT_GT(exp2, now);
  oc_clock_wait(exp2 - now + oc::DurationToTicks(2ms));

  EXPECT_LT(0, TestEventTimer::Poll());
  EXPECT_EQ(0, oc_etimer_next_expiration_time());

  oc_etimer_stop(&et1);
}

TEST_F(TestEventTimer, Reset)
{
  oc_etimer et{};
  oc_clock_time_t interval = oc::DurationToTicks(20ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  TestEventTimer::Poll();
  ASSERT_FALSE(oc_etimer_expired(&et));

  oc_clock_wait(interval + interval / 2);
  TestEventTimer::Poll();
  ASSERT_TRUE(oc_etimer_expired(&et));
  ASSERT_FALSE(oc_etimer_pending());

  oc_clock_time_t exp_next_expiration =
    oc_etimer_expiration_time(&et) + interval;
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_reset(&et);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)
  EXPECT_FALSE(oc_etimer_expired(&et));
  EXPECT_TRUE(oc_etimer_pending());
  EXPECT_EQ(exp_next_expiration, oc_etimer_expiration_time(&et));

  oc_etimer_stop(&et);
}

TEST_F(TestEventTimer, ResetWithNewInterval)
{
  oc_etimer et{};
  oc_clock_time_t interval = oc::DurationToTicks(20ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  TestEventTimer::Poll();
  ASSERT_FALSE(oc_etimer_expired(&et));

  oc_clock_wait(interval + interval / 2);
  TestEventTimer::Poll();
  ASSERT_TRUE(oc_etimer_expired(&et));
  ASSERT_FALSE(oc_etimer_pending());

  oc_clock_time_t new_interval = oc::DurationToTicks(420ms);
  oc_clock_time_t exp_next_expiration =
    oc_etimer_expiration_time(&et) + new_interval;
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_reset_with_new_interval(&et, new_interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)
  EXPECT_FALSE(oc_etimer_expired(&et));
  EXPECT_TRUE(oc_etimer_pending());
  EXPECT_EQ(exp_next_expiration, oc_etimer_expiration_time(&et));

  oc_etimer_stop(&et);
}

TEST_F(TestEventTimer, Restart)
{
  oc_etimer et{};
  oc_clock_time_t interval = oc::DurationToTicks(20ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  TestEventTimer::Poll();
  ASSERT_FALSE(oc_etimer_expired(&et));

  oc_clock_wait(interval + interval / 2);
  TestEventTimer::Poll();
  ASSERT_TRUE(oc_etimer_expired(&et));
  ASSERT_FALSE(oc_etimer_pending());

  oc_clock_time_t exp_next_expiration =
    oc_etimer_expiration_time(&et) + interval;
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_restart(&et);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)
  EXPECT_FALSE(oc_etimer_expired(&et));
  EXPECT_TRUE(oc_etimer_pending());
  EXPECT_LT(exp_next_expiration, oc_etimer_expiration_time(&et));

  oc_etimer_stop(&et);
}

TEST_F(TestEventTimer, Adjust)
{
  oc_etimer et{};
  oc_clock_time_t interval = oc::DurationToTicks(20ms);
  OC_PROCESS_CONTEXT_BEGIN(&oc_test_process_1)
  oc_etimer_set(&et, interval);
  OC_PROCESS_CONTEXT_END(&oc_test_process_1)

  oc_clock_time_t next = TestEventTimer::Poll();
  oc_etimer_adjust(&et, static_cast<int>(interval));
  oc_clock_time_t next_adjusted = TestEventTimer::Poll();
  EXPECT_LT(next, next_adjusted);

  oc_etimer_stop(&et);
}
