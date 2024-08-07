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

#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "util/oc_timer_internal.h"

#include "tests/gtest/Clock.h"

#include "gtest/gtest.h"

#include <inttypes.h>

using namespace std::chrono_literals;

class TestTimer : public testing::Test {
public:
  static void SetUpTestCase() { oc_clock_init(); }
};

TEST_F(TestTimer, Expired)
{
  oc_timer timer{};
  oc_clock_time_t interval = oc::DurationToTicks(10ms);
  oc_timer_set(&timer, interval);

  EXPECT_FALSE(oc_timer_expired(&timer));
  oc_clock_wait(interval + interval / 2);
  EXPECT_TRUE(oc_timer_expired(&timer));
}

TEST_F(TestTimer, Remaining)
{
  oc_timer timer{};
  oc_clock_time_t interval = oc::DurationToTicks(10ms);
  oc_timer_set(&timer, interval);

  EXPECT_LT(0, oc_timer_remaining(&timer));
  oc_clock_wait(interval + interval / 2);
  EXPECT_EQ(0, oc_timer_remaining(&timer));
}

TEST_F(TestTimer, Restart)
{
  oc_timer timer{};
  oc_clock_time_t interval = oc::DurationToTicks(10ms);
  oc_timer_set(&timer, interval);

  oc_clock_wait(interval * 2);
  EXPECT_TRUE(oc_timer_expired(&timer));
  oc_clock_time_t exp1 = oc_timer_expiration_time(&timer);
  oc_timer_restart(&timer);
  oc_clock_time_t exp2 = oc_timer_expiration_time(&timer);
  EXPECT_LT(exp1, exp2);
  EXPECT_FALSE(oc_timer_expired(&timer));
  oc_clock_wait(interval + interval / 2);
  EXPECT_TRUE(oc_timer_expired(&timer));
}

TEST_F(TestTimer, Reset)
{
  oc_timer timer{};
  oc_clock_time_t interval = oc::DurationToTicks(20ms);
  oc_timer_set(&timer, interval);

  oc_clock_wait(interval * 3);
  EXPECT_TRUE(oc_timer_expired(&timer));
  oc_clock_time_t exp1 = oc_timer_expiration_time(&timer);
  oc_timer_reset(&timer);
  oc_clock_time_t exp2 = oc_timer_expiration_time(&timer);
  EXPECT_LT(exp1, exp2);
  // multiple expiration intervals passed so a single reset is not enough
  EXPECT_TRUE(oc_timer_expired(&timer));
  while (oc_timer_expired(&timer)) {
    oc_timer_reset(&timer);
  }
  // ensure that timer doesn't expire before the test gets evaluated
  oc_timer_reset(&timer);
  EXPECT_FALSE(oc_timer_expired(&timer));
}
