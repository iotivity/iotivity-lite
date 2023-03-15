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

#include "port/oc_clock.h"

#include <cstdlib>
#include <gtest/gtest.h>
#include <string>

class TestClock : public testing::Test {
public:
  static void SetUpTestCase() { oc_clock_init(); }
};

TEST_F(TestClock, oc_clock_time)
{
  oc_clock_time_t timestamp = oc_clock_time();
  EXPECT_NE(0, timestamp);
}

TEST_F(TestClock, oc_clock_time_monotonic)
{
  auto t1 = oc_clock_time_monotonic();
  ASSERT_NE(0, t1);
  auto t2 = oc_clock_time_monotonic();
  ASSERT_NE(0, t2);
  EXPECT_LE(t1, t2);

  t1 = oc_clock_time_monotonic();
  auto wait_time = static_cast<oc_clock_time_t>(0.421337 * OC_CLOCK_SECOND);
  oc_clock_wait(wait_time);
  t2 = oc_clock_time_monotonic();

  oc_clock_time_t ticks = (t2 - t1);
  EXPECT_LE(wait_time, ticks);

  double delta = (100 * (OC_CLOCK_SECOND / 1e03)); // 100ms in ticks
  EXPECT_GT(wait_time + delta, ticks);
}

TEST_F(TestClock, oc_clock_seconds)
{
  long time_seconds = oc_clock_seconds();
  EXPECT_NE(0, time_seconds);
}

TEST_F(TestClock, oc_clock_wait)
{
  oc_clock_time_t wait_time = 1 * OC_CLOCK_SECOND;
  oc_clock_time_t prev_stamp = oc_clock_time();
  oc_clock_wait(wait_time);
  oc_clock_time_t cur_stamp = oc_clock_time();

  int seconds = (cur_stamp - prev_stamp) / OC_CLOCK_SECOND;
  EXPECT_EQ(1, seconds);
}
