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

#include "port/oc_clock.h"
#include "port/oc_log_internal.h"

#include <chrono>
#include <gtest/gtest.h>

class TestClock : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_clock_init();
    oc::SetTestStartTime();
  }

  void TearDown() override { oc::RestoreSystemTimeFromTestStartTime(); }
};

#if defined(__unix__) || defined(_WIN32)

TEST_F(TestClock, MonotonicTime)
{
  OC_INFO("start");
  oc_clock_time_t start_mt = oc_clock_time_monotonic();
  oc_clock_time_t start = oc_clock_time();

  // go 5 secs in the past
  ASSERT_TRUE(oc::SetSystemTime(start, std::chrono::seconds{ -5 }));
  OC_INFO("time change");

  // wait two seconds
  oc_clock_time_t delay = 2 * OC_CLOCK_SECOND;
  oc_clock_wait(delay);

  oc_clock_time_t end_mt = oc_clock_time_monotonic();
  oc_clock_time_t end = oc_clock_time();

  // elapsed time based on system time should be negative
  OC_INFO("start: %" PRIu64 ", end: %" PRIu64, start, end);
  int64_t elapsed = static_cast<int64_t>(end) - start;
  EXPECT_GT(0, elapsed);

  // elapsed time based on monotonic time should be around two seconds
  OC_INFO("start_mt: %" PRIu64 ", end_mt: %" PRIu64, start_mt, end_mt);
  int64_t elapsed_mt = static_cast<int64_t>(end_mt) - start_mt;
  EXPECT_LT(0, elapsed_mt);
}

#endif /* __unix__ || _WIN32 */
