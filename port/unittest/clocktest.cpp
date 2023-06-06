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

#include "oc_clock_util.h"
#include "oc_config.h"
#include "port/oc_clock.h"

#include <array>
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

class TestClockUtil : public testing::Test {
public:
  static void SetUpTestCase() { oc_clock_init(); }
};

TEST_F(TestClockUtil, oc_clock_time_rfc3339_fail)
{
  std::array<char, 1> too_small{};
  EXPECT_EQ(0, oc_clock_time_rfc3339(too_small.data(), too_small.size()));
}

TEST_F(TestClockUtil, oc_clock_time_rfc3339)
{
  oc_clock_time_t start = oc_clock_time();
  std::array<char, 32> buf{};
  size_t len = oc_clock_time_rfc3339(buf.data(), buf.size());
  ASSERT_LT(0, len);
  oc_clock_time_t parsed;
  ASSERT_TRUE(oc_clock_parse_time_rfc3339_v1(buf.data(), len, &parsed));
  oc_clock_time_t end = oc_clock_time();
  EXPECT_LE(start, parsed);
  EXPECT_LE(parsed, end);
}

TEST_F(TestClockUtil, oc_clock_parse_time_rfc3339)
{
  std::string invalid_time_str = "invalid";
  oc_clock_time_t ct1 = oc_clock_parse_time_rfc3339(invalid_time_str.c_str(),
                                                    invalid_time_str.length());
  EXPECT_EQ(0, ct1);

  std::string before_epoch_start_str = "970-01-01T00:00:00Z";
  oc_clock_time_t ct2 = oc_clock_parse_time_rfc3339(
    before_epoch_start_str.c_str(), before_epoch_start_str.length());
  EXPECT_EQ(0, ct2);

  std::string epoch_start_str = "1970-01-01T00:00:00Z";
  oc_clock_time_t ct3 = oc_clock_parse_time_rfc3339(epoch_start_str.c_str(),
                                                    epoch_start_str.length());
  EXPECT_EQ(0, ct3);

  std::string max_valid_rfc3339_time_str = "9999-12-31T23:59:59Z";
  oc_clock_time_t ct4 = oc_clock_parse_time_rfc3339(
    max_valid_rfc3339_time_str.c_str(), max_valid_rfc3339_time_str.length());
  EXPECT_LT(0, ct4);

  std::string past_max_valid_rfc3339_time_str = "99999-12-31T23:59:59Z";
  oc_clock_time_t ct5 =
    oc_clock_parse_time_rfc3339(past_max_valid_rfc3339_time_str.c_str(),
                                past_max_valid_rfc3339_time_str.length());
  EXPECT_EQ(0, ct5);
}

TEST_F(TestClockUtil, oc_clock_parse_time_rfc3339_v1)
{
  std::string invalid_time_str = "invalid";
  oc_clock_time_t ct1{};
  EXPECT_FALSE(oc_clock_parse_time_rfc3339_v1(invalid_time_str.c_str(),
                                              invalid_time_str.length(), &ct1));
  EXPECT_EQ(0, ct1);

  std::string before_epoch_start_str = "970-01-01T00:00:00Z";
  oc_clock_time_t ct2{};
  oc_clock_parse_time_rfc3339_v1(before_epoch_start_str.c_str(),
                                 before_epoch_start_str.length(), &ct2);
  EXPECT_EQ(0, ct2);

  std::string epoch_start_str = "1970-01-01T00:00:00Z";
  oc_clock_time_t ct3{};
  EXPECT_TRUE(oc_clock_parse_time_rfc3339_v1(epoch_start_str.c_str(),
                                             epoch_start_str.length(), &ct3));
  EXPECT_EQ(0, ct3);

  std::string max_valid_rfc3339_time_str = "9999-12-31T23:59:59Z";
  oc_clock_time_t ct4{};
  EXPECT_TRUE(
    oc_clock_parse_time_rfc3339_v1(max_valid_rfc3339_time_str.c_str(),
                                   max_valid_rfc3339_time_str.length(), &ct4));
  EXPECT_LT(0, ct4);

  std::string past_max_valid_rfc3339_time_str = "99999-12-31T23:59:59Z";
  oc_clock_time_t ct5{};
  EXPECT_FALSE(oc_clock_parse_time_rfc3339_v1(
    past_max_valid_rfc3339_time_str.c_str(),
    past_max_valid_rfc3339_time_str.length(), &ct5));
  EXPECT_EQ(0, ct5);
}

#ifdef OC_HAVE_TIME_H

TEST_F(TestClockUtil, oc_clock_time_to_timespec)
{
  oc_clock_time_t ct = oc_clock_time();
  timespec ts = oc_clock_time_to_timespec(ct);
  EXPECT_EQ(oc_clock_time_from_timespec(ts), ct);
}

#ifdef OC_HAVE_CLOCKID_T

TEST_F(TestClockUtil, oc_clock_monotonic_time_to_posix)
{
  oc_clock_time_t now = oc_clock_time();
  oc_clock_time_t now_from_mt{};
  EXPECT_TRUE(oc_clock_monotonic_time_to_posix(oc_clock_time_monotonic(),
                                               CLOCK_REALTIME, &now_from_mt));

  oc_clock_time_t epsilon = OC_CLOCK_SECOND / 1000;
  EXPECT_TRUE(now + epsilon >= now_from_mt);
  EXPECT_TRUE(now_from_mt + epsilon >= now);
}

#endif /* OC_HAVE_CLOCKID_T */

#endif /* OC_HAVE_TIME_H */
