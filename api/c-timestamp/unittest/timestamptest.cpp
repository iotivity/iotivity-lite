/******************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
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

#include "api/c-timestamp/timestamp.h"
#include "gtest/gtest.h"
#include <string>
#include <vector>

TEST(Timestamp, TimestampCompare)
{
  timestamp_t t1{};
  timestamp_t t2{};

  EXPECT_EQ(0, timestamp_compare(&t1, &t2));

  t1.sec = 1;
  EXPECT_LT(0, timestamp_compare(&t1, &t2));
  EXPECT_GT(0, timestamp_compare(&t2, &t1));

  t1.sec = 0;
  t1.nsec = 1;
  EXPECT_LT(0, timestamp_compare(&t1, &t2));
  EXPECT_GT(0, timestamp_compare(&t2, &t1));
}

TEST(Timestamp, TimestampFormatBufferSize)
{
  std::string buf;
  buf.resize(30);
  timestamp_t ts{};
  // YYYY-MM-DDThh:mm:ssZ + null-terminator = min. size 21
  EXPECT_LT(0, timestamp_format(&buf[0], 21, &ts));
  EXPECT_EQ(0, timestamp_format(&buf[0], 20, &ts));
  // YYYY-MM-DDThh:mm:ss±hh:mm + null-terminator = min. size 26
  ts.offset = 1;
  EXPECT_LT(0, timestamp_format(&buf[0], 26, &ts));
  EXPECT_EQ(0, timestamp_format(&buf[0], 25, &ts));
}

TEST(Timestamp, TimestampFormatOutOfRange)
{
  std::string buf;
  buf.resize(40);
  timestamp_t ts{};

  // nsec out of range
  ts.nsec = -1;
  EXPECT_EQ(0, timestamp_format(&buf[0], buf.capacity(), &ts));
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 0));
  ts.nsec = 1000000000;
  EXPECT_EQ(0, timestamp_format(&buf[0], buf.capacity(), &ts));
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 0));

  // offset out of range
  ts.nsec = 0;
  ts.offset = -23 * 60 - 60;
  EXPECT_EQ(0, timestamp_format(&buf[0], buf.capacity(), &ts));
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 0));
  ts.offset = +23 * 60 + 60;
  EXPECT_EQ(0, timestamp_format(&buf[0], buf.capacity(), &ts));
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 0));

  // sec out of range
  ts.offset = 0;
  ts.sec = INT64_C(-62135596801); /* 0000-12-31T23:59:59Z */
  EXPECT_EQ(0, timestamp_format(&buf[0], buf.capacity(), &ts));
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 0));
  ts.sec = INT64_C(253402387140); /* 10000-01-01T23:59:00Z */
  EXPECT_EQ(0, timestamp_format(&buf[0], buf.capacity(), &ts));
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 0));

  // precision out of rage
  ts.sec = 0;
  ts.offset = 0;
  ts.nsec = 0;
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, -1));
  EXPECT_EQ(0, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 10));
}

TEST(Timestamp, TimestampFormatPrecision)
{
  std::string buf;
  buf.resize(40);
  timestamp_t ts{};

  EXPECT_EQ(30, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 9));
  EXPECT_STREQ("1970-01-01T00:00:00.000000000Z", buf.c_str());

  EXPECT_EQ(27, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 6));
  EXPECT_STREQ("1970-01-01T00:00:00.000000Z", buf.c_str());

  EXPECT_EQ(23, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 2));
  EXPECT_STREQ("1970-01-01T00:00:00.00Z", buf.c_str());

  EXPECT_EQ(22, timestamp_format_precision(&buf[0], buf.capacity(), &ts, 1));
  EXPECT_STREQ("1970-01-01T00:00:00.0Z", buf.c_str());
}

TEST(Timestamp, TimestampFormat)
{
  struct test_t
  {
    timestamp_t ts;
    int precision;
    std::string expected;
  };

  std::vector<test_t> tests = {
    { { -62135596800L, 0, 0 }, 0, "0001-01-01T00:00:00Z" },
    { { -62135683140L, 0, 1439 }, 0, "0001-01-01T00:00:00+23:59" },
    { { -62135510460L, 0, -1439 }, 0, "0001-01-01T00:00:00-23:59" },
    { { 253402300799L, 0, 0 }, 0, "9999-12-31T23:59:59Z" },
    { { 253402214459L, 0, 1439 }, 0, "9999-12-31T23:59:59+23:59" },
    { { 253402387139L, 0, -1439 }, 0, "9999-12-31T23:59:59-23:59" },
    { { 0, 0, 0 }, 0, "1970-01-01T00:00:00Z" },
    { { 1, 0, 0 }, 0, "1970-01-01T00:00:01Z" },
    { { 10, 0, 0 }, 0, "1970-01-01T00:00:10Z" },
    { { 60, 0, 0 }, 0, "1970-01-01T00:01:00Z" },
    { { 600, 0, 0 }, 0, "1970-01-01T00:10:00Z" },
    { { 3600, 0, 0 }, 0, "1970-01-01T01:00:00Z" },
    { { 36000, 0, 0 }, 0, "1970-01-01T10:00:00Z" },
    { { 0, 123456789, 0 }, 9, "1970-01-01T00:00:00.123456789Z" },
    { { 0, 123456780, 0 }, 9, "1970-01-01T00:00:00.123456780Z" },
    { { 0, 123456700, 0 }, 9, "1970-01-01T00:00:00.123456700Z" },
    { { 0, 123456000, 0 }, 6, "1970-01-01T00:00:00.123456Z" },
    { { 0, 123450000, 0 }, 6, "1970-01-01T00:00:00.123450Z" },
    { { 0, 123400000, 0 }, 6, "1970-01-01T00:00:00.123400Z" },
    { { 0, 123000000, 0 }, 3, "1970-01-01T00:00:00.123Z" },
    { { 0, 120000000, 0 }, 3, "1970-01-01T00:00:00.120Z" },
    { { 0, 100000000, 0 }, 3, "1970-01-01T00:00:00.100Z" },
    { { 0, 10000000, 0 }, 3, "1970-01-01T00:00:00.010Z" },
    { { 0, 1000000, 0 }, 3, "1970-01-01T00:00:00.001Z" },
    { { 0, 100000, 0 }, 6, "1970-01-01T00:00:00.000100Z" },
    { { 0, 10000, 0 }, 6, "1970-01-01T00:00:00.000010Z" },
    { { 0, 1000, 0 }, 6, "1970-01-01T00:00:00.000001Z" },
    { { 0, 100, 0 }, 9, "1970-01-01T00:00:00.000000100Z" },
    { { 0, 10, 0 }, 9, "1970-01-01T00:00:00.000000010Z" },
    { { 0, 1, 0 }, 9, "1970-01-01T00:00:00.000000001Z" },
    { { 0, 9, 0 }, 9, "1970-01-01T00:00:00.000000009Z" },
    { { 0, 90, 0 }, 9, "1970-01-01T00:00:00.000000090Z" },
    { { 0, 900, 0 }, 9, "1970-01-01T00:00:00.000000900Z" },
    { { 0, 9000, 0 }, 6, "1970-01-01T00:00:00.000009Z" },
    { { 0, 90000, 0 }, 6, "1970-01-01T00:00:00.000090Z" },
    { { 0, 900000, 0 }, 6, "1970-01-01T00:00:00.000900Z" },
    { { 0, 9000000, 0 }, 3, "1970-01-01T00:00:00.009Z" },
    { { 0, 90000000, 0 }, 3, "1970-01-01T00:00:00.090Z" },
    { { 0, 900000000, 0 }, 3, "1970-01-01T00:00:00.900Z" },
    { { 0, 990000000, 0 }, 3, "1970-01-01T00:00:00.990Z" },
    { { 0, 999000000, 0 }, 3, "1970-01-01T00:00:00.999Z" },
    { { 0, 999900000, 0 }, 6, "1970-01-01T00:00:00.999900Z" },
    { { 0, 999990000, 0 }, 6, "1970-01-01T00:00:00.999990Z" },
    { { 0, 999999000, 0 }, 6, "1970-01-01T00:00:00.999999Z" },
    { { 0, 999999900, 0 }, 9, "1970-01-01T00:00:00.999999900Z" },
    { { 0, 999999990, 0 }, 9, "1970-01-01T00:00:00.999999990Z" },
    { { 0, 999999999, 0 }, 9, "1970-01-01T00:00:00.999999999Z" },
    { { 0, 0, 1439 }, 0, "1970-01-01T23:59:00+23:59" },
    { { 0, 0, 120 }, 0, "1970-01-01T02:00:00+02:00" },
    { { 0, 0, 90 }, 0, "1970-01-01T01:30:00+01:30" },
    { { 0, 0, 60 }, 0, "1970-01-01T01:00:00+01:00" },
    { { 0, 0, 1 }, 0, "1970-01-01T00:01:00+00:01" },
    { { 0, 0, -1 }, 0, "1969-12-31T23:59:00-00:01" },
    { { 0, 0, -60 }, 0, "1969-12-31T23:00:00-01:00" },
    { { 0, 0, -90 }, 0, "1969-12-31T22:30:00-01:30" },
    { { 0, 0, -120 }, 0, "1969-12-31T22:00:00-02:00" },
    { { 0, 0, -1439 }, 0, "1969-12-31T00:01:00-23:59" },
    { { 951782400, 0, 0 }, 0, "2000-02-29T00:00:00Z" },
    { { 1078012800, 0, 0 }, 0, "2004-02-29T00:00:00Z" },
  };

  std::string buf;
  buf.resize(40);
  for (size_t i = 0; i < tests.size(); ++i) {
    const auto &t = tests[i];
    EXPECT_EQ(t.expected.length(),
              timestamp_format(&buf[0], buf.capacity(), &t.ts))
      << "test case #" << i << " failed";
    EXPECT_STREQ(t.expected.c_str(), buf.c_str());

    EXPECT_EQ(
      t.expected.length(),
      timestamp_format_precision(&buf[0], buf.capacity(), &t.ts, t.precision))
      << "test case #" << i << " with precision failed";
    EXPECT_STREQ(t.expected.c_str(), buf.c_str());
  }
}

TEST(Timestamp, TimestampParseMalformed)
{
  struct test_t
  {
    std::string str;
  };
  std::vector<test_t> tests = {
    { "" },
    { "0000-01-01T00:00:00Z" },      /* Year < 0001                           */
    { "0001-00-01T00:00:00Z" },      /* Invalid month                         */
    { "0001-13-01T00:00:00Z" },      /* Invalid month                         */
    { "0001-01-32T00:00:00Z" },      /* Invalid day                           */
    { "2013-02-29T00:00:00Z" },      /* Invalid day                           */
    { "1970-01-01T24:00:00Z" },      /* Invalid hour                          */
    { "1970-01-01T23:60:00Z" },      /* Invalid minute                        */
    { "1970-01-01T23:59:61Z" },      /* Invalid second                        */
    { "1970-01-01T23:59:59+01" },    /* Invalid zone offset                   */
    { "1970-01-01T23:59:59+01:" },   /* Invalid zone offset                   */
    { "1970-01-01T23:59:59+01:0" },  /* Invalid zone offset  */
    { "1970-01-01T23:59:59+0100" },  /* Invalid zone offset  */
    { "1970-01-01T23:59:59+24:00" }, /* Zone hour > 23 */
    { "1970-01-01T23:59:59+01:60" }, /* Zone minute > 59 */
    { "1970-01-01" },                /* Date only                             */
    { "1970-01-01T23:59:59" },       /* Zone offset is required               */
    { "1970-01-01T23:59:59.123" },   /* Zone offset is required               */
    { "1970-01-01X23:59:59Z" },      /* Invalid time designator               */
    { "1970:01:01T23-59-59Z" },      /* Invalid separators                    */
    { "1970-01-01T00:00:00.Z" },     /* Fraction must have at-least one digit */
    { "X970-01-01T00:00:00Z" },      /* Non-digit in component                */
    { "1X70-01-01T00:00:00Z" },      /* Non-digit in component                */
    { "19X0-01-01T00:00:00Z" },      /* Non-digit in component                */
    { "197X-01-01T00:00:00Z" },      /* Non-digit in component                */
    { "1970-X1-01T00:00:00Z" },      /* Non-digit in component                */
    { "1970-0X-01T00:00:00Z" },      /* Non-digit in component                */
    { "1970-00-X1T00:00:00Z" },      /* Non-digit in component                */
    { "1970-00-0XT00:00:00Z" },      /* Non-digit in component                */
    { "1970-01-01T0X:00:00Z" },      /* Non-digit in component                */
    { "1970-01-01T00:0X:00Z" },      /* Non-digit in component                */
    { "1970-01-01T00:00:0XZ" },      /* Non-digit in component                */
    { "1970-01-01T00:00:00.12345X7890Z" }, /* Non-digit in component */
    { "1970-01-01T00:00:00.1234567890Z" }, /* Fraction > 9 digits */
    { "1970-01-01T00:00:00,123456789Z" },  /* Decimal sign must be full stop */
    { "1970-01-01T00:00:00Z " }, /* Trailing space                        */
  };

  for (const auto &t : tests) {
    timestamp_t ts;
    EXPECT_NE(0, timestamp_parse(t.str.c_str(), t.str.length(), &ts));
  }
}

TEST(Timestamp, TimestampParse)
{
  struct test_t
  {
    timestamp_t expected;
    std::string str;
  };

  std::vector<test_t> tests = {
    { { -62135596800L, 0, 0 }, "0001-01-01T00:00:00Z" },
    { { -62135683140L, 0, 1439 }, "0001-01-01T00:00:00+23:59" },
    { { -62135510460L, 0, -1439 }, "0001-01-01T00:00:00-23:59" },
    { { 253402300799L, 0, 0 }, "9999-12-31T23:59:59Z" },
    { { 253402214459L, 0, 1439 }, "9999-12-31T23:59:59+23:59" },
    { { 253402387139L, 0, -1439 }, "9999-12-31T23:59:59-23:59" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00Z" },
    { { 1, 0, 0 }, "1970-01-01T00:00:01Z" },
    { { 10, 0, 0 }, "1970-01-01T00:00:10Z" },
    { { 60, 0, 0 }, "1970-01-01T00:01:00Z" },
    { { 600, 0, 0 }, "1970-01-01T00:10:00Z" },
    { { 3600, 0, 0 }, "1970-01-01T01:00:00Z" },
    { { 36000, 0, 0 }, "1970-01-01T10:00:00Z" },
    { { 68169600, 0, 0 }, "1972-02-29T00:00:00Z" },
    { { 0, 123456789, 0 }, "1970-01-01T00:00:00.123456789Z" },
    { { 0, 123456780, 0 }, "1970-01-01T00:00:00.12345678Z" },
    { { 0, 123456700, 0 }, "1970-01-01T00:00:00.1234567Z" },
    { { 0, 123456000, 0 }, "1970-01-01T00:00:00.123456Z" },
    { { 0, 123450000, 0 }, "1970-01-01T00:00:00.12345Z" },
    { { 0, 123400000, 0 }, "1970-01-01T00:00:00.1234Z" },
    { { 0, 123000000, 0 }, "1970-01-01T00:00:00.123Z" },
    { { 0, 120000000, 0 }, "1970-01-01T00:00:00.12Z" },
    { { 0, 100000000, 0 }, "1970-01-01T00:00:00.1Z" },
    { { 0, 10000000, 0 }, "1970-01-01T00:00:00.01Z" },
    { { 0, 1000000, 0 }, "1970-01-01T00:00:00.001Z" },
    { { 0, 100000, 0 }, "1970-01-01T00:00:00.0001Z" },
    { { 0, 10000, 0 }, "1970-01-01T00:00:00.00001Z" },
    { { 0, 1000, 0 }, "1970-01-01T00:00:00.000001Z" },
    { { 0, 100, 0 }, "1970-01-01T00:00:00.0000001Z" },
    { { 0, 10, 0 }, "1970-01-01T00:00:00.00000001Z" },
    { { 0, 1, 0 }, "1970-01-01T00:00:00.000000001Z" },
    { { 0, 9, 0 }, "1970-01-01T00:00:00.000000009Z" },
    { { 0, 90, 0 }, "1970-01-01T00:00:00.00000009Z" },
    { { 0, 900, 0 }, "1970-01-01T00:00:00.0000009Z" },
    { { 0, 9000, 0 }, "1970-01-01T00:00:00.000009Z" },
    { { 0, 90000, 0 }, "1970-01-01T00:00:00.00009Z" },
    { { 0, 900000, 0 }, "1970-01-01T00:00:00.0009Z" },
    { { 0, 9000000, 0 }, "1970-01-01T00:00:00.009Z" },
    { { 0, 90000000, 0 }, "1970-01-01T00:00:00.09Z" },
    { { 0, 900000000, 0 }, "1970-01-01T00:00:00.9Z" },
    { { 0, 990000000, 0 }, "1970-01-01T00:00:00.99Z" },
    { { 0, 999000000, 0 }, "1970-01-01T00:00:00.999Z" },
    { { 0, 999900000, 0 }, "1970-01-01T00:00:00.9999Z" },
    { { 0, 999990000, 0 }, "1970-01-01T00:00:00.99999Z" },
    { { 0, 999999000, 0 }, "1970-01-01T00:00:00.999999Z" },
    { { 0, 999999900, 0 }, "1970-01-01T00:00:00.9999999Z" },
    { { 0, 999999990, 0 }, "1970-01-01T00:00:00.99999999Z" },
    { { 0, 999999999, 0 }, "1970-01-01T00:00:00.999999999Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.0Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.00Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.000Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.0000Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.00000Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.000000Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.0000000Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.00000000Z" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00.000000000Z" },
    { { 0, 0, 1439 }, "1970-01-01T23:59:00+23:59" },
    { { 0, 0, 120 }, "1970-01-01T02:00:00+02:00" },
    { { 0, 0, 90 }, "1970-01-01T01:30:00+01:30" },
    { { 0, 0, 60 }, "1970-01-01T01:00:00+01:00" },
    { { 0, 0, 1 }, "1970-01-01T00:01:00+00:01" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00+00:00" },
    { { 0, 0, -1 }, "1969-12-31T23:59:00-00:01" },
    { { 0, 0, -60 }, "1969-12-31T23:00:00-01:00" },
    { { 0, 0, -90 }, "1969-12-31T22:30:00-01:30" },
    { { 0, 0, -120 }, "1969-12-31T22:00:00-02:00" },
    { { 0, 0, -1439 }, "1969-12-31T00:01:00-23:59" },
    { { 0, 0, 0 }, "1970-01-01T00:00:00z" },
    { { 0, 0, 0 }, "1970-01-01 00:00:00Z" },
    { { 0, 0, 0 }, "1970-01-01t00:00:00Z" },
    { { 0, 0, 0 }, "1970-01-01 00:00:00+00:00" },
  };

  for (size_t i = 0; i < tests.size(); ++i) {
    const auto &t = tests[i];
    timestamp_t ts;
    EXPECT_EQ(0, timestamp_parse(t.str.c_str(), t.str.length(), &ts))
      << "parse of test case #" << i << " failed";
    EXPECT_EQ(0, timestamp_compare(&ts, &t.expected))
      << "comparison of test case #" << i << " failed";
    EXPECT_EQ(t.expected.offset, ts.offset)
      << "offset comparison of test case #" << i << " failed";
  }
}

#ifdef OC_PKI

TEST(Timestamp, TimestampToTm)
{
  /* 0001-01-01T12:30:45Z */
  timestamp_t ts{};
  ts.sec = -62135551755L;
  tm t;
  EXPECT_NE(nullptr, timestamp_to_tm_utc(&ts, &t));
  EXPECT_EQ(-1899, t.tm_year);
  EXPECT_EQ(0, t.tm_mon);
  EXPECT_EQ(1, t.tm_mday);
  EXPECT_EQ(0, t.tm_yday);
  EXPECT_EQ(1, t.tm_wday);
  EXPECT_EQ(12, t.tm_hour);
  EXPECT_EQ(30, t.tm_min);
  EXPECT_EQ(45, t.tm_sec);

  /* 0001-01-01T12:30:45+02:00 */
  ts.sec = -62135558955L;
  ts.offset = 120;
  t = tm{};
  EXPECT_NE(nullptr, timestamp_to_tm_local(&ts, &t));
  EXPECT_EQ(-1899, t.tm_year);
  EXPECT_EQ(0, t.tm_mon);
  EXPECT_EQ(1, t.tm_mday);
  EXPECT_EQ(0, t.tm_yday);
  EXPECT_EQ(1, t.tm_wday);
  EXPECT_EQ(12, t.tm_hour);
  EXPECT_EQ(30, t.tm_min);
  EXPECT_EQ(45, t.tm_sec);

  /* 1970-12-31T23:59:59Z */
  ts.sec = 31535999L;
  ts.offset = 0;
  t = tm{};
  EXPECT_NE(nullptr, timestamp_to_tm_utc(&ts, &t));
  EXPECT_EQ(70, t.tm_year);
  EXPECT_EQ(11, t.tm_mon);
  EXPECT_EQ(31, t.tm_mday);
  EXPECT_EQ(364, t.tm_yday);
  EXPECT_EQ(4, t.tm_wday);
  EXPECT_EQ(23, t.tm_hour);
  EXPECT_EQ(59, t.tm_min);
  EXPECT_EQ(59, t.tm_sec);
}

#endif /* OC_PKI */

TEST(Timestamp, TimestampValid)
{
  timestamp_t ts{};

  // nsec out of range
  ts.nsec = -1;
  EXPECT_FALSE(timestamp_valid(&ts));
  ts.nsec = 1000000000;
  EXPECT_FALSE(timestamp_valid(&ts));

  // offset out of range
  ts.nsec = 0;
  ts.offset = -23 * 60 - 60;
  EXPECT_FALSE(timestamp_valid(&ts));
  ts.offset = 23 * 60 + 60;
  EXPECT_FALSE(timestamp_valid(&ts));

  // sec out of range
  ts.offset = 0;
  ts.sec = -62135596801L; /* 0000-12-31T23:59:59Z */
  EXPECT_FALSE(timestamp_valid(&ts));
  ts.sec = 253402387140L; /* 10000-01-01T23:59:00Z */
  EXPECT_FALSE(timestamp_valid(&ts));
}
