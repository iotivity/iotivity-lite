#include "tap.h"
#include "timestamp.h"
#include <string.h>

const struct test_t
{
  timestamp_t ts;
  int precision;
  const char *exp;
} tests[] = {
  { { INT64_C(-62135596800), 0, 0 }, 0, "0001-01-01T00:00:00Z" },
  { { INT64_C(-62135683140), 0, 1439 }, 0, "0001-01-01T00:00:00+23:59" },
  { { INT64_C(-62135510460), 0, -1439 }, 0, "0001-01-01T00:00:00-23:59" },
  { { INT64_C(253402300799), 0, 0 }, 0, "9999-12-31T23:59:59Z" },
  { { INT64_C(253402214459), 0, 1439 }, 0, "9999-12-31T23:59:59+23:59" },
  { { INT64_C(253402387139), 0, -1439 }, 0, "9999-12-31T23:59:59-23:59" },
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

int
main()
{
  int i, ntests;
  char buf[40];
  timestamp_t ts;
  int n;

  ntests = sizeof(tests) / sizeof(*tests);
  for (i = 0; i < ntests; i++) {
    const struct test_t t = tests[i];

    n = (int)timestamp_format(buf, sizeof(buf), &t.ts);
    cmp_ok(n, "==", strlen(t.exp), "timestamp_format() (exp: \"%s\")", t.exp);
    is(buf, t.exp);

    n = (int)timestamp_format_precision(buf, sizeof(buf), &t.ts, t.precision);
    cmp_ok(n, "==", strlen(t.exp),
           "timestamp_format_precision(%d) (exp: \"%s\")", t.precision, t.exp);
    is(buf, t.exp);
  }

  {
    ts.sec = 0;
    ts.nsec = 0;
    ts.offset = 0;
    n = (int)timestamp_format_precision(buf, sizeof(buf), &ts, 9);
    cmp_ok(n, "==", 30);
    is(buf, "1970-01-01T00:00:00.000000000Z");

    n = (int)timestamp_format_precision(buf, sizeof(buf), &ts, 6);
    cmp_ok(n, "==", 27);
    is(buf, "1970-01-01T00:00:00.000000Z");

    n = (int)timestamp_format_precision(buf, sizeof(buf), &ts, 2);
    cmp_ok(n, "==", 23);
    is(buf, "1970-01-01T00:00:00.00Z");

    n = (int)timestamp_format_precision(buf, sizeof(buf), &ts, 1);
    cmp_ok(n, "==", 22);
    is(buf, "1970-01-01T00:00:00.0Z");
  }

  {
    ts.sec = 0;
    ts.offset = 0;
    ts.nsec = -1;
    ok(!timestamp_format(buf, sizeof(buf), &ts), "nsec out of range");
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, 0),
       "nsec out of range");
    ts.nsec = 1000000000;
    ok(!timestamp_format(buf, sizeof(buf), &ts), "nsec out of range");
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, 0),
       "nsec out of range");
    ts.nsec = 0;
    ts.offset = -23 * 60 - 60;
    ok(!timestamp_format(buf, sizeof(buf), &ts), "offset out of range");
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, 0),
       "offset out of range");
    ts.offset = +23 * 60 + 60;
    ok(!timestamp_format(buf, sizeof(buf), &ts), "offset out of range");
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, 0),
       "offset out of range");
    ts.offset = 0;
    ts.sec = INT64_C(-62135596801); /* 0000-12-31T23:59:59Z */
    ok(!timestamp_format(buf, sizeof(buf), &ts), "sec out of range");
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, 0),
       "sec out of range");
    ts.sec = INT64_C(253402387140); /* 10000-01-01T23:59:00Z */
    ok(!timestamp_format(buf, sizeof(buf), &ts), "sec out of range");
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, 0),
       "sec out of range");
    ts.sec = 0;
    ts.offset = 0;
    ts.nsec = 0;
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, -1),
       "precision out of range");
    ok(!timestamp_format_precision(buf, sizeof(buf), &ts, 10),
       "precision out of range");
  }

  /*
   *          1         2         3
   * 12345678901234567890123456789012345 (+ null-terminator)
   * YYYY-MM-DDThh:mm:ssZ
   * YYYY-MM-DDThh:mm:ss±hh:mm
   * YYYY-MM-DDThh:mm:ss.123Z
   * YYYY-MM-DDThh:mm:ss.123±hh:mm
   * YYYY-MM-DDThh:mm:ss.123456Z
   * YYYY-MM-DDThh:mm:ss.123456±hh:mm
   * YYYY-MM-DDThh:mm:ss.123456789Z
   * YYYY-MM-DDThh:mm:ss.123456789±hh:mm
   */

  {
    ts.sec = 0;
    ts.offset = 0;
    ts.nsec = 0;
    ok(timestamp_format(buf, 21, &ts), "suffcient buffer size");
    ok(!timestamp_format(buf, 20, &ts), "insufficient buffer size");
    ts.offset = 1;
    ok(timestamp_format(buf, 26, &ts), "suffcient buffer size");
    ok(!timestamp_format(buf, 25, &ts), "insufficient buffer size");
  }

  done_testing();
}
