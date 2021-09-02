#include "tap.h"
#include "timestamp.h"
#include <string.h>

int
main()
{
  timestamp_t ts;
  struct tm tm;

  { /* 0001-01-01T12:30:45Z */
    ts.sec = INT64_C(-62135551755);
    ts.nsec = 0;
    ts.offset = 0;

    memset(&tm, 0, sizeof(tm));
    ok(timestamp_to_tm_utc(&ts, &tm) != NULL);
    cmp_ok(tm.tm_year, "==", -1899, "tm_year");
    cmp_ok(tm.tm_mon, "==", 0, "tm_mon");
    cmp_ok(tm.tm_mday, "==", 1, "tm_mday");
    cmp_ok(tm.tm_yday, "==", 0, "tm_yday");
    cmp_ok(tm.tm_wday, "==", 1, "tm_wday");
    cmp_ok(tm.tm_hour, "==", 12, "tm_hour");
    cmp_ok(tm.tm_min, "==", 30, "tm_min");
    cmp_ok(tm.tm_sec, "==", 45, "tm_sec");
  }

  { /* 0001-01-01T12:30:45+02:00 */
    ts.sec = INT64_C(-62135558955);
    ts.nsec = 0;
    ts.offset = 120;

    memset(&tm, 0, sizeof(tm));
    ok(timestamp_to_tm_local(&ts, &tm) != NULL);
    cmp_ok(tm.tm_year, "==", -1899, "tm_year");
    cmp_ok(tm.tm_mon, "==", 0, "tm_mon");
    cmp_ok(tm.tm_mday, "==", 1, "tm_mday");
    cmp_ok(tm.tm_yday, "==", 0, "tm_yday");
    cmp_ok(tm.tm_wday, "==", 1, "tm_wday");
    cmp_ok(tm.tm_hour, "==", 12, "tm_hour");
    cmp_ok(tm.tm_min, "==", 30, "tm_min");
    cmp_ok(tm.tm_sec, "==", 45, "tm_sec");
  }

  { /* 1970-12-31T23:59:59Z */
    ts.sec = INT64_C(31535999);
    ts.nsec = 0;
    ts.offset = 0;

    memset(&tm, 0, sizeof(tm));
    ok(timestamp_to_tm_utc(&ts, &tm) != NULL);
    cmp_ok(tm.tm_year, "==", 70, "tm_year");
    cmp_ok(tm.tm_mon, "==", 11, "tm_mon");
    cmp_ok(tm.tm_mday, "==", 31, "tm_mday");
    cmp_ok(tm.tm_yday, "==", 364, "tm_yday");
    cmp_ok(tm.tm_wday, "==", 4, "tm_wday");
    cmp_ok(tm.tm_hour, "==", 23, "tm_hour");
    cmp_ok(tm.tm_min, "==", 59, "tm_min");
    cmp_ok(tm.tm_sec, "==", 59, "tm_sec");
  }

  done_testing();
}
