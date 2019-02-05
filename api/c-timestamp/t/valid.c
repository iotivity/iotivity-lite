#include "tap.h"
#include "timestamp.h"
#include <string.h>

int
main()
{
  timestamp_t ts;

  ts.sec = 0;
  ts.offset = 0;
  ts.nsec = -1;
  ok(!timestamp_valid(&ts), "nsec out of range");

  ts.nsec = 1000000000;
  ok(!timestamp_valid(&ts), "nsec out of range");

  ts.nsec = 0;
  ts.offset = -23 * 60 - 60;
  ok(!timestamp_valid(&ts), "offset out of range");

  ts.offset = +23 * 60 + 60;
  ok(!timestamp_valid(&ts), "offset out of range");

  ts.offset = 0;
  ts.sec = INT64_C(-62135596801); /* 0000-12-31T23:59:59Z */
  ok(!timestamp_valid(&ts), "sec out of range");
  ts.sec = INT64_C(253402387140); /* 10000-01-01T23:59:00Z */
  ok(!timestamp_valid(&ts), "sec out of range");

  done_testing();
}
