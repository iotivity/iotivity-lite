#include "tap.h"
#include "timestamp.h"
#include <string.h>

int
main()
{
  timestamp_t t1, t2;

  t1.sec = t2.sec = 0;
  t1.nsec = t2.nsec = 0;
  t1.offset = t2.offset = 0;
  cmp_ok(timestamp_compare(&t1, &t2), "==", 0, "t1 == t2");

  t1.sec = 1;
  cmp_ok(timestamp_compare(&t1, &t2), ">", 0, "t1 > t2");
  cmp_ok(timestamp_compare(&t2, &t1), "<", 0, "t1 < t2");

  t1.sec = 0;
  t1.nsec = 1;
  cmp_ok(timestamp_compare(&t1, &t2), ">", 0, "t1 > t2");
  cmp_ok(timestamp_compare(&t2, &t1), "<", 0, "t2 < t1");

  done_testing();
}
