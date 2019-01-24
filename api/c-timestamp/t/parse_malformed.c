#include "tap.h"
#include "timestamp.h"
#include <string.h>

const struct test_t
{
  const char *str;
} tests[] = {
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
  { "1970-01-01T23:59:59+01:0" },  /* Invalid zone offset                   */
  { "1970-01-01T23:59:59+0100" },  /* Invalid zone offset                   */
  { "1970-01-01T23:59:59+24:00" }, /* Zone hour > 23                        */
  { "1970-01-01T23:59:59+01:60" }, /* Zone minute > 59                      */
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
  { "1970-01-01T00:00:00,123456789Z" }, /* Decimal sign must be full stop */
  { "1970-01-01T00:00:00Z " }, /* Trailing space                        */
};

int
main()
{
  int i, ntests;

  ntests = sizeof(tests) / sizeof(*tests);
  for (i = 0; i < ntests; i++) {
    const struct test_t t = tests[i];
    timestamp_t ts;
    int ret;

    ret = timestamp_parse(t.str, strlen(t.str), &ts);
    cmp_ok(ret, "==", 1, "timestamp_parse(\"%s\")", t.str);
  }
  done_testing();
}
