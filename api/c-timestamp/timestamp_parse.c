/*
 * Copyright (c) 2014 Christian Hansen <chansen@cpan.org>
 * <https://github.com/chansen/c-timestamp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "timestamp.h"
#include <stdbool.h>
#include <stddef.h>

static int
leap_year(uint16_t y)
{
  return ((y & 3) == 0 && (y % 100 != 0 || y % 400 == 0));
}

static unsigned char
month_days(uint16_t y, uint16_t m)
{
  static const unsigned char days[2][13] = {
    { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
  };
  return days[m == 2 && leap_year(y)][m];
}

static int
parse_2d(const unsigned char *const p, size_t i, uint16_t *vp)
{
  unsigned char d0 = p[i + 0] - '0';
  if (d0 > 9) {
    return 1;
  }
  unsigned char d1 = p[i + 1] - '0';
  if (d1 > 9) {
    return 1;
  }

  *vp = d0 * 10 + d1;
  return 0;
}

static int
parse_4d(const unsigned char *const p, size_t i, uint16_t *vp)
{
  unsigned char d0 = p[i + 0] - '0';
  if (d0 > 9) {
    return 1;
  }
  unsigned char d1 = p[i + 1] - '0';
  if (d1 > 9) {
    return 1;
  }
  unsigned char d2 = p[i + 2] - '0';
  if (d2 > 9) {
    return 1;
  }
  unsigned char d3 = p[i + 3] - '0';
  if (d3 > 9) {
    return 1;
  }

  *vp = d0 * 1000 + d1 * 100 + d2 * 10 + d3;
  return 0;
}

static const uint32_t Pow10[10] = { 1,         10,        100,     1000,
                                    10000,     100000,    1000000, 10000000,
                                    100000000, 1000000000 };

static const uint16_t DayOffset[13] = { 0,   306, 337, 0,   31,  61, 92,
                                        122, 153, 184, 214, 245, 275 };

static bool
check_format(const unsigned char *str, size_t len)
{
  if (len < 20 || str[4] != '-' || str[7] != '-' || str[13] != ':' ||
      str[16] != ':') {
    return false;
  }

  unsigned char ch = str[10];
  return ch == 'T' || ch == ' ' || ch == 't';
}

static bool
parse_date(const unsigned char *str, uint16_t *year, uint16_t *month,
           uint16_t *day)
{
  uint16_t y;
  uint16_t m;
  uint16_t d;
  if (parse_4d(str, 0, &y) || y < 1 || parse_2d(str, 5, &m) || m < 1 ||
      m > 12 || parse_2d(str, 8, &d) || d < 1 || d > 31) {
    return false;
  }

  if (d > 28 && d > month_days(y, m)) {
    return false;
  }
  if (m < 3) {
    y--;
  }

  *year = y;
  *month = m;
  *day = d;
  return true;
}

static bool
parse_time(const unsigned char *str, uint16_t *hour, uint16_t *min,
           uint16_t *sec)
{
  uint16_t h;
  uint16_t m;
  uint16_t s;
  if (parse_2d(str, 11, &h) || h > 23 || parse_2d(str, 14, &m) || m > 59 ||
      parse_2d(str, 17, &s) || s > 59) {
    return false;
  }
  *hour = h;
  *min = m;
  *sec = s;
  return true;
}

static bool
parse_offset(const unsigned char *str, bool minus, int16_t *offset)
{
  uint16_t hour;
  uint16_t min;
  if (str[2] != ':') {
    return false;
  }

  if (parse_2d(str, 0, &hour) || hour > 23 || parse_2d(str, 3, &min) ||
      min > 59) {
    return false;
  }

  int16_t o = hour * 60 + min;
  if (minus) {
    o *= -1;
  }
  *offset = o;
  return true;
}

int
timestamp_parse(const char *str, size_t len, timestamp_t *tsp)
{
  /*
   *           1
   * 01234567890123456789
   * 2013-12-31T23:59:59Z
   */
  const unsigned char *cur = (const unsigned char *)str;
  if (!check_format(cur, len)) {
    return 1;
  }

  uint16_t year;
  uint16_t month;
  uint16_t day;
  uint16_t hour;
  uint16_t min;
  uint16_t sec;
  if (!parse_date(cur, &year, &month, &day) ||
      !parse_time(cur, &hour, &min, &sec)) {
    return 1;
  }

  uint32_t rdn =
    (1461 * year) / 4 - year / 100 + year / 400 + DayOffset[month] + day - 306;
  uint32_t sod = hour * 3600 + min * 60 + sec;
  const unsigned char *end = cur + len;
  cur = cur + 19;

  uint32_t nsec = 0;
  unsigned char ch = *cur++;
  if (ch == '.') {
    const unsigned char *start = cur;
    for (; cur < end; cur++) {
      const unsigned char digit = *cur - '0';
      if (digit > 9) {
        break;
      }
      nsec = nsec * 10 + digit;
    }

    size_t ndigits = cur - start;
    if (ndigits < 1 || ndigits > 9) {
      return 1;
    }

    nsec *= Pow10[9 - ndigits];

    if (cur == end) {
      return 1;
    }

    ch = *cur++;
  }

  int16_t offset = 0;
  if (!(ch == 'Z' || ch == 'z')) {
    /*
     *  01234
     * ±00:00
     */
    if (cur + 5 > end || !(ch == '+' || ch == '-') ||
        !parse_offset(cur, ch == '-', &offset)) {
      return 1;
    }
    cur += 5;
  }

  if (cur != end) {
    return 1;
  }

  tsp->sec = ((int64_t)rdn - 719163) * 86400 + sod - offset * 60;
  tsp->nsec = nsec;
  tsp->offset = offset;
  return 0;
}
