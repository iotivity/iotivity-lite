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
#include <assert.h>
#include <stddef.h>
#include <time.h>

static const uint16_t DayOffset[13] = { 0,   306, 337, 0,   31,  61, 92,
                                        122, 153, 184, 214, 245, 275 };

/* Rata Die algorithm by Peter Baum */

static void
rdn_to_struct_tm(uint32_t rdn, struct tm *tmp)
{
  uint32_t Z = rdn + 306;
  uint32_t H = 100 * Z - 25;
  uint32_t A = H / 3652425;
  uint32_t B = A - (A >> 2);
  uint32_t y = (100 * B + H) / 36525;
  uint32_t C = B + Z - (1461 * y >> 2);
  uint32_t m = (535 * C + 48950) >> 14;
  uint32_t d;
  if (m > 12) {
    d = C - 306;
    y++;
    m -= 12;
  } else {
    d = C + 59 + ((y & 3) == 0 && (y % 100 != 0 || y % 400 == 0));
  }

  tmp->tm_mday = (int)(C - DayOffset[m]); /* Day of month [1,31]           */
  tmp->tm_mon = (int)(m - 1);             /* Month of year [0,11]          */
  tmp->tm_year = (int)(y - 1900);         /* Years since 1900              */
  tmp->tm_wday = (int)(rdn % 7);          /* Day of week [0,6] (Sunday =0) */
  tmp->tm_yday = (int)(d - 1);            /* Day of year [0,365]           */
}

#define RDN_OFFSET INT64_C(62135683200) /* 1970-01-01T00:00:00 */

static struct tm *
timestamp_to_tm(const timestamp_t *tsp, struct tm *tmp, const bool local)
{
  if (!timestamp_valid(tsp)) {
    return NULL;
  }

  uint64_t sec = tsp->sec + RDN_OFFSET;
  if (local) {
    sec += tsp->offset * 60;
  }
  assert((sec / 86400) <= UINT32_MAX);
  uint32_t rdn = (uint32_t)(sec / 86400);
  uint32_t sod = sec % 86400;

  rdn_to_struct_tm(rdn, tmp);
  tmp->tm_sec = (int)(sod % 60);
  sod /= 60;
  tmp->tm_min = (int)(sod % 60);
  sod /= 60;
  tmp->tm_hour = (int)sod;
  return tmp;
}

struct tm *
timestamp_to_tm_local(const timestamp_t *tsp, struct tm *tmp)
{
  return timestamp_to_tm(tsp, tmp, true);
}

struct tm *
timestamp_to_tm_utc(const timestamp_t *tsp, struct tm *tmp)
{
  return timestamp_to_tm(tsp, tmp, false);
}
