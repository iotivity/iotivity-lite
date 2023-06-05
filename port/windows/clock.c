/****************************************************************************
 *
 * Copyright (c) 2017 Lynx Technology
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_clock_internal.h"
#include "port/oc_clock.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Profileapi.h>

#include <assert.h>
#include <limits.h>
#include <time.h>

// This magic number is the number of 100 nanosecond intervals since January 1,
// 1601 (UTC) until 00:00:00 January 1, 1970
#define kMILLISECOND_TO_FTIME_INTERNAL (10000ULL)
#define kSECOND_TO_FTIME_INTERVAL (kMILLISECOND_TO_FTIME_INTERNAL * 1000ULL)
#define kWINDOWS_EPOCH (11644473600ULL * kSECOND_TO_FTIME_INTERVAL)

static LONGLONG g_query_perm_frequency = 0;
void
oc_clock_init(void)
{
  LARGE_INTEGER freq;
  QueryPerformanceFrequency(&freq);       // always succeeds
  g_query_perm_frequency = freq.QuadPart; // doesn't change after system boot
}

oc_clock_time_t
oc_clock_time_from_filetime(FILETIME ftime)
{
  oc_clock_time_t time = 0;
  time = ((uint64_t)ftime.dwLowDateTime);
  time += ((uint64_t)ftime.dwHighDateTime) << sizeof(DWORD) * CHAR_BIT;
  // avoid float computation if we have ticks in milliseconds
#if (OC_CLOCK_SECOND == 1000)
  return (oc_clock_time_t)((time - kWINDOWS_EPOCH) /
                           kMILLISECOND_TO_FTIME_INTERNAL);
#else
  return (oc_clock_time_t)(((time - kWINDOWS_EPOCH) /
                            ((double)kSECOND_TO_FTIME_INTERVAL) /
                            OC_CLOCK_SECOND));
#endif
}

FILETIME
oc_clock_time_to_filetime(oc_clock_time_t time)
{
#if (OC_CLOCK_SECOND == 1000)
  oc_clock_time_t time_ft = time * kMILLISECOND_TO_FTIME_INTERNAL;
#else
  oc_clock_time_t time_ft =
    (time / (double)OC_CLOCK_SECOND) * kSECOND_TO_FTIME_INTERVAL;
#endif

  time_ft += kWINDOWS_EPOCH;
  FILETIME ftime;
  ftime.dwLowDateTime = (DWORD)time_ft;
  ftime.dwHighDateTime = (DWORD)(time_ft >> sizeof(DWORD) * CHAR_BIT);
  return ftime;
}

oc_clock_time_t
oc_clock_time(void)
{
  SYSTEMTIME stime;
  GetSystemTime(&stime);

  FILETIME ftime;
  if (!SystemTimeToFileTime(&stime, &ftime)) {
    return (oc_clock_time_t)-1;
  }
  return oc_clock_time_from_filetime(ftime);
}

bool
oc_clock_time_has_monotonic_clock(void)
{
  return true;
}

oc_clock_time_t
oc_clock_time_monotonic(void)
{
  assert(g_query_perm_frequency != 0);

  LARGE_INTEGER qtime;
  QueryPerformanceCounter(&qtime); // always succeeds
  // 10 MHz is a very common QPC frequency on modern PC, so we can simplify the
  // calculation
  const LONGLONG tenMHz = 10000000;
  if (g_query_perm_frequency == tenMHz) {
    const double multiplier = (double)OC_CLOCK_SECOND / tenMHz;
    return (LONGLONG)(qtime.QuadPart * multiplier);
  }

  // Instead of just having "(qtime * OC_CLOCK_SECOND) /
  // g_query_perm_frequency", the algorithm below prevents overflow when qtime
  // is sufficiently large.
  const LONGLONG whole =
    (qtime.QuadPart / g_query_perm_frequency) * OC_CLOCK_SECOND;
  const LONGLONG part =
    (LONGLONG)((qtime.QuadPart % g_query_perm_frequency) *
               ((double)OC_CLOCK_SECOND / g_query_perm_frequency));
  return whole + part;
}

unsigned long
oc_clock_seconds(void)
{
  return (unsigned long)time(0);
}

void
oc_clock_wait(oc_clock_time_t t)
{
#if (OC_CLOCK_SECOND == 1000)
  DWORD interval_ms = t;
#else
  DWORD interval_ms = (DWORD)(t * (OC_CLOCK_SECOND / (double)1000));
#endif
  Sleep(interval_ms);
}
