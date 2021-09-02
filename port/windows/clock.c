/*
// Copyright (c) 2017 Lynx Technology
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "port/oc_clock.h"

#include <time.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void
oc_clock_init(void)
{
}

oc_clock_time_t
oc_clock_time(void)
{
  oc_clock_time_t time = 0;

  // This magic number is the number of 100 nanosecond intervals since January
  // 1, 1601 (UTC)
  // until 00:00:00 January 1, 1970
  static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

  SYSTEMTIME system_time;
  FILETIME file_time;

  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &file_time);

  time = ((uint64_t)file_time.dwLowDateTime);
  time += ((uint64_t)file_time.dwHighDateTime) << 32;
  time = (oc_clock_time_t)((time - EPOCH) / 10000L);

  return time;
}

unsigned long
oc_clock_seconds(void)
{
  return (unsigned long)time(0);
}

void
oc_clock_wait(oc_clock_time_t t)
{
  Sleep((DWORD)(t * 1000));
}
