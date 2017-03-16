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

static LARGE_INTEGER frequency = { 0 };
void
oc_clock_init(void)
{
  QueryPerformanceFrequency(&frequency);
}

oc_clock_time_t
oc_clock_time(void)
{
  LARGE_INTEGER count = { 0 };
  if (frequency.QuadPart && QueryPerformanceCounter(&count)) {
    oc_clock_time_t t =
      1000 * count.QuadPart / frequency.QuadPart; // milliseconds
    return t;
  }
  // fall back if no QueryPerformanceCounter available
  return GetTickCount64();
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
