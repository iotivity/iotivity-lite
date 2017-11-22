/*
// Copyright 2018 Oleksandr Grytsov
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

#include "oc_clock.h"
#include "oc_api.h"

#include <openthread/platform/alarm-milli.h>

static uint32_t prev_time = 0;
static uint32_t high_time = 0;

void
oc_clock_init(void)
{
}

oc_clock_time_t
oc_clock_time(void)
{
  uint32_t time = otPlatAlarmMilliGetNow();

  if (time < prev_time) {
      high_time++;
  }

  prev_time = time;

  return (uint64_t)high_time << 32 | time;
}

unsigned long
oc_clock_seconds(void)
{
  unsigned long time = oc_clock_time() / OC_CLOCK_SECOND;

  return time;
}

void
oc_clock_wait(oc_clock_time_t t)
{
  (void)t;
}
