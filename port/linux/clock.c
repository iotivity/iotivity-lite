/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include <math.h>
#include <time.h>
#include <unistd.h>

void
oc_clock_init(void)
{
  // no initialization necessary on Linux
}

oc_clock_time_t
oc_clock_time(void)
{
  oc_clock_time_t time = 0;
  struct timespec t;
  if (clock_gettime(CLOCK_REALTIME, &t) != -1) {
    time = (oc_clock_time_t)t.tv_sec * OC_CLOCK_SECOND +
           (oc_clock_time_t)ceil((double)t.tv_nsec / (1.e09 / OC_CLOCK_SECOND));
  }
  return time;
}

bool
oc_clock_time_has_monotonic_clock(void)
{
  return true;
}

oc_clock_time_t
oc_clock_time_monotonic(void)
{
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &t) == -1) {
    return -1;
  }
  return (oc_clock_time_t)t.tv_sec * OC_CLOCK_SECOND +
         (oc_clock_time_t)ceil((double)t.tv_nsec / (1.e09 / OC_CLOCK_SECOND));
}

uint64_t
oc_clock_seconds_v1(void)
{
  struct timespec t;
  if (clock_gettime(CLOCK_REALTIME, &t) != -1) {
    return t.tv_sec;
  }
  return 0;
}

unsigned long
oc_clock_seconds(void)
{
  return (unsigned long)oc_clock_seconds_v1();
}

void
oc_clock_wait(oc_clock_time_t t)
{
  time_t sec = (time_t)(t / OC_CLOCK_SECOND);
  oc_clock_time_t rem_ticks = t % OC_CLOCK_SECOND;
  struct timespec time = {
    .tv_sec = sec,
    .tv_nsec = (long)(((double)rem_ticks * 1.e09) / OC_CLOCK_SECOND),
  };
  nanosleep(&time, NULL);
}
