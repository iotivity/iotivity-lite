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
#include "port/oc_log.h"
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <TargetConditionals.h>

static mach_timebase_info_data_t time_base;


static oc_clock_time_t oc_clock_mac_get_clocks_per_microsec(void)
{
  oc_clock_time_t cps = 0;
  assert(time_base.denom != 0);
  if (time_base.denom != 0) {
    // The calculation is typically used to convert
    // mach_absolute_time() into nanoseconds.
    cps = (1000 * (oc_clock_time_t)time_base.numer) / (oc_clock_time_t)time_base.denom;
  }
  // dummy value, make sure we do not return 0 to avoid crash upon division
  return cps > 0 ? cps : 1000;
}


void
oc_clock_init(void)
{
  // Clocks on Mac are actually CPU dependent. So we may have different values
  // for Mac and iOS (and maybe even iPhone vs iPad). Hence we are not using a
  // a constant to calculate between time and seconds.
  mach_timebase_info(&time_base);
}


/**
 * Get the current clock time.
 *
 * \return The current clock time in microseconds.
 */
oc_clock_time_t
oc_clock_time(void)
{
  // As we are using the Linux variants of the apps also for Mac, we need to
  // return also same clock unit which is microseconds.
  return mach_absolute_time() / oc_clock_mac_get_clocks_per_microsec();
}

unsigned long
oc_clock_seconds(void)
{
  return (unsigned long) (oc_clock_time() / (oc_clock_time_t)OC_CLOCK_CONF_TICKS_PER_SECOND);
}

/**
 * Sleeps the given amount of time.
 *
 * \param t time to sleep in microseconds
 */
void
oc_clock_wait(oc_clock_time_t t)
{
#if TARGET_OS_IPHONE == 1
  // nanosleep works unreliable on iOS.
  // But usleep may trigger a crash on Mac.
  usleep(t);
#else
  struct timespec req = {0};
  req.tv_sec = t / OC_CLOCK_CONF_TICKS_PER_SECOND;
  req.tv_nsec = (t % OC_CLOCK_CONF_TICKS_PER_SECOND)* 1000L;
  nanosleep(&req, NULL);
#endif
}
