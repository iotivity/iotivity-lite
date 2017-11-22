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
