/*
// Copyright (c) 2016 Intel Corporation
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

void
oc_clock_init(void)
{
}

oc_clock_time_t
oc_clock_time(void)
{
  return sys_tick_get_32();
}

unsigned long
oc_clock_seconds(void)
{
  return oc_clock_time() / sys_clock_ticks_per_sec;
}

void
oc_clock_wait(oc_clock_time_t t)
{
  switch (sys_execution_context_type_get()) {
  case NANO_CTX_FIBER:
    fiber_sleep(t);
    break;
#ifdef CONFIG_MICROKERNEL
  case NANO_CTX_TASK:
    task_sleep(t);
    break;
#endif
  default:
    return;
  }
}
