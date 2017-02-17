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
#include <time.h>
#include <windows.h>

void
oc_clock_init(void)
{
}

oc_clock_time_t
oc_clock_time(void)
{
  oc_clock_time_t time = (uint64_t)GetTickCount();
  return time;
}

unsigned long
oc_clock_seconds(void)
{
  time_t t = time(0);
  return (unsigned long)t;
}

void
oc_clock_wait(oc_clock_time_t t)
{
  Sleep((DWORD)(t*1000));
}
