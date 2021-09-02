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

#include "port/oc_random.h"

#define _CRT_RAND_S
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void
oc_random_init(void)
{
  srand((unsigned)GetTickCount());
}

unsigned int
oc_random_value(void)
{
  unsigned int val = 0;
  rand_s(&val);
  return val;
}

void
oc_random_destroy()
{
}
