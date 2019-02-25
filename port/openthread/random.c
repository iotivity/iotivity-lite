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

#include "port/oc_random.h"
#include "port/oc_log.h"

#include <openthread/platform/random.h>

void
oc_random_init(void)
{
}

unsigned int
oc_random_value(void)
{
  return otPlatRandomGet();
}

void
oc_random_destroy(void)
{
}
