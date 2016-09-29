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

#include "random.h"
#include "port/oc_random.h"

// FIXME: Employ an appropriate seeding strategy here for the PRNG.
void
oc_random_init(void)
{
  random_init(0);
}

unsigned int
oc_random_value(void)
{
  return random_uint32();
}

void
oc_random_destroy(void)
{
}
