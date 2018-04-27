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

#include "port/oc_random.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


void
oc_random_init(void)
{
  uint64_t currentTime = 0;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  currentTime = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
  srand(currentTime);
}

unsigned int
oc_random_value(void)
{
  return rand();
}

void
oc_random_destroy(void)
{
  //close(urandom_fd);
}
