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

static int urandom_fd;

void
oc_random_init(void)
{
  urandom_fd = open("/dev/urandom", O_RDONLY);
}

unsigned int
oc_random_value(void)
{
  unsigned int rand = 0;
  int ret = read(urandom_fd, &rand, sizeof(rand));
  assert(ret != -1);
#ifndef DEBUG
  (void)ret;
#endif
  return rand;
}

void
oc_random_destroy(void)
{
  close(urandom_fd);
}
