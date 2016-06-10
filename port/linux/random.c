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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "port/oc_random.h"

static int urandom_fd;

void oc_random_init(unsigned short seed)
{
  urandom_fd = open("/dev/urandom", O_RDONLY);
}

unsigned short oc_random_rand(void)
{
  unsigned short rand = 0;
  int ret = read(urandom_fd, &rand, sizeof(rand));
  if(ret != -1) {
    return rand;
  }
  return 0;
}

void oc_random_destroy()
{
  close(urandom_fd);
}
