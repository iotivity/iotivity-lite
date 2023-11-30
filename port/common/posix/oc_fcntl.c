/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "port/common/posix/oc_fcntl_internal.h"
#include "port/oc_fcntl_internal.h"

#include <fcntl.h>

int
oc_fcntl_set_flags(int fd, unsigned to_add, unsigned to_remove)
{
  int old_flags = fcntl(fd, F_GETFL, 0);
  if (old_flags < 0) {
    return -1;
  }

  int flags = old_flags;
  flags &= (int)~to_remove;
  flags |= (int)to_add;

  if (flags == old_flags) {
    return flags;
  }

  if (fcntl(fd, F_SETFL, flags) < 0) {
    return -1;
  }
  return flags;
}

bool
oc_fcntl_set_blocking(int fd)
{
  return oc_fcntl_set_flags(fd, 0, O_NONBLOCK) != -1;
}

bool
oc_fcntl_set_nonblocking(int fd)
{
  return oc_fcntl_set_flags(fd, O_NONBLOCK, 0) != -1;
}
