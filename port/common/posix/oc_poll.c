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

// make ppoll() available
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "util/oc_features.h"

#ifdef OC_HAVE_TIME_H

#include "port/common/posix/oc_poll_internal.h"
#include "oc_clock_util.h"

#include <unistd.h>

static int
ppoll_wait(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
           oc_poll_event_handler_t on_event, void *data)
{
  int ret = ppoll(fds, nfds, timeout, NULL);
  if (ret < 0) {
    return -1;
  }
  if (ret == 0) {
    return 0;
  }

  int count = 0;
  for (nfds_t i = 0; i < nfds; ++i) {
    if (fds[i].revents == 0) {
      continue;
    }
    ++count;
    if (!on_event(fds[i].fd, fds[i].revents, data)) {
      break;
    }
  }
  return count;
}

int
oc_poll_timedwait(struct pollfd *fds, nfds_t nfds, oc_clock_time_t timeout,
                  oc_poll_event_handler_t on_event, void *data)
{
  struct timespec ts = oc_clock_time_to_timespec(timeout);
  return ppoll_wait(fds, nfds, &ts, on_event, data);
}

int
oc_poll_wait(struct pollfd *fds, nfds_t nfds, oc_poll_event_handler_t on_event,
             void *data)
{
  return ppoll_wait(fds, nfds, NULL, on_event, data);
}

#endif /* OC_HAVE_TIME_H */
