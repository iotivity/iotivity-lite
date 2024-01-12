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

// make pipe2() available
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_LOOP_EVENT

#include "oc_config.h"
#include "port/common/posix/oc_poll_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_loop_event_internal.h"
#include "port/oc_clock.h"

#include <assert.h>
#include <errno.h>
#include <unistd.h>

#if defined(__linux__) || defined(__ANDROID_API__)
#include <sys/eventfd.h>
#else /* !__linux__ && !__ANDROID_API__ */
#include <fcntl.h>
#endif /* __linux__ || __ANDROID_API__ */

static int
loop_event_poll_timedwait(int fd, oc_clock_time_t timeout,
                          oc_poll_event_handler_t on_event)
{
  struct pollfd fds = {
    .fd = fd,
    .events = POLLIN,
  };
  int ret = oc_poll_timedwait(&fds, 1, timeout, on_event, NULL);
  if (ret < 0) {
    OC_ERR("failed to wait for loop event or timeout: error (%d)", errno);
    return OC_LOOP_EVENT_WAIT_ERROR;
  }
  return ret == 0 ? OC_LOOP_EVENT_WAIT_TIMEOUT : OC_LOOP_EVENT_WAIT_OK;
}

static oc_loop_event_wait_status_t
loop_event_poll_wait(int fd, oc_poll_event_handler_t on_event)
{
  struct pollfd fds = {
    .fd = fd,
    .events = POLLIN,
  };
  int ret = oc_poll_wait(&fds, 1, on_event, NULL);
  if (ret < 0) {
    OC_ERR("failed to wait for loop event: error (%d)", errno);
    return OC_LOOP_EVENT_WAIT_ERROR;
  }
  return ret == 0 ? OC_LOOP_EVENT_WAIT_TIMEOUT : OC_LOOP_EVENT_WAIT_OK;
}

#if defined(__linux__) || defined(__ANDROID_API__)

bool
oc_loop_event_init(oc_loop_event_t *event)
{
  assert(!oc_loop_event_is_initialized(event));

  int fd = eventfd(/*initval*/ 0, EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC);
  if (fd < 0) {
    OC_ERR("failed to create loop event: error (%d)", errno);
    return false;
  }
  event->eventfd = fd;
  return true;
}

void
oc_loop_event_deinit(oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  close(event->eventfd);
  event->eventfd = -1;
}

bool
oc_loop_event_is_initialized(const oc_loop_event_t *event)
{
  return event->eventfd != -1;
}

static bool
loop_event_event_read_eventfd(int fd, short event, void *data)
{
  (void)data;

  if ((event & POLLIN) != 0) {
    ssize_t len;
    eventfd_t dummy_value;
    do {
      len = eventfd_read(fd, &dummy_value);
    } while (len < 0 && errno == EINTR);
  }
  return false;
}

oc_loop_event_wait_status_t
oc_loop_event_timedwait(const oc_loop_event_t *event, oc_clock_time_t timeout)
{
  assert(oc_loop_event_is_initialized(event));

  return loop_event_poll_timedwait(event->eventfd, timeout,
                                   loop_event_event_read_eventfd);
}

oc_loop_event_wait_status_t
oc_loop_event_wait(const oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  return loop_event_poll_wait(event->eventfd, loop_event_event_read_eventfd);
}

void
oc_loop_event_signal(const oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  ssize_t len = 0;
  do {
    len = eventfd_write(event->eventfd, 1);
  } while (len < 0 && errno == EINTR);
#if OC_ERR_IS_ENABLED
  if (len < 0) {
    OC_ERR("failed to signal loop event: error (%d)", errno);
  }
#endif /* OC_ERR_IS_ENABLED */
}

#else /* !__linux__ && !__ANDROID_API__ */

bool
oc_loop_event_init(oc_loop_event_t *event)
{
  assert(!oc_loop_event_is_initialized(event));

  int fds[2];
  if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) < 0) {
    OC_ERR("failed to create loop event: error (%d)", errno);
    return false;
  }
  event->read_fd = fds[0];
  event->write_fd = fds[1];
  return true;
}

void
oc_loop_event_deinit(oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  close(event->read_fd);
  close(event->write_fd);
  event->read_fd = -1;
  event->write_fd = -1;
}

bool
oc_loop_event_is_initialized(const oc_loop_event_t *event)
{
  return event->read_fd != -1 && event->write_fd != -1;
}

static bool
loop_event_event_read_pipe(int fd, short event, void *data)
{
  (void)data;

  if ((event & POLLIN) != 0) {
    ssize_t len;
    uint8_t dummy_value;
    do {
      len = read(fd, &dummy_value, 1);
    } while (len < 0 && errno == EINTR);
  }
  return false;
}

oc_loop_event_wait_status_t
oc_loop_event_timedwait(const oc_loop_event_t *event, oc_clock_time_t timeout)
{
  assert(oc_loop_event_is_initialized(event));

  return loop_event_poll_timedwait(event->read_fd, timeout,
                                   loop_event_event_read_pipe);
}

oc_loop_event_wait_status_t
oc_loop_event_wait(const oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  return loop_event_poll_wait(event->read_fd, loop_event_event_read_pipe);
}

void
oc_loop_event_signal(const oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  ssize_t len = 0;
  do {
    uint8_t dummy_value = 0xef;
    len = write(event->write_fd, &dummy_value, 1);
  } while (len < 0 && errno == EINTR);
#if OC_ERR_IS_ENABLED || OC_WRN_IS_ENABLED
  if (len < 0) {
    if (errno != ENOSPC) {
      OC_ERR("failed to signal wake up to main loop: error(%d)", errno);
    }
#if OC_WRN_IS_ENABLED
    else {
      OC_WRN("failed to signal wake up to main loop: wake-up pipe is full");
    }
#endif /* OC_WRN_IS_ENABLED */
  }
#endif /* OC_ERR_IS_ENABLED || OC_WRN_IS_ENABLED */
}

#endif /* __linux__ || __ANDROID_API__ */

#endif /* OC_HAS_FEATURE_LOOP_EVENT */
