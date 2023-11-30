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

#ifndef PORT_POSIX_OC_POLL_INTERNAL_H
#define PORT_POSIX_OC_POLL_INTERNAL_H

#include "port/oc_clock.h"
#include "util/oc_compiler.h"

#include <poll.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Callback invoked when an event occurs on a file descriptor.
 *
 * @param fd file descriptor of the event
 * @param event event that occurred
 * @param data user data
 *
 * @return true if the handler should continue to process other events available
 * in the current iteration
 * @return false if the handler should stop processing of events and return
 */
typedef bool (*oc_poll_event_handler_t)(int fd, short event, void *data);

/**
 * @brief Wait with a timeout for events on a set of file descriptors.
 *
 * @param fds array of file descriptors to wait on (cannot be NULL)
 * @param nfds number of file descriptors in the array
 * @param timeout timeout
 * @param on_event callback invoked when an event occurs on a file descriptor
 * @param data user data provided to the \p on_event callback
 *
 * @return 0 if the timeout expired
 * @return >0 number of processes events
 * @return -1 an error occurred
 */
int oc_poll_timedwait(struct pollfd *fds, nfds_t nfds, oc_clock_time_t timeout,
                      oc_poll_event_handler_t on_event, void *data)
  OC_NONNULL(1, 4);

/**
 * @brief Wait indefinitely for events on a set of file descriptors.
 *
 * @param fds array of file descriptors to wait on (cannot be NULL)
 * @param nfds number of file descriptors in the array
 * @param on_event callback invoked when an event occurs on a file descriptor
 * @param data user data provided to the \p on_event callback
 *
 * @return >0 number of processes events
 * @return -1 an error occurred
 */
int oc_poll_wait(struct pollfd *fds, nfds_t nfds,
                 oc_poll_event_handler_t on_event, void *data) OC_NONNULL(1, 3);

#ifdef __cplusplus
}
#endif

#endif /* PORT_POSIX_OC_POLL_INTERNAL_H */
