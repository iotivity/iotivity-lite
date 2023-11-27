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

#ifndef PORT_COMMON_OC_LOOP_EVENT_INTERNAL_H
#define PORT_COMMON_OC_LOOP_EVENT_INTERNAL_H

#include "port/oc_clock.h"
#include "util/oc_compiler.h"
#include <stdbool.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_loop_event_t
{
#ifdef _WIN32
  HANDLE handle; // Win32 unnamed event object
#elif defined(__linux__) || defined(__ANDROID_API__)
  int eventfd; // eventfd file descriptor
#else  /* !_WIN32 && !__linux__ && !__ANDROID_API__ */
  int read_fd;  // read end pipe file descriptor
  int write_fd; // write end pipe file descriptor
#endif /* _WIN32 */
} oc_loop_event_t;

#ifdef _WIN32
#define OC_LOOP_EVENT_INIT                                                     \
  {                                                                            \
    INVALID_HANDLE_VALUE                                                       \
  }
#elif defined(__linux__) || defined(__ANDROID_API__)
#define OC_LOOP_EVENT_INIT                                                     \
  {                                                                            \
    -1                                                                         \
  }
#else /* !_WIN32 && !__linux__ && !__ANDROID_API__ */
#define OC_LOOP_EVENT_INIT                                                     \
  {                                                                            \
    -1, -1                                                                     \
  }
#endif /* _WIN32 */

/**
 * @brief Initialize the event object
 *
 * @param event event object (cannot be NULL)
 * @return true on success
 * @return false otherwise
 */
bool oc_loop_event_init(oc_loop_event_t *event) OC_NONNULL();

/**
 * @brief Check if the event is initialized
 *
 * @param event event object (cannot be NULL)
 * @see oc_loop_event_init
 */
bool oc_loop_event_is_initialized(const oc_loop_event_t *event) OC_NONNULL();

/** @brief Deinitialize the event object */
void oc_loop_event_deinit(oc_loop_event_t *event) OC_NONNULL();

typedef enum {
  OC_LOOP_EVENT_WAIT_TIMEOUT = 0,
  OC_LOOP_EVENT_WAIT_OK = 1,

  OC_LOOP_EVENT_WAIT_ERROR = -1,
} oc_loop_event_wait_status_t;

/**
 * @brief Wait for an event to occur or timeout
 *
 * @param event event object (cannot be NULL)
 * @param timeout timeout in ticks
 * @return OC_LOOP_EVENT_WAIT_TIMEOUT on timeout
 * @return OC_LOOP_EVENT_WAIT_OK event has occurred
 * @return OC_LOOP_EVENT_WAIT_ERROR on error
 */
oc_loop_event_wait_status_t oc_loop_event_timedwait(
  const oc_loop_event_t *event, oc_clock_time_t timeout) OC_NONNULL();

/** @brief Wait for an event to occur
 *
 * @param event event object (cannot be NULL)
 * @return >=1 number of events signaled
 * @return -1 on error
 */
oc_loop_event_wait_status_t oc_loop_event_wait(const oc_loop_event_t *event)
  OC_NONNULL();

/** @brief Signal the event to wake up */
void oc_loop_event_signal(const oc_loop_event_t *event) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PORT_COMMON_OC_LOOP_EVENT_INTERNAL_H */
