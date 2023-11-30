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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_LOOP_EVENT

#include "oc_config.h"
#include "port/oc_log_internal.h"
#include "port/oc_loop_event_internal.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <assert.h>

bool
oc_loop_event_init(oc_loop_event_t *event)
{
  assert(!oc_loop_event_is_initialized(event));

  HANDLE handle = CreateEvent(/*lpEventAttributes*/ NULL,
                              /*bManualReset*/ FALSE,
                              /*bInitialState*/ FALSE, /*lpName*/ NULL);
  if (handle == NULL) {
    OC_ERR("failed to create loop event: error (%lu)", GetLastError());
    return false;
  }

  event->handle = handle;
  return true;
}

void
oc_loop_event_deinit(oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  CloseHandle(event->handle);
  event->handle = INVALID_HANDLE_VALUE;
}

bool
oc_loop_event_is_initialized(const oc_loop_event_t *event)
{
  return event->handle != INVALID_HANDLE_VALUE;
}

oc_loop_event_wait_status_t
oc_loop_event_timedwait(const oc_loop_event_t *event, oc_clock_time_t timeout)
{
  assert(oc_loop_event_is_initialized(event));

  DWORD timeout_ms = (DWORD)(timeout * 1000 / OC_CLOCK_SECOND);
  DWORD ret = WaitForSingleObject(event->handle, timeout_ms);
  if (ret == WAIT_OBJECT_0) {
    return OC_LOOP_EVENT_WAIT_OK;
  }
  if (ret == WAIT_TIMEOUT) {
    return OC_LOOP_EVENT_WAIT_TIMEOUT;
  }
  OC_ERR("failed to wait for loop event or timeout: error (%lu)",
         GetLastError());
  return OC_LOOP_EVENT_WAIT_ERROR;
}

oc_loop_event_wait_status_t
oc_loop_event_wait(const oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  DWORD ret = WaitForSingleObject(event->handle, INFINITE);
  if (ret == WAIT_OBJECT_0) {
    return OC_LOOP_EVENT_WAIT_OK;
  }
  OC_ERR("failed to wait for loop event: error (%lu)", GetLastError());
  return OC_LOOP_EVENT_WAIT_ERROR;
}

void
oc_loop_event_signal(const oc_loop_event_t *event)
{
  assert(oc_loop_event_is_initialized(event));

  if (!SetEvent(event->handle)) {
    OC_ERR("failed to signal loop event: error (%lu)", GetLastError());
  }
}

#endif /* OC_HAS_FEATURE_LOOP_EVENT */
