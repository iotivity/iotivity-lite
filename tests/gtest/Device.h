/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#pragma once

#include "oc_api.h"
#include "oc_config.h"
#include "util/oc_atomic.h"

#if defined(_WIN32)
#include <windows.h>
#else /* !_WIN32 */
#include <pthread.h>
#endif /* _WIN32 */

#include <stdint.h>

namespace oc {

class Device {
public:
  Device();
  ~Device() = default;

  void SignalEventLoop();
  void PoolEvents(uint16_t seconds);
  void PoolEventsMs(uint16_t mseconds);
  void Terminate();

private:
  void Lock();
  void Unlock();
  void WaitForEvent(oc_clock_time_t next_event);

  static oc_event_callback_retval_t QuitEvent(void *data)
  {
    auto *instance = static_cast<Device *>(data);
    instance->Terminate();
    return OC_EVENT_DONE;
  }

#if defined(_WIN32)
  CRITICAL_SECTION mutex_;
  CONDITION_VARIABLE cv_;
#else  /* !_WIN32 */
  pthread_mutex_t mutex_;
  pthread_cond_t cv_;
#endif /* _WIN32 */
  OC_ATOMIC_UINT8_T terminate_;
};

class TestDevice {
public:
  TestDevice() = delete;

  static size_t Index() { return index; }
  static size_t IsStarted() { return is_started; }

  // IoTivity-lite application callbacks
  static int AppInit();
  static void RegisterResources()
  {
    // no-op
  }
  static void SignalEventLoop() { device.SignalEventLoop(); }
  static bool StartServer();
  static void StopServer();

private:
  static Device device;
  static size_t index;
  static bool is_started;
};

} // namespace oc
