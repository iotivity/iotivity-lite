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

#include "Device.h"

#include "oc_core_res.h"

namespace oc {

Device::Device()
{
#ifdef _WIN32
  InitializeCriticalSection(&mutex_);
  InitializeConditionVariable(&cv_);
#else
  if (pthread_mutex_init(&mutex_, nullptr) != 0) {
    throw "cannot initialize mutex";
  }
  if (pthread_cond_init(&cv_, nullptr) != 0) {
    throw "cannot initialize conditional variable";
  }
#endif /* _WIN32 */
}

void
Device::SignalEventLoop()
{
#ifdef _WIN32
  WakeConditionVariable(&cv_);
#else
  pthread_cond_signal(&cv_);
#endif
}

void
Device::Lock()
{
#ifdef _WIN32
  EnterCriticalSection(&mutex_);
#else
  pthread_mutex_lock(&mutex_);
#endif
}

void
Device::Unlock()
{
#ifdef _WIN32
  LeaveCriticalSection(&mutex_);
#else
  pthread_mutex_unlock(&mutex_);
#endif
}

void
Device::WaitForEvent(oc_clock_time_t next_event)
{
#ifdef _WIN32
  if (next_event == 0) {
    SleepConditionVariableCS(&cv_, &mutex_, INFINITE);
    return;
  }
  oc_clock_time_t now = oc_clock_time();
  if (now < next_event) {
    SleepConditionVariableCS(
      &cv_, &mutex_, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
  }
#else
  if (next_event == 0) {
    pthread_cond_wait(&cv_, &mutex_);
    return;
  }
  struct timespec ts;
  ts.tv_sec = (next_event / OC_CLOCK_SECOND);
  ts.tv_nsec =
    static_cast<long>((next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND);
  pthread_cond_timedwait(&cv_, &mutex_, &ts);
#endif
}

void
Device::Terminate()
{
  OC_ATOMIC_STORE8(terminate_, 1);
}

void
Device::PoolEvents(uint16_t seconds)
{
  PoolEventsMs(seconds * 1000);
}

void
Device::PoolEventsMs(uint16_t mseconds)
{
  OC_ATOMIC_STORE8(terminate_, 0);
  oc_set_delayed_callback_ms(this, Device::QuitEvent, mseconds);

  while (OC_ATOMIC_LOAD8(terminate_) == 0) {
    Lock();
    oc_clock_time_t next_event = oc_main_poll();
    if (OC_ATOMIC_LOAD8(terminate_) != 0) {
      Unlock();
      break;
    }
    WaitForEvent(next_event);
    Unlock();
  }

  oc_remove_delayed_callback(this, Device::QuitEvent);
}

Device TestDevice::device{};
size_t TestDevice::index{ 0 };
bool TestDevice::is_started{ false };

int
TestDevice::AppInit()
{
  if (oc_init_platform("OCFCloud", nullptr, nullptr) != 0) {
    return -1;
  }
  if (oc_add_device("/oic/d", "oic.d.light", "Cloud's Light", "ocf.1.0.0",
                    "ocf.res.1.0.0", nullptr, nullptr) != 0) {
    return -1;
  }
  index = oc_core_get_num_devices() - 1;
  return 0;
}

bool
TestDevice::StartServer()
{
  static oc_handler_t s_handler{};
  s_handler.init = AppInit;
  s_handler.signal_event_loop = SignalEventLoop;
  s_handler.register_resources = RegisterResources;

  int ret = oc_main_init(&s_handler);
  if (ret < 0) {
    is_started = false;
    return false;
  }
  is_started = true;
  device.PoolEventsMs(200); // give some time for everything to start-up
  return true;
}

void
TestDevice::StopServer()
{
  device.Terminate();
  if (is_started) {
    oc_main_shutdown();
  }
}

} // namespace oc
