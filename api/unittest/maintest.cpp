/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "api/oc_event_callback_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_main_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_config.h"
#include "port/oc_log_internal.h"
#include "util/oc_atomic.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_process_internal.h"

#include <chrono>
#include <functional>
#include <gtest/gtest.h>

#ifdef _WIN32
#include <windows.h>
#else /* !_WIN32 */
#include <pthread.h>
#endif /* _WIN32 */

using namespace std::chrono_literals;

OC_PROCESS(test_process, "Testing process in a worker thread");

class TestMain : public testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef _WIN32
    InitializeCriticalSection(&mutex);
    InitializeConditionVariable(&cv);
#else
    if (pthread_mutex_init(&mutex, nullptr) != 0) {
      throw std::string("cannot initialize mutex");
    }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0) {
      throw std::string("cannot attributes of conditional variable");
    }
    if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
      throw std::string("cannot configure clockid");
    }
    if (pthread_cond_init(&cv, &attr) != 0) {
      throw std::string("cannot initialize conditional variable");
    }
    pthread_condattr_destroy(&attr);
#endif /* _WIN32 */

    oc_runtime_init();
    oc_process_init();
    oc_event_assign_oc_process_events();
    oc_process_start(&oc_etimer_process, nullptr);
    oc_event_callbacks_process_start();
    oc_process_start(&test_process, nullptr);
  }

  static void TearDownTestCase()
  {
    oc_process_exit(&test_process);
    oc_event_callbacks_process_exit();
    oc_process_exit(&oc_etimer_process);
    oc_process_shutdown();
    oc_runtime_shutdown();

#ifndef _WIN32
    pthread_cond_destroy(&cv);
    pthread_mutex_destroy(&mutex);
#endif /* _WIN32 */
  }

  void SetUp() override
  {
    OC_ATOMIC_STORE8(TestMain::terminate, 0);
    OC_ATOMIC_STORE8(TestMain::needsPoll, 0);
    OC_ATOMIC_STORE32(TestMain::pollCounter, 0);
    OC_ATOMIC_STORE32(TestMain::eventCounter, 0);
  }

  void Lock();
  void Unlock();
  void PoolEventsMs(uint64_t mseconds);
  void SignalEventLoop();
  void Terminate();
  void WaitForEvent(oc_clock_time_t next_event_mt);

  void testSignalEventLoopinThreadWithMainLoop(
    const std::function<void()> &mainLoop);

#ifdef _WIN32
  static CRITICAL_SECTION mutex;
  static CONDITION_VARIABLE cv;
#else  /* !_WIN32 */
  static pthread_mutex_t mutex;
  static pthread_cond_t cv;
#endif /* _WIN32 */
  static OC_ATOMIC_UINT8_T terminate;

  static OC_ATOMIC_UINT8_T needsPoll;
  static OC_ATOMIC_UINT32_T pollCounter;
  static OC_ATOMIC_UINT32_T eventCounter;
};

#ifdef _WIN32
CRITICAL_SECTION TestMain::mutex;
CONDITION_VARIABLE TestMain::cv;
#else  /* !_WIN32 */
pthread_mutex_t TestMain::mutex;
pthread_cond_t TestMain::cv;
#endif /* _WIN32 */
OC_ATOMIC_UINT8_T TestMain::terminate = 0;

OC_ATOMIC_UINT8_T TestMain::needsPoll = 0;
OC_ATOMIC_UINT32_T TestMain::pollCounter = 0;
OC_ATOMIC_UINT32_T TestMain::eventCounter = 0;

OC_PROCESS_THREAD(test_process, ev, data)
{
  (void)data;
  (void)ev;
  OC_PROCESS_POLLHANDLER([]() {
    OC_DBG("polling(%u)", OC_ATOMIC_LOAD32(TestMain::pollCounter));
    OC_ATOMIC_STORE8(TestMain::needsPoll, 0);
    OC_ATOMIC_INCREMENT32(TestMain::pollCounter);
  }());
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&test_process)) {
    OC_PROCESS_YIELD();
    OC_DBG("received event(%u)", OC_ATOMIC_LOAD32(TestMain::eventCounter));
    OC_ATOMIC_INCREMENT32(TestMain::eventCounter);
  }
  OC_PROCESS_END();
}

void
TestMain::Lock()
{
#ifdef _WIN32
  EnterCriticalSection(&TestMain::mutex);
#else  /* !_WIN32 */
  pthread_mutex_lock(&TestMain::mutex);
#endif /* _WIN32 */
}

void
TestMain::Unlock()
{
#ifdef _WIN32
  LeaveCriticalSection(&TestMain::mutex);
#else  /* !_WIN32 */
  pthread_mutex_unlock(&TestMain::mutex);
#endif /* _WIN32 */
}

void
TestMain::WaitForEvent(oc_clock_time_t next_event_mt)
{
#ifdef _WIN32
  if (next_event_mt == 0) {
    SleepConditionVariableCS(&TestMain::cv, &TestMain::mutex, INFINITE);
    return;
  }
  oc_clock_time_t now_mt = oc_clock_time_monotonic();
  if (now_mt < next_event_mt) {
    SleepConditionVariableCS(
      &TestMain::cv, &TestMain::mutex,
      (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
  }
#else  /* !_WIN32 */
  if (next_event_mt == 0) {
    pthread_cond_wait(&TestMain::cv, &TestMain::mutex);
    return;
  }
  struct timespec next_event = { 0, 0 };
  if (oc_clock_time_t next_event_cv; oc_clock_monotonic_time_to_posix(
        next_event_mt, CLOCK_MONOTONIC, &next_event_cv)) {
    next_event = oc_clock_time_to_timespec(next_event_cv);
  }
  pthread_cond_timedwait(&TestMain::cv, &TestMain::mutex, &next_event);
#endif /* _WIN32 */
}

void
TestMain::SignalEventLoop()
{
  // we need to lock the main loop mutex to synchronize this call with
  // oc_process_nevents() in the main loop, without it we could miss events
  Lock();
#ifdef _WIN32
  WakeConditionVariable(&TestMain::cv);
#else  /* !_WIN32 */
  pthread_cond_signal(&TestMain::cv);
#endif /* _WIN32 */
  Unlock();
}

void
TestMain::Terminate()
{
  OC_ATOMIC_STORE8(TestMain::terminate, 1);
  SignalEventLoop();
}

static constexpr int kRepeats = 3000;

static void *
pollProcessAndSignal(void *data)
{
  auto *instance = static_cast<TestMain *>(data);
  for (int i = 0; i < kRepeats && OC_ATOMIC_LOAD8(TestMain::terminate) == 0;
       ++i) {
    OC_DBG("request poll");
    OC_ATOMIC_STORE8(TestMain::needsPoll, 1);
    oc_process_poll(&test_process);
    instance->SignalEventLoop();
    while (OC_ATOMIC_LOAD8(TestMain::terminate) == 0 &&
           OC_ATOMIC_LOAD8(TestMain::needsPoll) != 0) {
      continue;
    }
  }
  instance->Terminate();
  return nullptr;
}

#ifdef _WIN32

static DWORD
pollProcessAndSignalWin32(LPVOID data)
{
  pollProcessAndSignal(data);
  return 0;
}

#endif /* _WIN32 */

void
TestMain::testSignalEventLoopinThreadWithMainLoop(
  const std::function<void()> &mainLoop)
{
#ifdef _WIN32
  DWORD worker_thread_id;
  HANDLE worker_thread = CreateThread(nullptr, 0, pollProcessAndSignalWin32,
                                      nullptr, 0, &worker_thread_id);
  ASSERT_NE(worker_thread, nullptr);
#else  /* !_WIN32 */
  pthread_t worker_thread;
  ASSERT_EQ(
    0, pthread_create(&worker_thread, nullptr, pollProcessAndSignal, this));
#endif /* _WIN32 */

  auto timeout = 2000ms;
  auto quit = [](void *data) {
    auto *instance = static_cast<TestMain *>(data);
    instance->Terminate();
    return OC_EVENT_DONE;
  };
  oc_set_delayed_callback_ms_v1(this, quit, timeout.count());

  mainLoop();

  oc_remove_delayed_callback(this, quit);

#ifdef _WIN32
  WaitForSingleObject(worker_thread, INFINITE);
#else  /* !_WIN32 */
  pthread_join(worker_thread, nullptr);
#endif /* _WIN32 */

  ASSERT_EQ(kRepeats, OC_ATOMIC_LOAD32(TestMain::pollCounter));
}

TEST_F(TestMain, SignalEventLoopFromThread)
{
  testSignalEventLoopinThreadWithMainLoop([this]() {
    while (OC_ATOMIC_LOAD8(TestMain::terminate) == 0) {
      oc_clock_time_t next_event = oc_main_poll_v1();
      Lock();
      if (oc_main_needs_poll()) {
        Unlock();
        continue;
      }
      if (OC_ATOMIC_LOAD8(TestMain::terminate) != 0) {
        Unlock();
        break;
      }
      WaitForEvent(next_event);
      Unlock();
    }
  });
}

TEST_F(TestMain, NeedsPoll)
{
  oc_process_poll(&test_process);

  EXPECT_TRUE(oc_main_needs_poll());

  while (oc_main_poll_v1() != 0) {
    // no-op
  }
}
