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
#include "port/oc_poll_loop.h"
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
    oc_runtime_init();
    oc_poll_loop_init();
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
    oc_poll_loop_shutdown();
    oc_runtime_shutdown();
  }

  void SetUp() override
  {
    OC_ATOMIC_STORE8(TestMain::needsPoll, 0);
    OC_ATOMIC_STORE32(TestMain::pollCounter, 0);
    OC_ATOMIC_STORE32(TestMain::eventCounter, 0);
  }

  static void SignalEventLoop();
  static void Terminate();

  void testSignalEventLoopinThreadWithMainLoop(
    const std::function<void()> &mainLoop);

  static OC_ATOMIC_UINT8_T needsPoll;
  static OC_ATOMIC_UINT32_T pollCounter;
  static OC_ATOMIC_UINT32_T eventCounter;
};

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
TestMain::SignalEventLoop()
{
  oc_poll_loop_signal();
}

void
TestMain::Terminate()
{
  oc_poll_loop_terminate();
}

static constexpr int kRepeats = 3000;

static void *
pollProcessAndSignal(void *)
{
  while (oc_poll_loop_is_terminated()) {
    // wait for the main loop to start
    continue;
  }

  for (int i = 0; i < kRepeats && !oc_poll_loop_is_terminated(); ++i) {
    OC_DBG("request poll");
    OC_ATOMIC_STORE8(TestMain::needsPoll, 1);
    oc_process_poll(&test_process);
    TestMain::SignalEventLoop();
    while (OC_ATOMIC_LOAD8(TestMain::needsPoll) != 0 &&
           !oc_poll_loop_is_terminated()) {
      continue;
    }
  }
  TestMain::Terminate();
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
    0, pthread_create(&worker_thread, nullptr, pollProcessAndSignal, nullptr));
#endif /* _WIN32 */

  auto timeout = 2000ms;
  auto quit = [](void *) {
    TestMain::Terminate();
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
  testSignalEventLoopinThreadWithMainLoop([]() { oc_poll_loop_run(); });
}

TEST_F(TestMain, NeedsPoll)
{
  oc_process_poll(&test_process);

  EXPECT_TRUE(oc_main_needs_poll());

  while (oc_main_poll_v1() != 0) {
    // no-op
  }
}
