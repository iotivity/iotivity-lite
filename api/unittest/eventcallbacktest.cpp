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

#include "api/oc_core_res_internal.h"
#include "api/oc_event_callback_internal.h"
#include "api/oc_events_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_features.h"
#include "util/oc_process_internal.h"
#include "tests/gtest/Clock.h"
#include "tests/gtest/Device.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <gtest/gtest.h>

using namespace std::chrono_literals;

class TestTimedEventCallback : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_clock_init();
    oc_process_init();
    oc_event_assign_oc_process_events();
    oc_process_start(&oc_etimer_process, nullptr);

    oc_event_callbacks_init();
    oc_event_callbacks_process_start();
  }

  static void TearDownTestCase()
  {
    oc_event_callbacks_process_exit();
    oc_process_exit(&oc_etimer_process);
    oc_process_shutdown();
  }

  void TearDown() override { oc_event_callbacks_shutdown(); }

  static oc_clock_time_t Poll()
  {
    oc_clock_time_t next_event = oc_etimer_request_poll();
    while (oc_process_run()) {
      next_event = oc_etimer_request_poll();
    }
    return next_event;
  }
};

static oc_event_callback_retval_t
stopCallback(void *data)
{
  OC_DBG("stop callback invoked");
  if (data != nullptr) {
    *static_cast<bool *>(data) = true;
  }
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t
continuedCallback(void *data)
{
  OC_DBG("continued callback invoked");
  if (data != nullptr) {
    (*static_cast<int *>(data))++;
  }
  return OC_EVENT_CONTINUE;
}

TEST_F(TestTimedEventCallback, Add)
{
  ASSERT_FALSE(oc_ri_has_timed_event_callback(nullptr, stopCallback, true));

  bool invoked = false;
  oc_ri_add_timed_event_callback_ticks(&invoked, stopCallback, 0);
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&invoked, stopCallback, false));

  Poll();
  EXPECT_TRUE(invoked);
  EXPECT_FALSE(oc_ri_has_timed_event_callback(&invoked, stopCallback, false));
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestTimedEventCallback, Add_Fail)
{
  std::vector<char> data(OC_MAX_EVENT_CALLBACKS + 1, '\0');
  for (int i = 0; i < OC_MAX_EVENT_CALLBACKS; ++i) {
    oc_ri_add_timed_event_callback_ticks(&data[i], stopCallback,
                                         static_cast<oc_clock_time_t>(i));
    EXPECT_TRUE(oc_ri_has_timed_event_callback(&data[i], stopCallback, false));
  }

  oc_ri_add_timed_event_callback_ticks(&data[OC_MAX_EVENT_CALLBACKS],
                                       stopCallback, OC_MAX_EVENT_CALLBACKS);
  EXPECT_FALSE(oc_ri_has_timed_event_callback(&data[OC_MAX_EVENT_CALLBACKS],
                                              stopCallback, false));
}
#endif // !OC_DYNAMIC_ALLOCATION

TEST_F(TestTimedEventCallback, Remove)
{
  char data1 = '\0';
  oc_ri_add_timed_event_callback_ticks(&data1, stopCallback, 0);
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&data1, stopCallback, false));

  char data2 = '\0';
  oc_ri_add_timed_event_callback_ticks(&data2, stopCallback, 0);
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&data2, stopCallback, false));

  oc_ri_remove_timed_event_callback(&data1, stopCallback);
  EXPECT_FALSE(oc_ri_has_timed_event_callback(&data1, stopCallback, false));
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&data2, stopCallback, false));

  oc_ri_remove_timed_event_callback(&data2, stopCallback);
  EXPECT_FALSE(oc_ri_has_timed_event_callback(&data2, stopCallback, false));
}

TEST_F(TestTimedEventCallback, RemoveByFilter)
{
  int counter = 0;
  oc_ri_add_timed_event_callback_ticks(&counter, stopCallback, 0);
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&counter, stopCallback, false));

  oc_ri_add_timed_event_callback_ticks(&counter, stopCallback, 0);
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&counter, stopCallback, false));

  oc_ri_remove_timed_event_callback_by_filter(
    stopCallback,
    [](const void *cb_data, const void *) {
      return *static_cast<const int *>(cb_data) == 0;
    },
    nullptr, true, [](void *cb_data) { ++(*static_cast<int *>(cb_data)); });

  EXPECT_EQ(1, counter);
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&counter, stopCallback, false));
}

TEST_F(TestTimedEventCallback, InvokedMultiple)
{

  bool invoked1 = false;
  oc_ri_add_timed_event_callback_ticks(&invoked1, stopCallback,
                                       oc::DurationToTicks(50ms));
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&invoked1, stopCallback, false));

  bool invoked2 = false;
  oc_ri_add_timed_event_callback_ticks(&invoked2, stopCallback,
                                       oc::DurationToTicks(100ms));
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&invoked2, stopCallback, false));

  bool invoked3 = false;
  oc_ri_add_timed_event_callback_ticks(&invoked3, stopCallback,
                                       oc::DurationToTicks(150ms));
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&invoked3, stopCallback, false));

  EXPECT_FALSE(invoked1);
  EXPECT_FALSE(invoked2);
  EXPECT_FALSE(invoked3);

  oc_clock_wait(oc::DurationToTicks(55ms));
  Poll();
  EXPECT_TRUE(invoked1);
  EXPECT_FALSE(invoked2);
  EXPECT_FALSE(invoked3);

  oc_clock_wait(oc::DurationToTicks(50ms));
  Poll();
  EXPECT_TRUE(invoked2);
  EXPECT_FALSE(invoked3);

  oc_clock_wait(oc::DurationToTicks(50ms));
  Poll();
  EXPECT_TRUE(invoked3);
}

TEST_F(TestTimedEventCallback, ContinueCallback)
{
  int invoked = 0;
  oc_ri_add_timed_event_callback_ticks(&invoked, continuedCallback,
                                       oc::DurationToTicks(50ms));
  EXPECT_TRUE(
    oc_ri_has_timed_event_callback(&invoked, continuedCallback, false));

  oc_clock_wait(oc::DurationToTicks(55ms));
  Poll();
  EXPECT_EQ(1, invoked);

  oc_clock_wait(oc::DurationToTicks(50ms));
  Poll();
  EXPECT_EQ(2, invoked);
}

TEST_F(TestTimedEventCallback, IsProcessedCallback)
{
  struct CallbackCtx
  {
    oc_trigger_t cb;
    bool invoked;
  };

  auto callback_with_ctx = [](void *data) {
    auto *ctx = static_cast<CallbackCtx *>(data);
    ctx->invoked = true;
    EXPECT_TRUE(oc_timed_event_callback_is_currently_processed(ctx, ctx->cb));
    EXPECT_FALSE(
      oc_timed_event_callback_is_currently_processed(nullptr, stopCallback));
    return OC_EVENT_DONE;
  };

  CallbackCtx ctx = { callback_with_ctx, false };
  oc_ri_add_timed_event_callback_ticks(&ctx, callback_with_ctx, 0);
  ASSERT_TRUE(oc_ri_has_timed_event_callback(nullptr, callback_with_ctx, true));
  oc_ri_add_timed_event_callback_ticks(nullptr, stopCallback,
                                       oc::DurationToTicks(10ms));
  ASSERT_TRUE(oc_ri_has_timed_event_callback(nullptr, stopCallback, true));

  EXPECT_FALSE(
    oc_timed_event_callback_is_currently_processed(&ctx, callback_with_ctx));
  EXPECT_FALSE(
    oc_timed_event_callback_is_currently_processed(nullptr, stopCallback));

  Poll();
  EXPECT_TRUE(ctx.invoked);
}

TEST_F(TestTimedEventCallback, RemoveProcessedCallback)
{
  struct CallbackCtx
  {
    oc_trigger_t cb;
    bool cb_invoked;
    oc_ri_timed_event_filter_t filter;
    oc_ri_timed_event_on_delete_t on_delete;
    bool on_delete_invoked;
  };

  auto callback_with_ctx = [](void *data) {
    auto *ctx = static_cast<CallbackCtx *>(data);
    ctx->cb_invoked = true;
    oc_ri_remove_timed_event_callback_by_filter(ctx->cb, ctx->filter, nullptr,
                                                true, ctx->on_delete);
    return OC_EVENT_DONE;
  };

  CallbackCtx ctx = { callback_with_ctx, false,
                      [](const void *, const void *) { return true; },
                      [](void *data) {
                        static_cast<CallbackCtx *>(data)->on_delete_invoked =
                          true;
                      },
                      false };
  oc_ri_add_timed_event_callback_ticks(&ctx, callback_with_ctx, 0);
  ASSERT_TRUE(oc_ri_has_timed_event_callback(nullptr, callback_with_ctx, true));

  Poll();
  EXPECT_TRUE(ctx.cb_invoked);
  EXPECT_TRUE(ctx.on_delete_invoked);
}

TEST_F(TestTimedEventCallback, RemoveProcessedCallbackByFilter)
{
  struct CallbackCtx
  {
    oc_trigger_t cb;
    bool invoked;
  };

  auto callback_with_ctx = [](void *data) {
    static_cast<CallbackCtx *>(data)->invoked = true;
    return OC_EVENT_CONTINUE;
  };

  CallbackCtx ctx = { callback_with_ctx, false };
  oc_ri_add_timed_event_callback_ticks(&ctx, callback_with_ctx,
                                       oc::DurationToTicks(10ms));

  oc_clock_wait(oc::DurationToTicks(15ms));
  Poll();
  EXPECT_TRUE(ctx.invoked);

  oc_ri_remove_timed_event_callback(&ctx, callback_with_ctx);
  EXPECT_FALSE(oc_ri_has_timed_event_callback(&ctx, callback_with_ctx, false));
}

#ifdef OC_SERVER

static constexpr size_t kDeviceID{ 0 };

static const std::string kDeviceURI{ "/oic/d" };
static const std::string kDeviceType{ "oic.d.light" };
static const std::string kDeviceName{ "Table Lamp" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };
static const std::string kManufacturerName{ "Samsung" };

class TestObserveCallback : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_log_set_level(OC_LOG_LEVEL_DEBUG);

    oc_network_event_handler_mutex_init();
    oc_ri_init();
    oc_core_init();
    ASSERT_EQ(0, oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(),
                               kDeviceName.c_str(), kOCFSpecVersion.c_str(),
                               kOCFDataModelVersion.c_str(), nullptr, nullptr));
    ASSERT_EQ(0, oc_init_platform(kManufacturerName.c_str(), nullptr, nullptr));
  }

  static void TearDownTestCase()
  {
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(kDeviceID);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_network_event_handler_mutex_destroy();
  }

  void TearDown() override
  {
    oc_event_callbacks_shutdown();
  }
};

TEST_F(TestObserveCallback, Add)
{
  EXPECT_EQ(0, oc_periodic_observe_callback_count());

  EXPECT_TRUE(oc_periodic_observe_callback_add(
    oc_core_get_resource_by_index(OCF_P, kDeviceID)));
  EXPECT_EQ(1, oc_periodic_observe_callback_count());

  EXPECT_TRUE(oc_periodic_observe_callback_add(
    oc_core_get_resource_by_index(OCF_P, kDeviceID)));
  EXPECT_EQ(1, oc_periodic_observe_callback_count());
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestObserveCallback, Add_Fail)
{
  std::vector<char> data(OC_MAX_EVENT_CALLBACKS + 1, '\0');
  for (int i = 0; i < OC_MAX_EVENT_CALLBACKS; ++i) {
    oc_ri_add_timed_event_callback_ticks(&data[i], stopCallback,
                                         static_cast<oc_clock_time_t>(i));
    EXPECT_TRUE(oc_ri_has_timed_event_callback(&data[i], stopCallback, false));
  }
  ASSERT_EQ(0, oc_periodic_observe_callback_count());

  EXPECT_FALSE(oc_periodic_observe_callback_add(
    oc_core_get_resource_by_index(OCF_P, kDeviceID)));
  EXPECT_EQ(0, oc_periodic_observe_callback_count());
}

#endif // !OC_DYNAMIC_ALLOCATION

TEST_F(TestObserveCallback, Remove)
{
  EXPECT_FALSE(oc_periodic_observe_callback_remove(
    oc_core_get_resource_by_index(OCF_P, kDeviceID)));

  ASSERT_TRUE(oc_periodic_observe_callback_add(
    oc_core_get_resource_by_index(OCF_P, kDeviceID)));
  ASSERT_EQ(1, oc_periodic_observe_callback_count());

  EXPECT_TRUE(oc_periodic_observe_callback_remove(
    oc_core_get_resource_by_index(OCF_P, kDeviceID)));
  EXPECT_EQ(0, oc_periodic_observe_callback_count());
}

TEST_F(TestObserveCallback, Get)
{
  ASSERT_TRUE(oc_periodic_observe_callback_add(
    oc_core_get_resource_by_index(OCF_P, kDeviceID)));

  EXPECT_NE(nullptr, oc_periodic_observe_callback_get(
                       oc_core_get_resource_by_index(OCF_P, kDeviceID)));
  EXPECT_EQ(nullptr, oc_periodic_observe_callback_get(
                       oc_core_get_resource_by_index(OCF_D, kDeviceID)));
}

class TestObserveCallbackWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

TEST_F(TestObserveCallbackWithServer, Observe)
{
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  // TODO:
  // oc_do_observe
  // oc_stop_observe
}

#endif // OC_SERVER
