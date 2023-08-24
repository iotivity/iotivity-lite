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

#include "api/oc_collection_internal.h"
#include "api/oc_core_res_internal.h"
#include "api/oc_event_callback_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_link_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_ri.h"
#include "oc_collection.h"
#include "oc_core_res.h"
#include "port/oc_connectivity_internal.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_features.h"
#include "util/oc_process_internal.h"
#include "tests/gtest/Clock.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#include "security/oc_security_internal.h"
#endif /* OC_SECURITY */

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
    oc_ri_deinit();
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

struct Switches
{
  oc_collection_t *collection;
  std::vector<oc_resource_t *> resources;
};

class TestObserveCallbackWithServer : public testing::Test {
public:
#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
  static oc_collection_t *CreateSwitchesCollection(const std::string &uri)
  {
    auto *col = reinterpret_cast<oc_collection_t *>(
      oc_new_collection(nullptr, uri.c_str(), 1, 0));
    oc_resource_bind_resource_type(&col->res, "oic.wk.col");
    EXPECT_TRUE(
      oc_collection_add_supported_rt(&col->res, "oic.r.switch.binary"));
    EXPECT_TRUE(
      oc_collection_add_mandatory_rt(&col->res, "oic.r.switch.binary"));
    oc_resource_set_discoverable(&col->res, true);
#ifdef OC_SECURITY
    oc_resource_make_public(&col->res);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_set_access_in_RFOTM(&col->res, true, OC_PERM_RETRIEVE);
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
#endif /* OC_SECURITY */
    EXPECT_TRUE(oc_add_collection_v1(&col->res));
    return col;
  }

  static void onGet(oc_request_t *request, oc_interface_mask_t, void *data)
  {
    auto *counter = static_cast<int *>(data);
    ++(*counter);
    OC_DBG("%s(%d)", __func__, *counter);
    oc_send_response(request, OC_STATUS_OK);
  }

  static oc_resource_t *CreateSwitch(oc_collection_t *collection,
                                     const std::string &uri)
  {
    oc_resource_t *res = oc_new_resource(nullptr, uri.c_str(), 1, 0);
    oc_resource_bind_resource_type(res, "oic.r.switch.binary");
    oc_resource_bind_resource_interface(
      res, static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_R));
    oc_resource_set_default_interface(res, OC_IF_R);
    oc_resource_set_request_handler(res, OC_GET, onGet, res);
#ifdef OC_SECURITY
    oc_resource_make_public(res);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_set_access_in_RFOTM(res, true, OC_PERM_RETRIEVE);
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
#endif /* OC_SECURITY */
    EXPECT_TRUE(oc_add_resource(res));
    oc_collection_add_link(&collection->res, oc_new_link(res));
    return res;
  }
#endif // OC_SERVER && OC_COLLECTIONS

  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());

#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
    switches_.collection = CreateSwitchesCollection("/switches");
    switches_.resources.push_back(
      CreateSwitch(switches_.collection, "/switches/0"));
    switches_.resources.push_back(
      CreateSwitch(switches_.collection, "/switches/1"));
#endif // OC_SERVER && OC_COLLECTIONS
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }

  void TearDown() override
  {
    oc_resource_set_observable(oc_core_get_resource_by_index(OCF_P, kDeviceID),
                               false);
#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
    oc_resource_set_observable(&switches_.collection->res, false);
    for (auto *res : switches_.resources) {
      oc_resource_set_observable(res, false);
    }
#endif // OC_SERVER && OC_COLLECTIONS
  }

#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
  static Switches switches_;
#endif // OC_SERVER && OC_COLLECTIONS
};

#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
Switches TestObserveCallbackWithServer::switches_{};
#endif // OC_SERVER && OC_COLLECTIONS

TEST_F(TestObserveCallbackWithServer, Observe)
{
  oc_resource_set_observable(oc_core_get_resource_by_index(OCF_P, kDeviceID),
                             true);

  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  struct observe_data
  {
    int counter;
    int lastObserveOption;
  };
  auto observe = [](oc_client_response_t *cr) {
    EXPECT_EQ(OC_STATUS_OK, cr->code);
    oc::TestDevice::Terminate();
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload).data());
    auto *od = static_cast<observe_data *>(cr->user_data);
    od->lastObserveOption = cr->observe_option;
    ++od->counter;
  };

  observe_data od{};
  ASSERT_TRUE(oc_do_observe("/oic/p", ep, nullptr, observe, HIGH_QOS, &od));
  oc::TestDevice::PoolEvents(std::chrono::seconds(3).count());
  EXPECT_EQ(1, od.counter);
  EXPECT_EQ(0, od.lastObserveOption);

  od.counter = 0;
  ASSERT_TRUE(oc_stop_observe("/oic/p", ep));
  oc::TestDevice::PoolEvents(std::chrono::seconds(3).count());
  EXPECT_EQ(1, od.counter);
  EXPECT_EQ(-1, od.lastObserveOption);
}

TEST_F(TestObserveCallbackWithServer, PeriodicObserve)
{
  auto interval = 1s;
  oc_resource_set_periodic_observable(
    oc_core_get_resource_by_index(OCF_P, kDeviceID),
    static_cast<uint16_t>(interval.count()));

#ifdef OC_SECURITY
  oc_sec_self_own(kDeviceID);
#endif // OC_SECURITY

  struct observe_data
  {
    int counter;
    int lastObserveOption;
  };
  auto observe = [](oc_client_response_t *cr) {
    EXPECT_EQ(OC_STATUS_OK, cr->code);
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload).data());
    auto *od = static_cast<observe_data *>(cr->user_data);
    od->lastObserveOption = cr->observe_option;
    ++od->counter;
    if (cr->observe_option == -1) {
      oc::TestDevice::Terminate();
    }
  };

  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);
  observe_data od{};
  ASSERT_TRUE(oc_do_observe("/oic/p", ep, nullptr, observe, HIGH_QOS, &od));
  // give enough time to receive do processing and receive the initial
  // notification (observe_option == 0)
  uint64_t mseconds = std::chrono::milliseconds(700).count();
  // and the 2 periodic notifications
  mseconds += std::chrono::milliseconds(interval).count() * 2;
  oc::TestDevice::PoolEventsMs(mseconds);
  EXPECT_LE(3, od.counter);
  EXPECT_EQ(1, oc_periodic_observe_callback_count());

  od.counter = 0;
  ASSERT_TRUE(oc_stop_observe("/oic/p", ep));

  oc::TestDevice::PoolEvents(std::chrono::seconds(2).count());
  EXPECT_EQ(-1, od.lastObserveOption);
  EXPECT_EQ(1, od.counter);
  EXPECT_EQ(0, oc_periodic_observe_callback_count());

#ifdef OC_SECURITY
  oc_reset_device_v1(kDeviceID, true);
  // need to wait for closing of TLS sessions
  oc::TestDevice::PoolEventsMs(200);
#endif // OC_SECURITY
}

// Observing a non-observable resource gets a single GET response with the
// resource data
TEST_F(TestObserveCallbackWithServer, ObserveNonObservable)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto observe = [](oc_client_response_t *cr) {
    EXPECT_EQ(OC_STATUS_OK, cr->code);
    EXPECT_EQ(-1, cr->observe_option);
    oc::TestDevice::Terminate();
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload).data());
    ++(*static_cast<int *>(cr->user_data));
  };

  int counter = 0;
  ASSERT_TRUE(
    oc_do_observe("/oic/p", ep, nullptr, observe, HIGH_QOS, &counter));
  oc::TestDevice::PoolEvents(std::chrono::seconds(3).count());
  EXPECT_EQ(1, counter);
}

#ifdef OC_COLLECTIONS

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

// Observing a collection
TEST_F(TestObserveCallbackWithServer, ObserveCollection)
{
  oc_resource_set_observable(&switches_.collection->res, true);
  oc_resource_set_observable(switches_.resources[0], true);

  struct observe_data
  {
    int counter;
    int lastObserveOption;
  };
  auto observe = [](oc_client_response_t *cr) {
    EXPECT_EQ(OC_STATUS_OK, cr->code);

    oc::TestDevice::Terminate();
    auto *od = static_cast<observe_data *>(cr->user_data);
    od->lastObserveOption = cr->observe_option;
    ++od->counter;

    std::string json = oc::RepPool::GetJson(cr->payload).data();
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option, json.c_str());
    // the payload should contain all subresources of the collection
    for (auto *link =
           static_cast<oc_link_t *>(oc_list_head(switches_.collection->links));
         link != nullptr; link = link->next) {
      std::string href = R"("href":")";
      href += oc_string(link->resource->uri);
      href += R"(")";
      OC_DBG("find link(%s)", href.c_str());
      EXPECT_TRUE(json.find(href) != std::string::npos);
    }
  };

  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);
  observe_data od{};
  ASSERT_TRUE(oc_do_observe(oc_string(switches_.collection->res.uri), ep,
                            nullptr, observe, HIGH_QOS, &od));
  oc::TestDevice::PoolEvents(std::chrono::seconds(3).count());
  EXPECT_EQ(1, od.counter);
  EXPECT_EQ(0, od.lastObserveOption);

  od.counter = 0;
  ASSERT_TRUE(oc_stop_observe(oc_string(switches_.collection->res.uri), ep));
  oc::TestDevice::PoolEvents(std::chrono::seconds(3).count());
  EXPECT_EQ(1, od.counter);
  EXPECT_EQ(-1, od.lastObserveOption);
}

// TODO fix:
// for SECURE device
//    a) must own -> coap_notify_observers_internal: device not in RFNOP;
//    skipping notification b) cannot just self-own and use anon connection -
//    oc_sec_check_acl: anon-clear access to vertical resources is prohibited

#ifndef OC_SECURITY

TEST_F(TestObserveCallbackWithServer, PeriodicObserveCollection)
{
  //   auto interval = 1s;
  //   oc_resource_set_periodic_observable(&switches_.collection->res,
  //                                       interval.count());
  // #ifdef OC_SECURITY
  //   oc_sec_self_own(kDeviceID);
  // #endif // OC_SECURITY

  //   struct observe_data
  //   {
  //     int counter;
  //     int lastObserveOption;
  //   };
  //   auto observe = [](oc_client_response_t *cr) {
  //     EXPECT_EQ(OC_STATUS_OK, cr->code);
  //     OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
  //            oc::RepPool::GetJson(cr->payload).data());
  //     auto *od = static_cast<observe_data *>(cr->user_data);
  //     od->lastObserveOption = cr->observe_option;
  //     ++od->counter;
  //     if (cr->observe_option == -1) {
  //       oc::TestDevice::Terminate();
  //     }
  //   };

  //   const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0,
  //   SECURED); ASSERT_NE(nullptr, ep); observe_data od{};
  //   ASSERT_TRUE(oc_do_observe(oc_string(switches_.collection->res.uri), ep,
  //                             "if=" OC_IF_BASELINE_STR, observe, HIGH_QOS,
  //                             &od));
  //   oc::TestDevice::PoolEventsMs(std::chrono::milliseconds(interval).count()
  //   *
  //                                2.5f);
  //   EXPECT_LE(3, od.counter);
  //   EXPECT_EQ(1, oc_periodic_observe_callback_count());

  //   od.counter = 0;
  //   ASSERT_TRUE(oc_stop_observe(oc_string(switches_.collection->res.uri),
  //   ep));

  //   oc::TestDevice::PoolEvents(std::chrono::seconds(2).count());

  // #ifdef OC_SECURITY
  //   oc_reset_device_v1(kDeviceID, true);
  //   // need to wait for closing of TLS sessions
  //   oc::TestDevice::PoolEventsMs(200);
  // #endif // OC_SECURITY
}

TEST_F(TestObserveCallbackWithServer, PeriodicBatchObserveCollection)
{
  // TODO:
  // add a collection with multiple subresources
  // make it periodically observable
  // wait for observation notifications of all subresources
}

#endif // OC_SECURITY

#endif // !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

#endif // OC_COLLECTIONS

#endif // OC_SERVER
