/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
 *           2021 CASCODA LTD        All Rights Reserved.
 *           2023 plgd.dev s.r.o.    All Rights Reserved.
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

#include "api/oc_ri_internal.h"
#include "api/oc_ri_server_internal.h"
#include "oc_api.h"
#include "oc_collection.h"
#include "oc_config.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "port/oc_network_event_handler_internal.h"
#include "tests/gtest/Device.h"
#include "util/oc_process_internal.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <unordered_map>

static const std::string kResourceURI = "/LightResourceURI";
static const std::string kResourceName = "roomlights";
static constexpr uint16_t kObservePeriodSeconds = 1;

class TestOcServerRi : public testing::Test {
public:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_ri_init();
  }

  void TearDown() override
  {
    oc_ri_shutdown();
    oc_network_event_handler_mutex_destroy();
  }

  static void dummyRequestHandler(oc_request_t *, oc_interface_mask_t, void *)
  {
    // no-op
  }

  static void dummyOnDelete(oc_resource_t *)
  {
    // no-op
  }
};

TEST_F(TestOcServerRi, GetAppResourceByUri_P)
{
  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, kObservePeriodSeconds);
  oc_resource_set_request_handler(res, OC_GET, dummyRequestHandler, nullptr);
  EXPECT_TRUE(oc_ri_add_resource(res));

  res = oc_ri_get_app_resource_by_uri(kResourceURI.c_str(),
                                      kResourceURI.length(), 0);
  EXPECT_NE(nullptr, res);
  EXPECT_TRUE(oc_ri_delete_resource(res));
}

TEST_F(TestOcServerRi, GetAppResourceByUri_N)
{
  oc_resource_t *res = oc_ri_get_app_resource_by_uri(kResourceURI.c_str(),
                                                     kResourceURI.length(), 0);
  EXPECT_EQ(nullptr, res);
}

TEST_F(TestOcServerRi, RiGetAppResource_P)
{
  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, kObservePeriodSeconds);
  oc_resource_set_request_handler(res, OC_GET, dummyRequestHandler, nullptr);
  EXPECT_TRUE(oc_ri_add_resource(res));
  res = oc_ri_get_app_resources();
  EXPECT_NE(nullptr, res);
  EXPECT_TRUE(oc_ri_delete_resource(res));
}

TEST_F(TestOcServerRi, RiGetAppResource_N)
{
  oc_resource_t *res = oc_ri_get_app_resources();
  EXPECT_EQ(nullptr, res);
}

TEST_F(TestOcServerRi, RiAllocResource_P)
{
  oc_resource_t *res = oc_ri_alloc_resource();
  EXPECT_NE(nullptr, res);
  oc_ri_dealloc_resource(res);
}

TEST_F(TestOcServerRi, RiFreeResourceProperties_P)
{
  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_ri_free_resource_properties(res);
  EXPECT_EQ(0, oc_string_len(res->name));
  EXPECT_TRUE(oc_ri_delete_resource(res));
}

TEST_F(TestOcServerRi, RiAddResource_P)
{
  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, kObservePeriodSeconds);
  oc_resource_set_request_handler(res, OC_GET, dummyRequestHandler, nullptr);
  EXPECT_TRUE(oc_ri_add_resource(res));
  // cannot add the same resource twice
  EXPECT_FALSE(oc_ri_add_resource(res));

  EXPECT_TRUE(oc_ri_delete_resource(res));
}

TEST_F(TestOcServerRi, RiAddResourceAfterDelayedDelete_F)
{
  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, kObservePeriodSeconds);
  oc_resource_set_request_handler(res, OC_GET, dummyRequestHandler, nullptr);
  ASSERT_TRUE(oc_ri_add_resource(res));

  oc_delayed_delete_resource(res);
  // cannot add resource to application when it has been scheduled for deletion
  EXPECT_FALSE(oc_ri_add_resource(res));
}

TEST_F(TestOcServerRi, RiOnDeleteResourceCallbacksAdd)
{
#ifndef OC_DYNAMIC_ALLOCATION
  std::array<oc_ri_delete_resource_cb_t, OC_MAX_ON_DELETE_RESOURCE_CBS>
    on_delete{
      [](oc_resource_t *) { OC_DBG("1"); },
      [](oc_resource_t *) { OC_DBG("2"); },
    };

  for (size_t i = 0; i < OC_MAX_ON_DELETE_RESOURCE_CBS; ++i) {
    oc_ri_on_delete_resource_add_callback(on_delete[i]);
  }
  EXPECT_FALSE(oc_ri_on_delete_resource_add_callback(dummyOnDelete));
  oc_ri_on_delete_resource_remove_all();
#endif /* !OC_DYNAMIC_ALLOCATION */

  EXPECT_TRUE(oc_ri_on_delete_resource_add_callback(dummyOnDelete));
  // adding of duplicates should fail
  EXPECT_FALSE(oc_ri_on_delete_resource_add_callback(dummyOnDelete));
}

TEST_F(TestOcServerRi, RiOnDeleteResourceCallbacksRemove)
{
  EXPECT_EQ(nullptr, oc_ri_on_delete_resource_find_callback(dummyOnDelete));
  EXPECT_FALSE(oc_ri_on_delete_resource_remove_callback(dummyOnDelete));

#ifdef OC_DYNAMIC_ALLOCATION
  auto on_delete_1 = [](oc_resource_t *) { OC_DBG("1"); };
  EXPECT_TRUE(oc_ri_on_delete_resource_add_callback(on_delete_1));
  EXPECT_TRUE(oc_ri_on_delete_resource_find_callback(on_delete_1));
  auto on_delete_2 = [](oc_resource_t *) { OC_DBG("2"); };
  EXPECT_TRUE(oc_ri_on_delete_resource_add_callback(on_delete_2));
  EXPECT_TRUE(oc_ri_on_delete_resource_find_callback(on_delete_2));
  auto on_delete_3 = [](oc_resource_t *) { OC_DBG("3"); };
  EXPECT_TRUE(oc_ri_on_delete_resource_add_callback(on_delete_3));
  EXPECT_TRUE(oc_ri_on_delete_resource_find_callback(on_delete_3));

  EXPECT_TRUE(oc_ri_on_delete_resource_remove_callback(on_delete_1));
  EXPECT_FALSE(oc_ri_on_delete_resource_find_callback(on_delete_1));
  EXPECT_TRUE(oc_ri_on_delete_resource_find_callback(on_delete_2));
  EXPECT_TRUE(oc_ri_on_delete_resource_find_callback(on_delete_3));

  oc_ri_on_delete_resource_remove_all();
  EXPECT_FALSE(oc_ri_on_delete_resource_find_callback(on_delete_2));
  EXPECT_FALSE(oc_ri_on_delete_resource_find_callback(on_delete_3));
#endif /* OC_DYNAMIC_ALLOCATION */
}

#ifdef OC_COLLECTIONS

static bool
find_resource_in_collections(const oc_resource_t *resource)
{
  oc_collection_t *collection = oc_collection_get_all();
  while (collection) {
    const auto *link =
      static_cast<oc_link_t *>(oc_list_head(collection->links));
    while (link) {
      if (link->resource == resource) {
        return true;
      }
      link = link->next;
    }
    collection = reinterpret_cast<oc_collection_t *>(collection->res.next);
  }
  return false;
}

TEST_F(TestOcServerRi, RiCleanupCollection_P)
{
  oc_resource_t *col = oc_new_collection(nullptr, "/switches", 1, 0);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);
  oc_resource_set_observable(col, true);
  oc_collection_add_supported_rt(col, "oic.r.switch.binary");
  oc_collection_add_mandatory_rt(col, "oic.r.switch.binary");
  oc_add_collection(col);

  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, kObservePeriodSeconds);
  oc_resource_set_request_handler(res, OC_GET, dummyRequestHandler, nullptr);

  oc_link_t *l = oc_new_link(res);
  oc_collection_add_link(col, l);
  bool add_check = oc_ri_add_resource(res);
  EXPECT_TRUE(add_check);
  bool find_check = find_resource_in_collections(res);
  EXPECT_TRUE(find_check);

  res = oc_ri_get_app_resources();
  EXPECT_NE(nullptr, res);
  bool del_check = oc_ri_delete_resource(res);
  EXPECT_TRUE(del_check);

  find_check = find_resource_in_collections(res);
  EXPECT_FALSE(find_check);
  oc_delete_collection(col);
  res = oc_ri_get_app_resources();
  EXPECT_EQ(nullptr, res);
}

#endif /* OC_COLLECTIONS */

class TestOcRiWithServer : public testing::Test {
public:
  static void onGet(oc_request_t *request, oc_interface_mask_t, void *data)
  {
    auto *counter = static_cast<int *>(data);
    ++(*counter);
    OC_DBG("%s(%d)", __func__, *counter);
    oc_send_response(request, OC_STATUS_OK);
  }

  static void onUpdate(oc_request_t *request, oc_interface_mask_t, void *data)
  {
    auto *counter = static_cast<int *>(data);
    ++(*counter);
    OC_DBG("%s(%d)", __func__, *counter);
    oc_send_response(request, OC_STATUS_CHANGED);
  }

  static void onDelete(oc_request_t *request, oc_interface_mask_t, void *data)
  {
    auto *counter = static_cast<int *>(data);
    ++(*counter);
    OC_DBG("%s(%d)", __func__, *counter);
    oc_delayed_delete_resource(request->resource);
    oc_send_response(request, OC_STATUS_DELETED);
  }

  static void addDynamicResources()
  {
    oc::DynamicResourceHandler handlers{
      /*onGet=*/onGet,
      /*onGetData=*/&onGetCounter,
      /*onPost=*/onUpdate,
      /*onPostData=*/&onPostCounter,
      /*onPut=*/onUpdate,
      /*onPutData=*/&onPutCounter,
      /*onDelete=*/onDelete,
      /*onDeleteData=*/&onDeleteCounter,
    };

    std::vector<oc::DynamicResourceToAdd> dynResources = {
      {
        "Dynamic Resource 1",
        "/dyn1",
        {
          "oic.d.dynamic",
          "oic.d.test",
        },
        {
          OC_IF_BASELINE,
          OC_IF_RW,
        },
        handlers,
        true,
      },
    };
    for (const auto &dr : dynResources) {
      oc_resource_t *res = oc::TestDevice::AddDynamicResource(dr, /*device*/ 0);
      ASSERT_NE(nullptr, res);
    }
  }

  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void SetUp() override
  {
    addDynamicResources();
    onDeleteCounter = 0;
    onDelayedDeleteCounter.clear();
    onGetCounter = 0;
    onPostCounter = 0;
    onPutCounter = 0;
  }

  void TearDown() override { oc::TestDevice::ClearDynamicResources(); }

  static int onDeleteCounter;
  static std::unordered_map<std::string, int> onDelayedDeleteCounter;
  static int onGetCounter;
  static int onPostCounter;
  static int onPutCounter;
};

int TestOcRiWithServer::onDeleteCounter = 0;
std::unordered_map<std::string, int>
  TestOcRiWithServer::onDelayedDeleteCounter{};
int TestOcRiWithServer::onGetCounter = 0;
int TestOcRiWithServer::onPostCounter = 0;
int TestOcRiWithServer::onPutCounter = 0;

TEST_F(TestOcRiWithServer, RiMultipleDelayedDeleteResource)
{
  oc_resource_t *res =
    oc::TestDevice::GetDynamicResource(/*device*/ 0, /*index*/ 0);
  ASSERT_NE(nullptr, res);
  std::string uri{ oc_string(res->uri) };

  auto on_delete = [](oc_resource_t *resource) {
    onDelayedDeleteCounter[oc_string(resource->uri)]++;
  };
  EXPECT_TRUE(oc_ri_on_delete_resource_add_callback(on_delete));

  oc_delayed_delete_resource(res);
  oc_delayed_delete_resource(res);
  // give some time for the delayed events to fire
  oc::TestDevice::PoolEventsMs(100);
  oc::TestDevice::ClearDynamicResource(/*device*/ 0, /*index*/ 0, false);

  EXPECT_EQ(1, onDelayedDeleteCounter.size());
  EXPECT_EQ(1, onDelayedDeleteCounter[uri]);
  EXPECT_TRUE(oc_ri_on_delete_resource_remove_callback(on_delete));

  ASSERT_EQ(nullptr, oc_ri_on_delete_resource_find_callback(on_delete));
}

TEST_F(TestOcRiWithServer, RiDelayedDeleteAndDeleteResource)
{
  oc_resource_t *res =
    oc::TestDevice::GetDynamicResource(/*device*/ 0, /*index*/ 0);
  ASSERT_NE(nullptr, res);

  oc_delayed_delete_resource(res);
  oc_delete_resource(res);
  // give some time for the delayed events to fire
  oc::TestDevice::PoolEventsMs(100);
  oc::TestDevice::ClearDynamicResource(/*device*/ 0, /*index*/ 0, false);
}

TEST_F(TestOcRiWithServer, RiDelayedDeleteResourceOnShutdown)
{
  oc_resource_t *res =
    oc::TestDevice::GetDynamicResource(/*device*/ 0, /*index*/ 0);
  ASSERT_NE(nullptr, res);

  oc_delayed_delete_resource(res);
  oc::TestDevice::ClearDynamicResource(/*device*/ 0, /*index*/ 0, false);

  oc::TestDevice::StopServer();
  ASSERT_TRUE(oc::TestDevice::StartServer());
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

TEST_F(TestOcRiWithServer, RiMultipleDeleteResourceRequests)
{
  // get insecure connection to the testing device
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  oc_resource_t *res =
    oc::TestDevice::GetDynamicResource(/*device*/ 0, /*index*/ 0);
  ASSERT_NE(nullptr, res);
  oc::TestDevice::ClearDynamicResource(/*device*/ 0, /*index*/ 0, false);

  int onDeleteResponseCounter = 0;
  auto onDeleteResponse = [](oc_client_response_t *data) {
    auto *counter = static_cast<int *>(data->user_data);
    ++(*counter);
    OC_DBG("onDeleteResponse(%d) code=%d\n", *counter, (int)data->code);
    if (*counter == 2) {
      oc::TestDevice::Terminate();
    }
  };

  EXPECT_TRUE(oc_do_delete_with_timeout(oc_string(res->uri), ep, nullptr, 2,
                                        onDeleteResponse, HIGH_QOS,
                                        &onDeleteResponseCounter));
  EXPECT_TRUE(oc_do_delete_with_timeout(oc_string(res->uri), ep, nullptr, 2,
                                        onDeleteResponse, HIGH_QOS,
                                        &onDeleteResponseCounter));
  oc_process_suspend(&oc_timed_callback_events);
  oc::TestDevice::PoolEventsMs(1000);
  oc_process_resume(&oc_timed_callback_events);
  oc::TestDevice::PoolEventsMs(100);

  // DELETE response handler should be invoked for each request
  EXPECT_EQ(2, onDeleteResponseCounter);
  // DELETE handler of the resource should get invoked just once, because the
  // first execution should flag the resource as to be deleted and all requests
  // should be rejected and return error
  EXPECT_EQ(1, onDeleteCounter);
}

TEST_F(TestOcRiWithServer, RiRequestAfterDeleteResourceRequest)
{
  // get insecure connection to the testing device
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  oc_resource_t *res =
    oc::TestDevice::GetDynamicResource(/*device*/ 0, /*index*/ 0);
  ASSERT_NE(nullptr, res);
  oc::TestDevice::ClearDynamicResource(/*device*/ 0, /*index*/ 0, false);

  int responseCounter = 0;
  auto onDeleteResponse = [](oc_client_response_t *data) {
    auto *counter = static_cast<int *>(data->user_data);
    ++(*counter);
    OC_DBG("onDeleteResponse(%d) code=%d\n", *counter, (int)data->code);
    EXPECT_EQ(OC_STATUS_DELETED, data->code);
    if (*counter == 2) {
      oc::TestDevice::Terminate();
    }
  };

  auto onRequestResponse = [](oc_client_response_t *data) {
    auto *counter = static_cast<int *>(data->user_data);
    ++(*counter);
    OC_DBG("onRequestResponse(%d) code=%d\n", *counter, (int)data->code);
    EXPECT_TRUE(data->code >= OC_STATUS_BAD_REQUEST);
    if (*counter == 2) {
      oc::TestDevice::Terminate();
    }
  };

  EXPECT_TRUE(oc_do_delete_with_timeout(oc_string(res->uri), ep, nullptr, 2,
                                        onDeleteResponse, HIGH_QOS,
                                        &responseCounter));
  EXPECT_TRUE(oc_do_get_with_timeout(oc_string(res->uri), ep, nullptr, 2,
                                     onRequestResponse, HIGH_QOS,
                                     &responseCounter));

  oc_process_suspend(&oc_timed_callback_events);
  oc::TestDevice::PoolEventsMs(1000);
  oc_process_resume(&oc_timed_callback_events);
  oc::TestDevice::PoolEventsMs(100);

  // both DELETE and GET response handlers should get invoked
  EXPECT_EQ(2, responseCounter);
  // DELETE handler of the resource should also get invoked
  EXPECT_EQ(1, onDeleteCounter);
  // GET handler shouldn't be invoked because resource is flagged as scheduled
  // to be deleted
  EXPECT_EQ(0, onGetCounter);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
