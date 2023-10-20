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

#include "api/oc_rep_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_enums.h"
#include "oc_ri.h"
#include "tests/gtest/Collection.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "oc_push.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <array>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std::chrono_literals;

static constexpr size_t kDevice1ID{ 0 };
static constexpr std::string_view kDevice1Name{ "Test Device 1" };

#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)
static constexpr size_t kDevice2ID{ 1 };
static constexpr std::string_view kDevice2Name{ "Test Device 2" };

constexpr std::string_view kDynamicURI1 = "/dyn/discoverable";
constexpr std::string_view kDynamicURI2 = "/dyn/undiscoverable";
constexpr std::string_view kCollectionURI = "/col";
constexpr std::string_view kColDynamicURI1 = "/col/discoverable";
#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */

class TestResource : public testing::Test {};

TEST_F(TestResource, SetDiscoverable)
{
  oc_resource_t res{};
  oc_resource_set_discoverable(&res, true);
  EXPECT_NE(0, res.properties & OC_DISCOVERABLE);

  oc_resource_set_discoverable(&res, false);
  EXPECT_EQ(0, res.properties & OC_DISCOVERABLE);
}

#ifdef OC_HAS_FEATURE_PUSH

TEST_F(TestResource, SetPushable)
{
  oc_resource_t res{};
  oc_resource_set_pushable(&res, true);
  EXPECT_NE(0, res.properties & OC_PUSHABLE);

  oc_resource_set_pushable(&res, false);
  EXPECT_EQ(0, res.properties & OC_PUSHABLE);
}

#endif /* OC_HAS_FEATURE_PUSH */

TEST_F(TestResource, SetObservable)
{
  oc_resource_t res{};
  oc_resource_set_observable(&res, true);
  EXPECT_NE(0, res.properties & OC_OBSERVABLE);

  oc_resource_set_observable(&res, false);
  EXPECT_EQ(0, res.properties & OC_OBSERVABLE);
}

TEST_F(TestResource, SetPeriodicObservable)
{
  oc_resource_t res{};
  oc_resource_set_periodic_observable(&res, 42);
  EXPECT_EQ(OC_OBSERVABLE | OC_PERIODIC,
            res.properties & (OC_OBSERVABLE | OC_PERIODIC));
  EXPECT_EQ(42, res.observe_period_seconds);

  oc_resource_set_observable(&res, false);
  EXPECT_EQ(0, res.properties & (OC_OBSERVABLE | OC_PERIODIC));
}

#ifdef OC_OSCORE

TEST_F(TestResource, SetSecureMcast)
{
  oc_resource_set_secure_mcast(nullptr, true);
  oc_resource_set_secure_mcast(nullptr, false);

  oc_resource_t res{};
  oc_resource_set_secure_mcast(&res, true);
  EXPECT_NE(0, res.properties & OC_SECURE_MCAST);

  oc_resource_set_secure_mcast(&res, false);
  EXPECT_EQ(0, res.properties & OC_SECURE_MCAST);
}

#endif /* OC_OSCORE */

TEST_F(TestResource, SupportsInterface)
{
  oc_resource_t res{};
  res.interfaces = static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_R);

  EXPECT_TRUE(oc_resource_supports_interface(&res, OC_IF_BASELINE));
  EXPECT_TRUE(oc_resource_supports_interface(&res, OC_IF_R));
  EXPECT_FALSE(oc_resource_supports_interface(&res, OC_IF_RW));
}

struct DynamicResourceData
{
  int power;
};

class TestResourceWithDevice : public testing::Test {
public:
#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)
  static void addDynamicResources();
  static void onGetDynamicResource(oc_request_t *request, oc_interface_mask_t,
                                   void *user_data);
#ifdef OC_COLLECTIONS
  static void addCollections();
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */

  static void SetUpTestCase()
  {
    oc_set_send_response_callback(SendResponseCallback);
    oc::TestDevice::SetServerDevices({
      {
        /*rt=*/"oic.d.test1",
        /*name=*/std::string(kDevice1Name),
        /*spec_version=*/"ocf.1.0.0",
        /*data_model_version=*/"ocf.res.1.0.0",
        /*uri=*/"/oic/d",
      },
#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)
        {
          /*rt=*/"oic.d.test2",
          /*name=*/std::string(kDevice2Name),
          /*spec_version=*/"ocf.1.0.0",
          /*data_model_version=*/"ocf.res.1.0.0",
          /*uri=*/"/oic/d",
        },
#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */
    });
    EXPECT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_t *con = oc_core_get_resource_by_index(OCF_CON, kDevice1ID);
    ASSERT_NE(nullptr, con);
    oc_resource_set_access_in_RFOTM(con, true, OC_PERM_RETRIEVE);
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)
    addDynamicResources();
#ifdef OC_COLLECTIONS
    addCollections();
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
    oc_set_send_response_callback(nullptr);
    m_send_response_cb_invoked = false;
  }

  static void SendResponseCallback(oc_request_t *request,
                                   oc_status_t response_code)
  {
    (void)request;
    (void)response_code;
    m_send_response_cb_invoked = true;
  }

  static bool IsSendResponseCallbackInvoked()
  {
    return m_send_response_cb_invoked;
  }

#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)
  static std::unordered_map<std::string, DynamicResourceData>
    m_dynamic_resources;
#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */

private:
  static bool m_send_response_cb_invoked;
};

bool TestResourceWithDevice::m_send_response_cb_invoked = false;

#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)

std::unordered_map<std::string, DynamicResourceData>
  TestResourceWithDevice::m_dynamic_resources{};

void
TestResourceWithDevice::onGetDynamicResource(oc_request_t *request,
                                             oc_interface_mask_t,
                                             void *user_data)
{
  const auto *data = static_cast<DynamicResourceData *>(user_data);
  oc_rep_start_root_object();
  oc_rep_set_int(root, power, data->power);
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

void
TestResourceWithDevice::addDynamicResources()
{
  oc::DynamicResourceHandler handlers1{};
  m_dynamic_resources[std::string(kDynamicURI1)] = { 42 };
  handlers1.onGet = onGetDynamicResource;
  handlers1.onGetData = &m_dynamic_resources[std::string(kDynamicURI1)];

  oc::DynamicResourceHandler handlers2{};
  m_dynamic_resources[std::string(kDynamicURI2)] = { 1337 };
  handlers2.onGet = onGetDynamicResource;
  handlers2.onGetData = &m_dynamic_resources[std::string(kDynamicURI2)];

  std::vector<oc::DynamicResourceToAdd> dynResources = {
    oc::makeDynamicResourceToAdd("Dynamic Resource 1",
                                 std::string(kDynamicURI1),
                                 { "oic.d.discoverable", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, handlers1),
    oc::makeDynamicResourceToAdd("Dynamic Resource 2",
                                 std::string(kDynamicURI2),
                                 { "oic.d.undiscoverable", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, handlers2, 0),
  };
  for (const auto &dr : dynResources) {
    oc_resource_t *res = oc::TestDevice::AddDynamicResource(dr, kDevice1ID);
    ASSERT_NE(nullptr, res);
  }
}

#ifdef OC_COLLECTIONS

void
TestResourceWithDevice::addCollections()
{
  constexpr std::string_view powerSwitchRT = "oic.d.power";

  auto col = oc::NewCollection("col", kCollectionURI, kDevice1ID, "oic.wk.col");
  ASSERT_NE(nullptr, col);
  oc_resource_set_discoverable(&col->res, true);
  oc_collection_add_supported_rt(&col->res, powerSwitchRT.data());
  oc_collection_add_mandatory_rt(&col->res, powerSwitchRT.data());
  ASSERT_TRUE(oc_add_collection_v1(&col->res));

  oc::DynamicResourceHandler handlers1{};
  m_dynamic_resources[std::string(kColDynamicURI1)] = { 404 };
  handlers1.onGet = onGetDynamicResource;
  handlers1.onGetData = &m_dynamic_resources[std::string(kColDynamicURI1)];

  auto dr1 = oc::makeDynamicResourceToAdd(
    "Collection Resource 1", std::string(kColDynamicURI1),
    { std::string(powerSwitchRT), "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
    handlers1);
  oc_resource_t *res1 = oc::TestDevice::AddDynamicResource(dr1, kDevice1ID);
  ASSERT_NE(nullptr, res1);
  oc_link_t *link1 = oc_new_link(res1);
  ASSERT_NE(link1, nullptr);
  oc_collection_add_link(&col->res, link1);

  col.release();
}

#endif /* OC_COLLECTIONS */

#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */

TEST_F(TestResourceWithDevice, IteratePlatformResources)
{
  auto store_platform = [](oc_resource_t *resource, void *data) {
    auto *platform = static_cast<std::set<std::string> *>(data);
    platform->insert(oc_string(resource->uri));
    return true;
  };

  std::set<std::string, std::less<>> platform1{};
  oc_resources_iterate_platform(store_platform, &platform1);
  ASSERT_FALSE(platform1.empty());

  std::set<std::string, std::less<>> platform2{};
  oc_resources_iterate_platform(
    [](oc_resource_t *resource, void *data) {
      auto *platform = static_cast<std::set<std::string> *>(data);
      platform->insert(oc_string(resource->uri));
      return false;
    },
    &platform2);
  ASSERT_EQ(1, platform2.size());

  std::set<std::string, std::less<>> platform3{};
  oc_resources_iterate(0, true, false, false, false, store_platform,
                       &platform3);
  ASSERT_EQ(platform1.size(), platform3.size());
  for (const auto &uri : platform1) {
    EXPECT_EQ(1, platform3.count(uri));
  }
}

TEST_F(TestResourceWithDevice, IterateCoreResources)
{
  auto store_core = [](oc_resource_t *resource, void *data) {
    auto *core = static_cast<std::set<std::string> *>(data);
    core->insert(oc_string(resource->uri));
    return true;
  };

  std::set<std::string, std::less<>> core1{};
  oc_resources_iterate_core(kDevice1ID, store_core, &core1);
  ASSERT_FALSE(core1.empty());

  std::set<std::string, std::less<>> core2{};
  oc_resources_iterate_core(
    kDevice1ID,
    [](oc_resource_t *resource, void *data) {
      auto *core = static_cast<std::set<std::string> *>(data);
      core->insert(oc_string(resource->uri));
      return false;
    },
    &core2);
  ASSERT_EQ(1, core2.size());

  std::set<std::string, std::less<>> core3{};
  oc_resources_iterate(kDevice1ID, false, true, false, false, store_core,
                       &core3);
  ASSERT_EQ(core1.size(), core3.size());
  for (const auto &uri : core1) {
    EXPECT_EQ(1, core3.count(uri));
  }

#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)
  std::set<std::string, std::less<>> core4{};
  oc_resources_iterate_core(kDevice2ID, store_core, &core4);
  ASSERT_FALSE(core4.empty());
  // first device contains dynamic and collection resources
  // but core resources are the same for both devices
  ASSERT_EQ(core1.size(), core4.size());
  for (const auto &uri : core4) {
    EXPECT_EQ(1, core1.count(uri));
  }
#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */
}

#if defined(OC_SERVER) && defined(OC_DYNAMIC_ALLOCATION)

TEST_F(TestResourceWithDevice, IterateDynamicResources)
{
  auto store_dynamic = [](oc_resource_t *resource, void *data) {
    auto *dynamic = static_cast<std::set<std::string> *>(data);
    dynamic->insert(oc_string(resource->uri));
    return true;
  };

  std::set<std::string, std::less<>> dynamic1{};
  oc_resources_iterate_dynamic(kDevice1ID, store_dynamic, &dynamic1);
  ASSERT_FALSE(dynamic1.empty());

  std::set<std::string, std::less<>> dynamic2{};
  oc_resources_iterate_dynamic(
    kDevice1ID,
    [](oc_resource_t *resource, void *data) {
      auto *dynamic = static_cast<std::set<std::string> *>(data);
      dynamic->insert(oc_string(resource->uri));
      return false;
    },
    &dynamic2);
  ASSERT_EQ(1, dynamic2.size());

  std::set<std::string, std::less<>> dynamic3{};
  oc_resources_iterate(kDevice1ID, false, false, true, false, store_dynamic,
                       &dynamic3);
  ASSERT_EQ(dynamic1.size(), dynamic3.size());
  for (const auto &uri : dynamic1) {
    EXPECT_EQ(1, dynamic3.count(uri));
  }

  std::set<std::string, std::less<>> dynamic4{};
  oc_resources_iterate_dynamic(kDevice2ID, store_dynamic, &dynamic4);
// seconds device doesn't contain any dynamic resources
#ifdef OC_HAS_FEATURE_PUSH
  // except when push feature is enabled
  dynamic4.erase(PUSHRECEIVERS_RESOURCE_PATH);
#endif /* OC_HAS_FEATURE_PUSH */
  ASSERT_TRUE(dynamic4.empty());
}

TEST_F(TestResourceWithDevice, IterateCollectionResources)
{
  auto store_collection = [](oc_resource_t *resource, void *data) {
    auto *collection = static_cast<std::set<std::string> *>(data);
    collection->insert(oc_string(resource->uri));
    return true;
  };

  std::set<std::string, std::less<>> collection1{};
  oc_resources_iterate_collections(kDevice1ID, store_collection, &collection1);
  ASSERT_FALSE(collection1.empty());

  std::set<std::string, std::less<>> collection2{};
  oc_resources_iterate_collections(
    kDevice1ID,
    [](oc_resource_t *resource, void *data) {
      auto *collection = static_cast<std::set<std::string> *>(data);
      collection->insert(oc_string(resource->uri));
      return false;
    },
    &collection2);
  ASSERT_EQ(1, collection2.size());

  std::set<std::string, std::less<>> collection3{};
  oc_resources_iterate(kDevice1ID, false, false, false, true, store_collection,
                       &collection3);
  ASSERT_EQ(collection1.size(), collection3.size());
  for (const auto &uri : collection1) {
    EXPECT_EQ(1, collection3.count(uri));
  }

  std::set<std::string, std::less<>> collection4{};
  oc_resources_iterate_collections(kDevice2ID, store_collection, &collection4);
  // seconds device doesn't contain any collections
#ifdef OC_HAS_FEATURE_PUSH
  // except when push feature is enabled
  collection4.erase(PUSHCONFIG_RESOURCE_PATH);
#endif /* OC_HAS_FEATURE_PUSH */
  ASSERT_TRUE(collection4.empty());
}

#endif /* OC_SERVER && OC_DYNAMIC_ALLOCATION */

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

constexpr oc_pos_description_t kBaselinePosDesc = OC_POS_CENTRE;
constexpr oc_enum_t kBaselineFuncDesc = OC_ENUM_TESTING;
constexpr struct oc_pos_rel_t
{
  double x;
  double y;
  double z;
} kBaselinePosRel{ 42.0, 13.37, 10.01 };
constexpr oc_locn_t kBaselineLocn = OCF_LOCN_DUNGEON;

static void
checkBaselineProperties(const oc_rep_t *rep)
{
  // if
  // rt
  // tag-pos-desc
  // tag-func-desc
  // tag-locn
  // tag-pos-rel

  char *str = nullptr;
  size_t size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "n", &str, &size));
  EXPECT_STREQ(kDevice1Name.data(), str);

  oc_string_array_t arr{};
  size = 0;
  EXPECT_TRUE(oc_rep_get_string_array(rep, "rt", &arr, &size));
  EXPECT_EQ(1, size);
  EXPECT_STREQ("oic.wk.con", oc_string_array_get_item(arr, 0));

  str = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "tag-pos-desc", &str, &size));
  EXPECT_STREQ(oc_enum_pos_desc_to_str(kBaselinePosDesc), str);

  double *darr = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_double_array(rep, "tag-pos-rel", &darr, &size));
  EXPECT_EQ(3, size);
  EXPECT_EQ(kBaselinePosRel.x, darr[0]);
  EXPECT_EQ(kBaselinePosRel.y, darr[1]);
  EXPECT_EQ(kBaselinePosRel.z, darr[2]);

  str = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "tag-func-desc", &str, &size));
  EXPECT_STREQ(oc_enum_to_str(kBaselineFuncDesc), str);

  str = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "tag-locn", &str, &size));
  EXPECT_STREQ(oc_enum_locn_to_str(kBaselineLocn), str);
}

TEST_F(TestResourceWithDevice, BaselineInterfaceProperties)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDevice1ID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
    *static_cast<bool *>(data->user_data) = true;

    const oc_rep_t *rep = data->payload;
    while (rep != nullptr) {
      EXPECT_TRUE(oc_rep_is_baseline_interface_property(rep));
      rep = rep->next;
    }
    checkBaselineProperties(data->payload);
  };

  oc_resource_t *con = oc_core_get_resource_by_index(OCF_CON, kDevice1ID);
  ASSERT_NE(nullptr, con);
  oc_resource_tag_pos_desc(con, kBaselinePosDesc);
  oc_resource_tag_pos_rel(con, kBaselinePosRel.x, kBaselinePosRel.y,
                          kBaselinePosRel.z);
  oc_resource_tag_func_desc(con, kBaselineFuncDesc);
  oc_resource_tag_locn(con, kBaselineLocn);

  auto timeout = 1s;
  bool invoked = false;
  EXPECT_TRUE(oc_do_get_with_timeout("/oc/con", &ep, "if=" OC_IF_BASELINE_STR,
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(IsSendResponseCallbackInvoked());

  EXPECT_TRUE(invoked);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
