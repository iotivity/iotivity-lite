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

#include "oc_config.h"

#ifdef OC_COLLECTIONS

#include "api/oc_collection_internal.h"
#include "api/oc_event_callback_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_link_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/oc_coap.h"
#include "oc_collection.h"
#include "port/oc_random.h"
#include "tests/gtest/Collection.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_features.h"
#include "util/oc_mmem_internal.h"

#ifdef OC_HAS_FEATURE_ETAG
#include "oc_etag.h"
#endif /* OC_HAS_FEATURE_ETAG */

#include <algorithm>
#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

using namespace std::chrono_literals;

constexpr size_t kDeviceID = 0;

namespace {
oc::oc_collection_unique_ptr
MakeCollection()
{
  return oc::oc_collection_unique_ptr(oc_collection_alloc(),
                                      &oc_collection_free);
}

size_t
CountCollections()
{
  size_t count = 0;
  auto *collection = oc_collection_get_all();
  while (collection != nullptr) {
    ++count;
    collection = reinterpret_cast<oc_collection_t *>(collection->res.next);
  }
  return count;
}

size_t
CountLinksInCollection(oc_collection_t *collection)
{
  size_t count = 0;
  auto *link = oc_collection_get_links(&collection->res);
  while (link != nullptr) {
    ++count;
    link = link->next;
  }
  return count;
}

}

class TestCollections : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_random_init(); // oc_random_value is needed by oc_new_link
  }

  static void TearDownTestCase() { oc_random_destroy(); }

  void SetUp() override { oc_event_callbacks_init(); }

  void TearDown() override { oc_event_callbacks_shutdown(); }
};

TEST_F(TestCollections, Alloc)
{
  oc_collection_t *collection = oc_collection_alloc();
  ASSERT_NE(nullptr, collection);
  oc_collection_free(collection);
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestCollections, AllocFail)
{
  std::vector<oc::oc_collection_unique_ptr> collections{};
  for (int i = 0; i < OC_MAX_NUM_COLLECTIONS; ++i) {
    auto collection = MakeCollection();
    ASSERT_NE(nullptr, collection);
    collections.emplace_back(std::move(collection));
  }
  EXPECT_EQ(nullptr, MakeCollection());
}
#endif /* !OC_DYNAMIC_ALLOCATION */

TEST_F(TestCollections, Add)
{
  auto collection1 = oc::NewCollection("name1", "/uri", 0);
  ASSERT_NE(nullptr, collection1);
  ASSERT_TRUE(oc_add_collection_v1(&collection1->res));
  EXPECT_EQ(1, CountCollections());

  // different device
  auto collection2 = oc::NewCollection("name2", "/uri", 1);
  ASSERT_NE(nullptr, collection2);
  ASSERT_TRUE(oc_add_collection_v1(&collection2->res));
  EXPECT_EQ(2, CountCollections());

  // different uri
  auto collection3 = oc::NewCollection("name3", "/uri2", 0);
  ASSERT_NE(nullptr, collection3);
  ASSERT_TRUE(oc_add_collection_v1(&collection3->res));
  EXPECT_EQ(3, CountCollections());
}

TEST_F(TestCollections, Add_FailSameCollection)
{
  auto collection1 = oc::NewCollection("name1", "/uri", kDeviceID);
  ASSERT_NE(nullptr, collection1);
  ASSERT_TRUE(oc_add_collection_v1(&collection1->res));
  EXPECT_FALSE(oc_add_collection_v1(&collection1->res));
}

TEST_F(TestCollections, AddSupportedResourceType)
{
  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);

  std::string srt1 = "rt1";
  EXPECT_TRUE(oc_collection_add_supported_rt(&collection->res, srt1.c_str()));

  // adding the same resource type again should fail
  EXPECT_FALSE(oc_collection_add_supported_rt(&collection->res, srt1.c_str()));
}

TEST_F(TestCollections, AddSupportedResourceType_Multiple)
{
  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);

  for (int i = 0; i < OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX; ++i) {
    std::string srt = "rt" + std::to_string(i);
    EXPECT_TRUE(oc_collection_add_supported_rt(&collection->res, srt.c_str()));
  }
  EXPECT_EQ(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX,
            oc_list_length(collection->supported_rts));

  std::string srt =
    "rt" + std::to_string(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX);
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_TRUE(oc_collection_add_supported_rt(&collection->res, srt.c_str()));
  EXPECT_EQ(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX + 1,
            oc_list_length(collection->supported_rts));
#else  /* !OC_DYNAMIC_ALLOCATION */
  EXPECT_FALSE(oc_collection_add_supported_rt(&collection->res, srt.c_str()));
  EXPECT_EQ(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX,
            oc_list_length(collection->supported_rts));
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestCollections, AddMandatoryResourceType)
{
  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);

  std::string mrt1 = "rt1";
  EXPECT_TRUE(oc_collection_add_mandatory_rt(&collection->res, mrt1.c_str()));

  // adding the same resource type again should fail
  EXPECT_FALSE(oc_collection_add_mandatory_rt(&collection->res, mrt1.c_str()));
}

TEST_F(TestCollections, AddMandatoryResourceType_Multiple)
{
  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);

  for (int i = 0; i < OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX; ++i) {
    std::string mrt = "rt" + std::to_string(i);
    EXPECT_TRUE(oc_collection_add_mandatory_rt(&collection->res, mrt.c_str()));
  }
  EXPECT_EQ(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX,
            oc_list_length(collection->mandatory_rts));

  std::string mrt =
    "rt" + std::to_string(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX);
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_TRUE(oc_collection_add_mandatory_rt(&collection->res, mrt.c_str()));
  EXPECT_EQ(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX + 1,
            oc_list_length(collection->mandatory_rts));
#else  /* !OC_DYNAMIC_ALLOCATION */
  EXPECT_FALSE(oc_collection_add_mandatory_rt(&collection->res, mrt.c_str()));
  EXPECT_EQ(OC_COLLECTION_RESOURCE_TYPES_COUNT_MAX,
            oc_list_length(collection->mandatory_rts));
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestCollections, Free)
{
  oc_collection_free(nullptr);
}

TEST_F(TestCollections, AddLink)
{
  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);

  EXPECT_EQ(0, CountLinksInCollection(collection.get()));

  std::string uri_1 = "/a";
  oc_resource_t resource_1{};
  resource_1.uri = OC_MMEM(&uri_1[0], uri_1.length() + 1, nullptr);
  oc_link_t *link_1 = oc_new_link(&resource_1);
  ASSERT_NE(link_1, nullptr);
  oc_collection_add_link(&collection->res, link_1);
  EXPECT_EQ(1, CountLinksInCollection(collection.get()));

  std::string uri_2 = "/b";
  oc_resource_t resource_2{};
  resource_2.uri = OC_MMEM(&uri_2[0], uri_2.length() + 1, nullptr);
  oc_link_t *link_2 = oc_new_link(&resource_2);
  ASSERT_NE(link_2, nullptr);
  oc_collection_add_link(&collection->res, link_2);
  EXPECT_EQ(2, CountLinksInCollection(collection.get()));
}

TEST_F(TestCollections, AddLink_Fail)
{
  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);

  oc_link_t link{};
  oc_collection_add_link(&collection->res, &link);

  oc_resource_t resource{};
  link.resource = &resource;
  oc_collection_add_link(&collection->res, &link);
}

TEST_F(TestCollections, RemoveLink)
{
  oc_collection_remove_link(nullptr, nullptr);

  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);
  oc_collection_remove_link(&collection->res, nullptr);

  std::string uri_1 = "/ccc";
  oc_resource_t resource_1{};
  resource_1.uri = OC_MMEM(&uri_1[0], uri_1.length() + 1, nullptr);
  oc_link_t *link_1 = oc_new_link(&resource_1);
  ASSERT_NE(link_1, nullptr);
  oc_collection_add_link(&collection->res, link_1);

  std::string uri_2 = "/bb";
  oc_resource_t resource_2{};
  resource_2.uri = OC_MMEM(&uri_2[0], uri_2.length() + 1, nullptr);
  oc_link_t *link_2 = oc_new_link(&resource_2);
  ASSERT_NE(link_2, nullptr);
  oc_collection_add_link(&collection->res, link_2);

  std::string uri_3 = "/a";
  oc_resource_t resource_3{};
  resource_3.uri = OC_MMEM(&uri_3[0], uri_3.length() + 1, nullptr);
  oc_link_t *link_3 = oc_new_link(&resource_3);
  ASSERT_NE(link_3, nullptr);
  oc_collection_add_link(&collection->res, link_3);

  EXPECT_EQ(3, CountLinksInCollection(collection.get()));
  oc_collection_remove_link(&collection->res, link_1);
  oc_delete_link(link_1);
  EXPECT_EQ(2, CountLinksInCollection(collection.get()));
  oc_collection_remove_link(&collection->res, link_2);
  oc_delete_link(link_2);
  EXPECT_EQ(1, CountLinksInCollection(collection.get()));
  oc_collection_remove_link(&collection->res, link_3);
  oc_delete_link(link_3);
  EXPECT_EQ(0, CountLinksInCollection(collection.get()));
}

TEST_F(TestCollections, GetAllLinks)
{
  EXPECT_EQ(nullptr, oc_collection_get_links(nullptr));
}

TEST_F(TestCollections, GetLinkByURI)
{
  EXPECT_EQ(nullptr, oc_get_link_by_uri(nullptr, nullptr, 0));

  auto collection = MakeCollection();
  ASSERT_NE(nullptr, collection);
  EXPECT_EQ(nullptr, oc_get_link_by_uri(collection.get(), nullptr, 0));
  EXPECT_EQ(nullptr, oc_get_link_by_uri(collection.get(), "", 0));

  std::string uri_1 = "/aaa";
  oc_resource_t resource_1{};
  resource_1.uri = OC_MMEM(&uri_1[0], uri_1.length() + 1, nullptr);
  oc_link_t *link_1 = oc_new_link(&resource_1);
  ASSERT_NE(link_1, nullptr);
  oc_collection_add_link(&collection->res, link_1);

  std::string uri_2 = "/bbb";
  oc_resource_t resource_2{};
  resource_2.uri = OC_MMEM(&uri_2[0], uri_2.length() + 1, nullptr);
  oc_link_t *link_2 = oc_new_link(&resource_2);
  ASSERT_NE(link_2, nullptr);
  oc_collection_add_link(&collection->res, link_2);

  ASSERT_EQ(2, CountLinksInCollection(collection.get()));

  std::string uri = "/test";
  EXPECT_EQ(nullptr,
            oc_get_link_by_uri(collection.get(), uri.c_str(), uri.length()));
  uri = "/";
  EXPECT_EQ(nullptr,
            oc_get_link_by_uri(collection.get(), uri.c_str(), uri.length()));
  uri = "/aaaaa";
  EXPECT_EQ(nullptr,
            oc_get_link_by_uri(collection.get(), uri.c_str(), uri.length()));

  EXPECT_EQ(link_1, oc_get_link_by_uri(collection.get(), uri_1.c_str(),
                                       uri_1.length()));
  EXPECT_EQ(link_2, oc_get_link_by_uri(collection.get(), uri_2.c_str(),
                                       uri_2.length()));
}

#ifdef OC_COLLECTIONS_IF_CREATE

// TODO: add test cases

#endif // OC_COLLECTIONS_IF_CREATE

namespace {

constexpr std::string_view switchRT = "test.r.switch";
constexpr auto switchIF =
  static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_R);
constexpr std::string_view colRT = "test.r.col";

constexpr std::string_view col1Name = "Switch collection";
constexpr std::string_view col1URI = "/switches";

constexpr std::string_view switch1Name{ "test switch" };
constexpr std::string_view switch1URI{ "/switches/1" };
constexpr std::array<double, 3> switch1Pos = { 0.34, 0.5, 0.8 };

constexpr std::string_view col2Name = "Inner collection";
constexpr std::string_view col2URI = "/switches/inner";

constexpr std::string_view switch2Name{ "inner switch" };
constexpr std::string_view switch2URI{ "/switches/inner/1" };

struct SwitchData
{
  bool state = false;
};

struct CollectionData
{
  std::string label = {};
  int power = 0;
};

} // namespace

class TestCollectionsWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void SetUp() override
  {
    switch1Data = SwitchData{ true };
    switch2Data = SwitchData{ false };

    col1Data = { "label 1", 42 };
    col2Data = { "label 2", 1337 };
  }

  void TearDown() override
  {
    for (auto *resource : resources) {
      oc_delete_resource(resource);
    }
    resources.clear();
    oc_collections_free_all();
  }

  static oc_resource_t *makeSwitch(std::string_view name, std::string_view uri,
                                   size_t device,
                                   oc_request_callback_t callback,
                                   SwitchData *switchData);
  static oc_resource_t *makeSwitch(std::string_view name, std::string_view uri,
                                   size_t device, SwitchData *switchData);

  static oc::oc_collection_unique_ptr makeSwitchCollection(
    std::string_view name, std::string_view uri, std::string_view rt,
    size_t device, CollectionData *colData);

  static void makeTestResources();

#ifdef OC_HAS_FEATURE_ETAG
  static void assertETag(oc_coap_etag_t etag1, uint64_t etag2);
  static void assertResourceETag(oc_coap_etag_t etag,
                                 const oc_resource_t *resource);
  static void assertCollectionETag(oc_coap_etag_t etag, std::string_view uri,
                                   size_t device, bool is_batch = false);
#if 0
  static void assertBatchETag(oc_coap_etag_t etag, std::string_view uri,
                              size_t device,
                              const oc::Collection::BatchData &bd);
#endif
#endif // OC_HAS_FEATURE_ETAG

  static std::vector<oc_resource_t *> resources;
  static SwitchData switch1Data;
  static SwitchData switch2Data;
  static CollectionData col1Data;
  static CollectionData col2Data;
};

std::vector<oc_resource_t *> TestCollectionsWithServer::resources{};
SwitchData TestCollectionsWithServer::switch1Data{};
SwitchData TestCollectionsWithServer::switch2Data{};
CollectionData TestCollectionsWithServer::col1Data{};
CollectionData TestCollectionsWithServer::col2Data{};

void
TestCollectionsWithServer::makeTestResources()
{
  auto col1 = makeSwitchCollection(col1Name.data(), col1URI.data(),
                                   colRT.data(), kDeviceID, &col1Data);
  ASSERT_NE(nullptr, col1);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  ASSERT_TRUE(oc::SetAccessInRFOTM(&col1->res, true, OC_PERM_RETRIEVE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  ASSERT_TRUE(oc_add_collection_v1(&col1->res));

  auto *bswitch1 = makeSwitch(switch1Name, switch1URI, kDeviceID, &switch1Data);
  ASSERT_NE(nullptr, bswitch1);
  oc_resource_tag_func_desc(bswitch1, OC_ENUM_SMART);
  oc_resource_tag_pos_rel(bswitch1, switch1Pos[0], switch1Pos[1],
                          switch1Pos[2]);
  oc_resource_tag_pos_desc(bswitch1, OC_POS_TOP);
  ASSERT_TRUE(oc_add_resource(bswitch1));
  resources.push_back(bswitch1);

  oc_link_t *link1 = oc_new_link(bswitch1);
  ASSERT_NE(link1, nullptr);
  EXPECT_TRUE(oc_link_add_link_param(link1, "tag", "test"));
  EXPECT_TRUE(oc_link_add_link_param(link1, "hidden", "true"));
  oc_collection_add_link(&col1->res, link1);

  auto col2 = makeSwitchCollection(col2Name.data(), col2URI.data(),
                                   colRT.data(), kDeviceID, &col2Data);
  ASSERT_NE(nullptr, col2);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  ASSERT_TRUE(oc::SetAccessInRFOTM(&col2->res, true, OC_PERM_RETRIEVE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  ASSERT_TRUE(oc_add_collection_v1(&col2->res));

  auto *bswitch2 = makeSwitch(switch2Name, switch2URI, kDeviceID, &switch2Data);
  ASSERT_NE(nullptr, bswitch2);
  ASSERT_TRUE(oc_add_resource(bswitch2));
  resources.push_back(bswitch2);

  oc_link_t *link2 = oc_new_link(bswitch2);
  ASSERT_NE(link2, nullptr);
  oc_collection_add_link(&col2->res, link2);

  // link col2 to col1
  oc_link_t *link3 = oc_new_link(&col2->res);
  ASSERT_NE(link3, nullptr);
  oc_collection_add_link(&col1->res, link3);

  col2.release();
  col1.release();
}

oc::oc_collection_unique_ptr
TestCollectionsWithServer::makeSwitchCollection(std::string_view name,
                                                std::string_view uri,
                                                std::string_view rt,
                                                size_t device,
                                                CollectionData *colData)
{
  auto setProps = [](const oc_resource_t *, const oc_rep_t *rep, void *data) {
    auto *cData = static_cast<CollectionData *>(data);
    while (rep != nullptr) {
      switch (rep->type) {
      case OC_REP_STRING:
        cData->label = oc_string(rep->value.string);
        break;
      case OC_REP_INT:
        cData->power = static_cast<int>(rep->value.integer);
        break;
      default:
        break;
      }
      rep = rep->next;
    }
    return true;
  };

  auto getProps = [](const oc_resource_t *, oc_interface_mask_t, void *data) {
    const auto *cData = static_cast<CollectionData *>(data);
    oc_rep_set_text_string_v1(root, label, cData->label.c_str(),
                              cData->label.length());
    oc_rep_set_int(root, power, cData->power);
  };

  auto col = oc::NewCollection(name.data(), uri.data(), device, rt.data());
  if (!col) {
    return oc::oc_collection_unique_ptr(nullptr, nullptr);
  }

  oc_collection_add_supported_rt(&col->res, switchRT.data());
  oc_collection_add_mandatory_rt(&col->res, switchRT.data());
  oc_resource_set_properties_cbs(&col->res, getProps, colData, setProps,
                                 colData);
  return col;
}

oc_resource_t *
TestCollectionsWithServer::makeSwitch(std::string_view name,
                                      std::string_view uri, size_t device,
                                      oc_request_callback_t callback,
                                      SwitchData *switchData)
{
  oc_resource_t *bswitch = oc_new_resource(name.data(), uri.data(), 1, device);
  if (bswitch == nullptr) {
    return nullptr;
  }

  oc_resource_bind_resource_type(bswitch, switchRT.data());
  oc_resource_bind_resource_interface(bswitch, switchIF);
  oc_resource_set_default_interface(bswitch, OC_IF_R);
  oc_resource_set_discoverable(bswitch, true);
  oc_resource_set_observable(bswitch, true);
  oc_resource_set_request_handler(bswitch, OC_GET, callback, switchData);
  return bswitch;
}

oc_resource_t *
TestCollectionsWithServer::makeSwitch(std::string_view name,
                                      std::string_view uri, size_t device,
                                      SwitchData *switchData)
{
  auto getSwitch = [](oc_request_t *request, oc_interface_mask_t iface_mask,
                      void *user_data) {
    const auto *data = static_cast<SwitchData *>(user_data);
    oc_rep_start_root_object();
    switch (iface_mask) {
    case OC_IF_BASELINE:
      oc_process_baseline_interface(request->resource);
      [[fallthrough]];
    case OC_IF_R:
      oc_rep_set_boolean(root, state, data->state);
      break;
    default:
      break;
    }
    oc_rep_end_root_object();

    oc_send_response(request, OC_STATUS_OK);
  };

  return makeSwitch(name, uri, device, getSwitch, switchData);
}

#ifdef OC_HAS_FEATURE_ETAG

void
TestCollectionsWithServer::assertETag(oc_coap_etag_t etag1, uint64_t etag2)
{
  ASSERT_EQ(sizeof(etag2), etag1.length);
  std::array<uint8_t, sizeof(etag2)> etag2_buf;
  memcpy(&etag2_buf[0], &etag2, etag2_buf.size());
  ASSERT_EQ(0, memcmp(etag1.value, &etag2_buf, etag1.length));
}

void
TestCollectionsWithServer::assertResourceETag(oc_coap_etag_t etag,
                                              const oc_resource_t *resource)
{
  ASSERT_NE(nullptr, resource);
  assertETag(etag, resource->etag);
}

void
TestCollectionsWithServer::assertCollectionETag(oc_coap_etag_t etag,
                                                std::string_view uri,
                                                size_t device, bool is_batch)
{
  const auto *col = oc_get_collection_by_uri(uri.data(), uri.length(), device);
  ASSERT_NE(nullptr, col);
  if (is_batch) {
    assertETag(etag, oc_collection_get_batch_etag(col));
  } else {
    assertResourceETag(etag, &col->res);
  }
}

#if 0

void
TestCollectionsWithServer::assertBatchETag(oc_coap_etag_t etag, std::string_view uri,
                                           size_t device,
                                           const oc::Collection::BatchData &bd)
{
  const auto *col = oc_get_collection_by_uri(uri.data(), uri.length(), device);
  ASSERT_NE(nullptr, col);
  uint64_t max_etag = col->res.etag;
  for (const auto &[_, value] : bd) {
    ASSERT_EQ(sizeof(uint64_t), value.etag.size());
    uint64_t etag_value = 0;
    memcpy(&etag_value, value.etag.data(), value.etag.size());
    if (etag_value > max_etag) {
      max_etag = etag_value;
    }
  }
  assertETag(etag, max_etag);
}

#endif

#endif // OC_HAS_FEATURE_ETAG

TEST_F(TestCollectionsWithServer, New)
{
  std::string name = "col";
  std::string uri = "/col";
  oc_resource_t *col =
    oc_new_collection(name.c_str(), uri.c_str(), 0, kDeviceID);
  ASSERT_NE(nullptr, col);

  EXPECT_STREQ(name.c_str(), oc_string(col->name));
  EXPECT_STREQ(uri.c_str(), oc_string(col->uri));
  EXPECT_EQ(kDeviceID, col->device);

  oc_delete_collection(col);

  std::string uri2 = "col"; // oc_new_collection will add a leading slash
  oc_resource_t *col2 = oc_new_collection(nullptr, uri2.c_str(), 0, kDeviceID);
  ASSERT_NE(nullptr, col2);

  EXPECT_EQ(nullptr, oc_string(col2->name));
  EXPECT_STREQ(("/" + uri2).c_str(), oc_string(col2->uri));
  EXPECT_EQ(kDeviceID, col2->device);

  oc_delete_collection(col2);
}

TEST_F(TestCollectionsWithServer, Add_FailSameURI)
{
  // cannot match core resource
  auto col1 = oc::NewCollection("name1", "/oic/p", kDeviceID);
  ASSERT_NE(nullptr, col1);
  EXPECT_FALSE(oc_add_collection_v1(&col1->res));

  // cannot match an existing dynamic resource
  oc_resource_t *dyn1 = oc_new_resource("platform", "/dyn1", 1, kDeviceID);
  ASSERT_NE(nullptr, dyn1);
  oc_resource_set_request_handler(
    dyn1, OC_GET,
    [](oc_request_t *, oc_interface_mask_t, void *) {
      // no-op
    },
    nullptr);
  ASSERT_TRUE(oc_ri_add_resource(dyn1));

  auto col2 = oc::NewCollection("name2", oc_string(dyn1->uri), kDeviceID);
  ASSERT_NE(nullptr, col2);
  EXPECT_FALSE(oc_add_collection_v1(&col2->res));

  auto col3 = oc::NewCollection("name3", "/col", kDeviceID);
  ASSERT_NE(nullptr, col3);
  ASSERT_TRUE(oc_add_collection_v1(&col3->res));

  auto col4 = oc::NewCollection("name4", "/col", kDeviceID);
  ASSERT_NE(nullptr, col4);
  EXPECT_FALSE(oc_add_collection_v1(&col4->res));

  ASSERT_TRUE(oc_ri_delete_resource(dyn1));
}

TEST_F(TestCollectionsWithServer, CheckIfCollection)
{
  EXPECT_FALSE(oc_check_if_collection(nullptr));

  auto col = oc::NewCollection("col", "/col", kDeviceID);
  ASSERT_NE(nullptr, col);

  // collection hasn't been added to the global list of collections yet
  EXPECT_FALSE(oc_check_if_collection(&col->res));
  size_t num_collections = CountCollections();

  // add collection to the global list of collections
  ASSERT_TRUE(oc_collection_add(col.get()));
  EXPECT_TRUE(oc_check_if_collection(&col->res));
  EXPECT_EQ(num_collections + 1, CountCollections());

  // freeing the collection should remove it from the list
  col.reset();
  EXPECT_EQ(num_collections, CountCollections());
}

TEST_F(TestCollectionsWithServer, GetByURI)
{
  EXPECT_EQ(nullptr, oc_get_collection_by_uri("", 0, kDeviceID));

  auto col = oc::NewCollection("col", "/col", kDeviceID);
  ASSERT_NE(nullptr, col);
  ASSERT_TRUE(oc_collection_add(col.get()));

  std::string uri = "/col";
  EXPECT_EQ(col.get(),
            oc_get_collection_by_uri(uri.c_str(), uri.length(), kDeviceID));

  // uri without the leading slash should also work
  std::string uri2 = "col";
  EXPECT_EQ(col.get(),
            oc_get_collection_by_uri(uri2.c_str(), uri2.length(), kDeviceID));

  // unknown uri should return nullptr
  std::string uri3 = "/leet";
  EXPECT_EQ(nullptr,
            oc_get_collection_by_uri(uri3.c_str(), uri3.length(), kDeviceID));

  // uri with a different device id should return nullptr
  size_t badDeviceID = std::numeric_limits<size_t>::max();
  EXPECT_EQ(nullptr,
            oc_get_collection_by_uri(uri.c_str(), uri.length(), badDeviceID));
}

#ifdef OC_HAS_FEATURE_ETAG

#if 0

TEST_F(TestCollectionsWithServer, GetBatchETag)
{
  auto col = makeSwitchCollection(col1Name.data(), col1URI.data(), colRT.data(),
                                  kDeviceID, &col1Data);
  ASSERT_NE(nullptr, col);
  ASSERT_TRUE(oc_add_collection_v1(&col->res));

  // no links -> batch etag should be equal to the collection's etag
  EXPECT_EQ(col->res.etag, oc_collection_get_batch_etag(col.get()));

  // add links -> batch etag should be equal to the last changed resource's etag
  for (int i = 0; i < 2; ++i) {
    std::string uri = std::string(col1URI) + "/" + std::to_string(i);
    oc_resource_t *bswitch = makeSwitch(
      "switch", uri, kDeviceID,
      [](oc_request_t *, oc_interface_mask_t, void *) {
        // no-op
      }, nullptr);
    ASSERT_NE(nullptr, bswitch);
    ASSERT_TRUE(oc_add_resource(bswitch));
    resources.push_back(bswitch);

    oc_link_t *link = oc_new_link(bswitch);
    ASSERT_NE(link, nullptr);
    oc_collection_add_link(&col->res, link);
  }
  auto *bswitch = resources.back();
  oc_notify_resource_changed(bswitch);
  EXPECT_EQ(bswitch->etag, oc_collection_get_batch_etag(col.get()));
}

#endif

TEST_F(TestCollectionsWithServer, GetETagAfterLinkAddOrRemove)
{
  auto col = makeSwitchCollection(col1Name.data(), col1URI.data(), colRT.data(),
                                  kDeviceID, &col1Data);
  ASSERT_NE(nullptr, col);
  ASSERT_TRUE(oc_add_collection_v1(&col->res));
  uint64_t etag1 = col->res.etag;

  // create dynamic resource
  std::string uri = std::string(col1URI) + "/1";
  oc_resource_t *bswitch = makeSwitch(
    "switch", uri, kDeviceID,
    [](oc_request_t *, oc_interface_mask_t, void *) {
      // no-op
    },
    nullptr);
  ASSERT_NE(nullptr, bswitch);
  ASSERT_TRUE(oc_add_resource(bswitch));
  resources.push_back(bswitch);
  // creating a resource shouldn't change etag
  EXPECT_EQ(etag1, col->res.etag);

  // adding a link should change etag
  oc_link_t *link = oc_new_link(bswitch);
  ASSERT_NE(link, nullptr);
  oc_collection_add_link(&col->res, link);
  uint64_t etag2 = col->res.etag;
  EXPECT_NE(etag1, etag2);

  // removing a link should change etag
  oc_collection_remove_link(&col->res, link);
  oc_delete_link(link);
  uint64_t etag3 = col->res.etag;
  EXPECT_NE(etag2, etag3);
}

#endif // OC_HAS_FEATURE_ETAG

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

TEST_F(TestCollectionsWithServer, GetRequest_Baseline)
{
  makeTestResources();

  auto col1 =
    oc_get_collection_by_uri(col1URI.data(), col1URI.length(), kDeviceID);
  ASSERT_NE(nullptr, col1);

  // get insecure connection to the testing device
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
#ifdef OC_HAS_FEATURE_ETAG
    assertCollectionETag(data->etag, col1URI, data->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto cData = oc::Collection::ParsePayload(data->payload);
    ASSERT_TRUE(cData.has_value());
    *static_cast<oc::Collection::Data *>(data->user_data) =
      std::move(cData.value());
  };

  oc::Collection::Data data{};
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_get_with_timeout(oc_string(col1->res.uri), &ep,
                                     "if=" OC_IF_BASELINE_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &data));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_STREQ(col1Name.data(), data.baseline->name.c_str());
  ASSERT_EQ(1, data.baseline->rts.size());
  EXPECT_STREQ(colRT.data(), data.baseline->rts[0].c_str());
  ASSERT_EQ(3, data.baseline->ifs.size());

  ASSERT_EQ(1, data.rts.size());
  EXPECT_STREQ(switchRT.data(), data.rts[0].c_str());
  ASSERT_EQ(1, data.rts_m.size());
  EXPECT_STREQ(switchRT.data(), data.rts_m[0].c_str());

  ASSERT_EQ(2, data.links.size());

  const oc::LinkData &switchLink = data.links[switch1URI.data()];
  EXPECT_STREQ(switch1URI.data(), switchLink.href.c_str());
  ASSERT_EQ(1, switchLink.rts.size());
  EXPECT_STREQ(switchRT.data(), switchLink.rts[0].c_str());
  ASSERT_EQ(1, switchLink.rels.size());
  EXPECT_STREQ("hosts", switchLink.rels[0].c_str());
  EXPECT_NE(0, switchLink.ins);
  ASSERT_EQ(2, switchLink.ifs.size());
  EXPECT_NE(
    switchLink.ifs.end(),
    std::find(switchLink.ifs.begin(), switchLink.ifs.end(), OC_IF_BASELINE));
  EXPECT_NE(switchLink.ifs.end(),
            std::find(switchLink.ifs.begin(), switchLink.ifs.end(), OC_IF_R));
  ASSERT_EQ(2, switchLink.params.size());
  EXPECT_STREQ("tag", switchLink.params[0].key.c_str());
  EXPECT_STREQ("test", switchLink.params[0].value.c_str());
  EXPECT_STREQ("hidden", switchLink.params[1].key.c_str());
  EXPECT_STREQ("true", switchLink.params[1].value.c_str());
  EXPECT_EQ(OC_DISCOVERABLE | OC_OBSERVABLE, switchLink.bm);
  EXPECT_FALSE(switchLink.tag_pos_desc.empty());
  EXPECT_FALSE(switchLink.tag_func_desc.empty());
  EXPECT_EQ(3, switchLink.tag_pos_rel.size());
  EXPECT_EQ(switch1Pos[0], switchLink.tag_pos_rel[0]);
  EXPECT_EQ(switch1Pos[1], switchLink.tag_pos_rel[1]);
  EXPECT_EQ(switch1Pos[2], switchLink.tag_pos_rel[2]);
  EXPECT_FALSE(switchLink.eps.empty());

  const oc::LinkData &colLink = data.links[col2URI.data()];
  EXPECT_STREQ(col2URI.data(), colLink.href.c_str());
}

TEST_F(TestCollectionsWithServer, GetRequest_LinkedList)
{
  /* TODO:
   EXPECT_TRUE(
     oc_do_get("/col", ep, "if=" OC_IF_LL_STR, get_handler, HIGH_QOS,
     nullptr));
  */
}

TEST_F(TestCollectionsWithServer, GetRequest_Batch)
{
  makeTestResources();

  auto col1 =
    oc_get_collection_by_uri(col1URI.data(), col1URI.length(), kDeviceID);
  ASSERT_NE(nullptr, col1);

  // get insecure connection to the testing device
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  struct batchData
  {
    oc_status_t code;
    oc::Collection::BatchData data;
  };

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *bd = static_cast<batchData *>(data->user_data);
    bd->code = data->code;
#ifndef OC_SECURITY
    bd->data = oc::Collection::ParseBatchPayload(data->payload);
#ifdef OC_HAS_FEATURE_ETAG
#if 0
    assertCollectionETag(data->etag, col1URI, data->endpoint->device, true);
    // the response etag should be the highest etag contained the payload
    assertBatchETag(data->etag, col1URI, data->endpoint->device, bd->data);
#endif
#endif /* OC_HAS_FEATURE_ETAG */
#endif /* !OC_SECURITY */
  };

  auto timeout = 1s;
  batchData bd{};
  ASSERT_TRUE(oc_do_get_with_timeout(oc_string(col1->res.uri), &ep,
                                     "if=" OC_IF_B_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &bd));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

#ifdef OC_SECURITY
  // need secure endpoint to get batch response if OC_SECURITY is enabled
  ASSERT_EQ(OC_STATUS_BAD_REQUEST, bd.code);
  ASSERT_EQ(0, bd.data.size());
#else  /* !OC_SECURITY */
  ASSERT_EQ(OC_STATUS_OK, bd.code);
  ASSERT_EQ(2, bd.data.size());
#endif /* OC_SECURITY */
}

#endif // !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

#endif /* OC_COLLECTIONS */
