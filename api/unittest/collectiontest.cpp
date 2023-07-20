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
#include "api/oc_link_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_collection.h"
#include "port/oc_random.h"
#include "tests/gtest/Collection.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

using oc_collection_unique_ptr =
  std::unique_ptr<oc_collection_t, void (*)(oc_collection_t *)>;

constexpr size_t kDeviceID = 0;

namespace {
oc_collection_unique_ptr
MakeCollection()
{
  return oc_collection_unique_ptr(oc_collection_alloc(), &oc_collection_free);
}

template<typename... Ts>
oc_collection_unique_ptr
NewCollection(std::string_view name, std::string_view uri,
              size_t deviceID = kDeviceID, const Ts &...resourceTypes)
{
  oc_resource_t *res = oc_new_collection(name.data(), uri.data(),
                                         sizeof...(resourceTypes), deviceID);
  (oc_resource_bind_resource_type(res, resourceTypes), ...);
  return oc_collection_unique_ptr(reinterpret_cast<oc_collection_t *>(res),
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
  std::vector<oc_collection_unique_ptr> collections{};
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
  auto collection1 = NewCollection("name1", "/uri", 0);
  ASSERT_NE(nullptr, collection1);
  ASSERT_TRUE(oc_add_collection_v1(&collection1->res));
  EXPECT_EQ(1, CountCollections());

  // different device
  auto collection2 = NewCollection("name2", "/uri", 1);
  ASSERT_NE(nullptr, collection2);
  ASSERT_TRUE(oc_add_collection_v1(&collection2->res));
  EXPECT_EQ(2, CountCollections());

  // different uri
  auto collection3 = NewCollection("name3", "/uri2", 0);
  ASSERT_NE(nullptr, collection3);
  ASSERT_TRUE(oc_add_collection_v1(&collection3->res));
  EXPECT_EQ(3, CountCollections());
}

TEST_F(TestCollections, Add_FailSameCollection)
{
  auto collection1 = NewCollection("name1", "/uri");
  ASSERT_NE(nullptr, collection1);
  ASSERT_TRUE(oc_add_collection_v1(&collection1->res));
  EXPECT_FALSE(oc_add_collection_v1(&collection1->res));
}

TEST_F(TestCollections, Add_FailSameURI)
{
  auto collection1 = NewCollection("name1", "/uri");
  ASSERT_NE(nullptr, collection1);
  ASSERT_TRUE(oc_add_collection_v1(&collection1->res));

  auto collection2 = NewCollection("name2", "/uri");
  ASSERT_NE(nullptr, collection2);
  EXPECT_FALSE(oc_add_collection_v1(&collection2->res));
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
  resource_1.uri = { nullptr, uri_1.length() + 1, &uri_1[0] };
  oc_link_t *link_1 = oc_new_link(&resource_1);
  ASSERT_NE(link_1, nullptr);
  oc_collection_add_link(&collection->res, link_1);
  EXPECT_EQ(1, CountLinksInCollection(collection.get()));

  std::string uri_2 = "/b";
  oc_resource_t resource_2{};
  resource_2.uri = { nullptr, uri_2.length() + 1, &uri_2[0] };
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
  resource_1.uri = { nullptr, uri_1.length() + 1, &uri_1[0] };
  oc_link_t *link_1 = oc_new_link(&resource_1);
  ASSERT_NE(link_1, nullptr);
  oc_collection_add_link(&collection->res, link_1);

  std::string uri_2 = "/bb";
  oc_resource_t resource_2{};
  resource_2.uri = { nullptr, uri_2.length() + 1, &uri_2[0] };
  oc_link_t *link_2 = oc_new_link(&resource_2);
  ASSERT_NE(link_2, nullptr);
  oc_collection_add_link(&collection->res, link_2);

  std::string uri_3 = "/a";
  oc_resource_t resource_3{};
  resource_3.uri = { nullptr, uri_3.length() + 1, &uri_3[0] };
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
  resource_1.uri = { nullptr, uri_1.length() + 1, &uri_1[0] };
  oc_link_t *link_1 = oc_new_link(&resource_1);
  ASSERT_NE(link_1, nullptr);
  oc_collection_add_link(&collection->res, link_1);

  std::string uri_2 = "/bbb";
  oc_resource_t resource_2{};
  resource_2.uri = { nullptr, uri_2.length() + 1, &uri_2[0] };
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

class TestCollectionsWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

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

TEST_F(TestCollectionsWithServer, CheckIfCollection)
{
  EXPECT_FALSE(oc_check_if_collection(nullptr));

  auto col = NewCollection("col", "/col");
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

  auto col = NewCollection("col", "/col");
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

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

TEST_F(TestCollectionsWithServer, GetRequest_Baseline)
{
  struct switchData
  {
    bool state = false;
  };

  auto getSwitch = [](oc_request_t *request, oc_interface_mask_t iface_mask,
                      void *user_data) {
    const auto *data = static_cast<switchData *>(user_data);
    oc_rep_start_root_object();
    switch (iface_mask) {
    case OC_IF_BASELINE:
      oc_process_baseline_interface(request->resource);
      [[fallthrough]];
    case OC_IF_RW:
      oc_rep_set_boolean(root, state, data->state);
      break;
    default:
      break;
    }
    oc_rep_end_root_object();

    oc_send_response(request, OC_STATUS_OK);
  };

  constexpr const char *switchName = "test switch";
  constexpr const char *switchURI = "/switch";
  constexpr const char *switchRT = "test.r.switch";
  constexpr auto switchIF =
    static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_R);
  static constexpr std::array<double, 3> switchPos = { 0.34, 0.5, 0.8 };

  oc_resource_t *bswitch = oc_new_resource(switchName, switchURI, 1, kDeviceID);
  oc_resource_bind_resource_type(bswitch, switchRT);
  oc_resource_bind_resource_interface(bswitch, switchIF);
  oc_resource_set_default_interface(bswitch, OC_IF_R);
  oc_resource_set_discoverable(bswitch, true);
  oc_resource_set_observable(bswitch, true);
  oc_resource_set_request_handler(bswitch, OC_GET, getSwitch, nullptr);
  oc_resource_tag_func_desc(bswitch, OC_ENUM_SMART);
  oc_resource_tag_pos_rel(bswitch, switchPos[0], switchPos[1], switchPos[2]);
  oc_resource_tag_pos_desc(bswitch, OC_POS_TOP);
  oc_add_resource(bswitch);

  constexpr const char *colName = "test collection";
  constexpr const char *colURI = "/col";
  constexpr const char *colRT = "test.r.col";

  struct collectionData
  {
    std::string label = {};
    int power = 0;
  };
  collectionData colData{
    "label",
    42,
  };

  auto setProps = [](const oc_resource_t *, const oc_rep_t *rep, void *data) {
    auto *cData = static_cast<collectionData *>(data);
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
    const auto *cData = static_cast<collectionData *>(data);
    oc_rep_set_text_string_v1(root, label, cData->label.c_str(),
                              cData->label.length());
    oc_rep_set_int(root, power, cData->power);
  };

  auto col = NewCollection(colName, colURI, kDeviceID, colRT);
  ASSERT_NE(nullptr, col);
  oc_collection_add(col.get());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  ASSERT_TRUE(oc::SetAccessInRFOTM(&col->res, true, OC_PERM_RETRIEVE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

  oc_collection_add_supported_rt(&col->res, switchRT);
  oc_collection_add_mandatory_rt(&col->res, switchRT);
  oc_resource_set_properties_cbs(&col->res, getProps, &colData, setProps,
                                 &colData);

  oc_link_t *link = oc_new_link(bswitch);
  ASSERT_NE(link, nullptr);
  EXPECT_TRUE(oc_link_add_link_param(link, "tag", "test"));
  EXPECT_TRUE(oc_link_add_link_param(link, "hidden", "true"));
  oc_collection_add_link(&col->res, link);

  // get insecure connection to the testing device
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto cData = oc::Collection::ParsePayload(data->payload);
    ASSERT_TRUE(cData.has_value());

    EXPECT_STREQ(colName, cData->baseline->name.c_str());
    ASSERT_EQ(1, cData->baseline->rts.size());
    EXPECT_STREQ(colRT, cData->baseline->rts[0].c_str());
    ASSERT_EQ(3, cData->baseline->ifs.size());

    ASSERT_EQ(1, cData->rts.size());
    EXPECT_STREQ(switchRT, cData->rts[0].c_str());
    ASSERT_EQ(1, cData->rts_m.size());
    EXPECT_STREQ(switchRT, cData->rts_m[0].c_str());

    ASSERT_EQ(1, cData->links.size());
    const oc::LinkData &ld = cData->links[0];
    EXPECT_STREQ(switchURI, ld.href.c_str());
    ASSERT_EQ(1, ld.rts.size());
    EXPECT_STREQ(switchRT, ld.rts[0].c_str());
    ASSERT_EQ(1, ld.rels.size());
    EXPECT_STREQ("hosts", ld.rels[0].c_str());
    EXPECT_NE(0, ld.ins);
    ASSERT_EQ(2, ld.ifs.size());
    EXPECT_NE(ld.ifs.end(),
              std::find(ld.ifs.begin(), ld.ifs.end(), OC_IF_BASELINE));
    EXPECT_NE(ld.ifs.end(), std::find(ld.ifs.begin(), ld.ifs.end(), OC_IF_R));
    ASSERT_EQ(2, ld.params.size());
    EXPECT_STREQ("tag", ld.params[0].key.c_str());
    EXPECT_STREQ("test", ld.params[0].value.c_str());
    EXPECT_STREQ("hidden", ld.params[1].key.c_str());
    EXPECT_STREQ("true", ld.params[1].value.c_str());
    EXPECT_EQ(OC_DISCOVERABLE | OC_OBSERVABLE, ld.bm);
    EXPECT_FALSE(ld.tag_pos_desc.empty());
    EXPECT_FALSE(ld.tag_func_desc.empty());
    EXPECT_EQ(3, ld.tag_pos_rel.size());
    EXPECT_EQ(switchPos[0], ld.tag_pos_rel[0]);
    EXPECT_EQ(switchPos[1], ld.tag_pos_rel[1]);
    EXPECT_EQ(switchPos[2], ld.tag_pos_rel[2]);
    EXPECT_FALSE(ld.eps.empty());
  };

  EXPECT_TRUE(oc_do_get("/col", ep, "if=" OC_IF_BASELINE_STR, get_handler,
                        HIGH_QOS, nullptr));
  oc::TestDevice::PoolEvents(5);
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
  /* TODO:
    EXPECT_TRUE(
      oc_do_get("/col", ep, "if=" OC_IF_B_STR, get_handler, HIGH_QOS,
      nullptr));
  */
}

#endif // !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

#endif /* OC_COLLECTIONS */
