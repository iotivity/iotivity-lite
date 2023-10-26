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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ETAG

#include "api/oc_client_api_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_etag_internal.h"
#include "api/oc_introspection_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/options_internal.h"
#include "oc_api.h"
#include "oc_base64.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Storage.h"
#include "util/oc_mmem_internal.h"

#ifdef OC_INTROSPECTION
#include "oc_introspection.h"
#endif /* OC_INTROSPECTION */

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#include "tests/gtest/Collection.h"
#endif /* OC_COLLECTIONS */

#ifdef OC_SECURITY
#include "oc_csr.h"
#include "security/oc_security_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_STORAGE
#include "api/oc_storage_internal.h"
#endif /* OC_STORAGE */

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "api/plgd/plgd_time_internal.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

static constexpr size_t kDeviceID1{ 0 };

#ifdef OC_DYNAMIC_ALLOCATION
static constexpr size_t kDeviceID2{ 1 };

static constexpr std::string_view kDynamicResourceURI1{ "/dyn1" };
static constexpr std::string_view kDynamicResourceURI2{ "/dyn2" };
#ifdef OC_COLLECTIONS
static constexpr std::string_view kCollectionURI = "/col";
static constexpr std::string_view kColDynamicURI1 = "/col/discoverable";
#endif /* OC_COLLECTIONS */
#endif // OC_DYNAMIC_ALLOCATION

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
const long g_max_app_data_size{ oc_get_max_app_data_size() };
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */

using namespace std::chrono_literals;

class TestETag : public ::testing::Test {};

#ifdef OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES

TEST_F(TestETag, HasIncrementalUpdatesQuery_F)
{
  EXPECT_FALSE(oc_etag_has_incremental_updates_query(nullptr, 0));

  std::string query = "";
  EXPECT_FALSE(
    oc_etag_has_incremental_updates_query(query.c_str(), query.length()));

  // prefix
  query = std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY);
  query = query.substr(0, query.size() - 1);
  EXPECT_FALSE(
    oc_etag_has_incremental_updates_query(query.c_str(), query.length()));

  // suffix
  query = std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY) + "_";
  EXPECT_FALSE(
    oc_etag_has_incremental_updates_query(query.c_str(), query.length()));
}

TEST_F(TestETag, HasIncrementalUpdatesQuery)
{
  std::string query = OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY;
  EXPECT_TRUE(
    oc_etag_has_incremental_updates_query(query.c_str(), query.length()));

  query = std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY) + "=";
  EXPECT_TRUE(
    oc_etag_has_incremental_updates_query(query.c_str(), query.length()));

  query = "key1=1&key2=2&" + std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY);
  EXPECT_TRUE(
    oc_etag_has_incremental_updates_query(query.c_str(), query.length()));
}

static bool
iterateGetETags(uint64_t etag, void *data)
{
  auto &etags = *static_cast<std::vector<uint64_t> *>(data);
  etags.push_back(etag);
  // stop iteration if etag is 0
  return etag != 0;
}

static std::vector<uint8_t>
encodeETagToBase64(uint64_t etag)
{
  std::array<uint8_t, sizeof(etag)> etag_buf{};
  memcpy(&etag_buf[0], &etag, sizeof(etag));
  std::array<uint8_t, 12> b64{};
  int b64_len =
    oc_base64_encode_v1(OC_BASE64_ENCODING_URL, false, etag_buf.data(),
                        etag_buf.size(), b64.data(), b64.size());
  if (b64_len < 0) {
    throw std::string("base64 encoding failed");
  }

  std::vector<uint8_t> encodedETag{};
  encodedETag.insert(encodedETag.end(), b64.data(),
                     b64.data() + static_cast<size_t>(b64_len));
  return encodedETag;
}

static std::string
incrementalUpdatesQuery(const std::vector<uint64_t> &etags)
{
  std::string query{ OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY };
  query += "=";
  for (size_t i = 0; i < etags.size(); ++i) {
    if (i > 0) {
      query += ",";
    }

    auto b64 = encodeETagToBase64(etags[i]);
    query.insert(query.end(), b64.begin(), b64.end());
  }
  return query;
}

TEST_F(TestETag, IterateIncrementalUpdates_Empty)
{
  std::string query = "";
  std::vector<uint64_t> etags{};
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());

  // key is prefix of OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY
  query = "inc=";
  auto b64 = encodeETagToBase64(123);
  query.insert(query.end(), b64.begin(), b64.end());
  etags.clear();
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());

  // key is suffix of OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY
  query = std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY) + "123=";
  b64 = encodeETagToBase64(123);
  query.insert(query.end(), b64.begin(), b64.end());
  etags.clear();
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());

  // different key
  query = "if=oic.if.baseline";
  etags.clear();
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());

  // no value
  query = incrementalUpdatesQuery({});
  etags.clear();
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());

  // only separators as value
  query = std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY) + "=,,,,,,,,,,&" +
          OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY + "=";
  etags.clear();
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());
}

TEST_F(TestETag, IterateIncrementalUpdates_Invalid)
{
  // non base64 value
  std::string query =
    std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY) + "=invalid";
  std::vector<uint64_t> etags{};
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());

  // base64 encoded value shorter than 8 bytes
  std::vector<uint8_t> buf{ 'l', 'e', 'e', 't' };
  std::array<uint8_t, 32> b64{};
  int b64_len =
    oc_base64_encode(buf.data(), buf.size(), b64.data(), b64.size());
  ASSERT_NE(-1, b64_len);
  query = std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY) + "=";
  query.insert(query.end(), b64.data(),
               b64.data() + static_cast<size_t>(b64_len));
  etags.clear();
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());

  // value longer than 8 bytes
  buf = { 's', 'u', 'p', 'e', 'r', 'l', 'e', 'e', 't', 'e', 't', 'a', 'g' };
  b64_len = oc_base64_encode(buf.data(), buf.size(), b64.data(), b64.size());
  ASSERT_NE(-1, b64_len);
  query = std::string(OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY) + "=";
  query.insert(query.end(), b64.data(),
               b64.data() + static_cast<size_t>(b64_len));
  etags.clear();
  oc_etag_iterate_incremental_updates_query(query.c_str(), query.length(),
                                            iterateGetETags, &etags);
  EXPECT_TRUE(etags.empty());
}

TEST_F(TestETag, IterateIncrementalUpdates_Single)
{
  uint64_t etag = 123;
  std::string query = incrementalUpdatesQuery({ etag });
  std::vector<uint64_t> etags{};
  oc_etag_iterate_incremental_updates_query(query.data(), query.length(),
                                            iterateGetETags, &etags);
  ASSERT_EQ(1, etags.size());
  EXPECT_EQ(123, etags[0]);
}

TEST_F(TestETag, IterateIncrementalUpdates_MultipleKeys)
{
  std::vector<uint64_t> etags{ 1, 2345, 45678901, 890123456789,
                               234567890123456 };
  std::string query{};
  for (size_t i = 0; i < etags.size(); ++i) {
    if (i > 0) {
      query += "&";
    }
    query += incrementalUpdatesQuery({ etags[i] });
  }
  std::vector<uint64_t> parsedETags{};
  oc_etag_iterate_incremental_updates_query(query.data(), query.length(),
                                            iterateGetETags, &parsedETags);
  ASSERT_EQ(etags.size(), parsedETags.size());
  for (size_t i = 0; i < etags.size(); ++i) {
    EXPECT_EQ(etags[i], parsedETags[i]);
  }
}

TEST_F(TestETag, IterateIncrementalUpdates_MultipleETags)
{
  std::vector<uint64_t> etags{ 1, 2345, 45678901, 890123456789,
                               234567890123456 };
  std::string query = incrementalUpdatesQuery(etags);
  std::vector<uint64_t> parsedETags{};
  oc_etag_iterate_incremental_updates_query(query.data(), query.length(),
                                            iterateGetETags, &parsedETags);
  ASSERT_EQ(etags.size(), parsedETags.size());
  for (size_t i = 0; i < etags.size(); ++i) {
    EXPECT_EQ(etags[i], parsedETags[i]);
  }
}

TEST_F(TestETag, IterateIncrementalUpdates_StopIteration)
{
  std::vector<uint64_t> etags{ 1, 2345, 0, 890123456789, 234567890123456 };
  std::string query = incrementalUpdatesQuery(etags);
  std::vector<uint64_t> parsedETags{};
  oc_etag_iterate_incremental_updates_query(query.data(), query.length(),
                                            iterateGetETags, &parsedETags);
  auto it = std::find(etags.begin(), etags.end(), 0);
  ASSERT_NE(etags.end(), it);
  size_t etagsCount = static_cast<size_t>(std::distance(etags.begin(), it)) + 1;
  ASSERT_EQ(etagsCount, parsedETags.size());
  for (size_t i = 0; i < etagsCount; ++i) {
    EXPECT_EQ(etags[i], parsedETags[i]);
  }
}

TEST_F(TestETag, IterateIncrementalUpdates)
{
  std::vector<uint64_t> etags{
    1, 2345, 45678901, 890123456789, 234567890123456, 7777777
  };

  std::string query = "first=1&" + incrementalUpdatesQuery({ etags[0] });
  query += std::string("&second=2&") + OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY +
           "=123,,,";
  auto b64 = encodeETagToBase64(etags[1]);
  query.insert(query.end(), b64.begin(), b64.end());
  query += ",,";
  b64 = encodeETagToBase64(etags[2]);
  query.insert(query.end(), b64.begin(), b64.end());
  query += ",filler,";
  b64 = encodeETagToBase64(etags[3]);
  query.insert(query.end(), b64.begin(), b64.end());
  query += "&third=";
  b64 = encodeETagToBase64(1337);
  query.insert(query.end(), b64.begin(), b64.end());
  query += "&" + incrementalUpdatesQuery({ etags[4], etags[5] });
  query += ",,,,&fourth=4";
  std::vector<uint64_t> parsedETags{};
  oc_etag_iterate_incremental_updates_query(query.data(), query.length(),
                                            iterateGetETags, &parsedETags);
  ASSERT_EQ(etags.size(), parsedETags.size());
  for (size_t i = 0; i < etags.size(); ++i) {
    EXPECT_EQ(etags[i], parsedETags[i]);
  }
}

#endif /* OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES */

class TestETagWithServer : public ::testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Config());
#endif // OC_STORAGE
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
    oc_set_max_app_data_size(16384);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */

    oc::TestDevice::SetServerDevices({
      {
        /*rt=*/"oic.d.test1",
        /*name=*/"Test Device 2",
        /*spec_version=*/"ocf.1.0.0",
        /*data_model_version=*/"ocf.res.1.0.0",
        /*uri=*/"/oic/d",
      },
#ifdef OC_DYNAMIC_ALLOCATION
      {
        /*rt=*/"oic.d.test2",
        /*name=*/"Test Device 2",
        /*spec_version=*/"ocf.1.0.0",
        /*data_model_version=*/"ocf.res.1.0.0",
        /*uri=*/"/oic/d",
      },
#endif // OC_DYNAMIC_ALLOCATION
    });
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_DYNAMIC_ALLOCATION
    addDynamicResources();
#ifdef OC_COLLECTIONS
    addCollections();
#endif /* OC_COLLECTIONS */
#endif // OC_DYNAMIC_ALLOCATION

#ifdef OC_IDD_API
    ASSERT_TRUE(addIntrospectionData(kDeviceID1));
#endif /* OC_IDD_API */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
    oc_set_max_app_data_size(g_max_app_data_size);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Clear());
#endif // OC_STORAGE
  }

#ifdef OC_SECURITY
  static void selfOnboard()
  {
    oc_sec_self_own(kDeviceID1);
#ifdef OC_DYNAMIC_ALLOCATION
    oc_sec_self_own(kDeviceID2);
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  static void selfOffboard()
  {
    oc_sec_self_disown(kDeviceID1);
#ifdef OC_DYNAMIC_ALLOCATION
    oc_sec_self_disown(kDeviceID2);
#endif /* OC_DYNAMIC_ALLOCATION */
  }
#endif /* OC_SECURITY */

  void TearDown() override
  {
#ifdef OC_SECURITY
    selfOffboard();
#endif /* OC_SECURITY */
#ifdef OC_STORAGE
    oc_etag_clear_storage();
#endif // OC_STORAGE
  }

#ifdef OC_DYNAMIC_ALLOCATION
  static void onRequest(oc_request_t *request, oc_interface_mask_t, void *)
  {
    if (request->method == OC_GET) {
      oc_rep_start_root_object();
      oc_rep_end_root_object();
    }
    oc_send_response(request, OC_STATUS_OK);
  }

  static oc_resource_t *addDynamicResource(
    const std::string &name, const std::string &uri,
    const std::vector<std::string> &rts,
    const std::vector<oc_interface_mask_t> &ifaces, size_t device);

  static void addDynamicResources();

#ifdef OC_COLLECTIONS
  static void addCollections();
#endif /* OC_COLLECTIONS */
#endif // OC_DYNAMIC_ALLOCATION
#ifdef OC_IDD_API
  static bool addIntrospectionData(size_t device);
#endif /* OC_IDD_API */
};

#ifdef OC_DYNAMIC_ALLOCATION

oc_resource_t *
TestETagWithServer::addDynamicResource(
  const std::string &name, const std::string &uri,
  const std::vector<std::string> &rts,
  const std::vector<oc_interface_mask_t> &ifaces, size_t device)
{
  oc::DynamicResourceHandler handlers{};
  handlers.onGet = onRequest;
  handlers.onPost = onRequest;
  return oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd(name, uri, rts, ifaces, handlers), device);
}

void
TestETagWithServer::addDynamicResources()
{
  ASSERT_NE(nullptr, addDynamicResource(
                       "Dynamic Resource 1", std::string(kDynamicResourceURI1),
                       { "oic.d.dynamic", "oic.d.test" },
                       { OC_IF_BASELINE, OC_IF_R }, kDeviceID1));
  ASSERT_NE(nullptr, addDynamicResource(
                       "Dynamic Resource 2", std::string(kDynamicResourceURI2),
                       { "oic.d.dynamic", "oic.d.test" },
                       { OC_IF_BASELINE, OC_IF_RW }, kDeviceID2));
}

#ifdef OC_COLLECTIONS

void
TestETagWithServer::addCollections()
{
  constexpr std::string_view powerSwitchRT = "oic.d.power";

  auto col = oc::NewCollection("col", kCollectionURI, kDeviceID1, "oic.wk.col");
  ASSERT_NE(nullptr, col);
  oc_resource_set_discoverable(&col->res, true);
  oc_collection_add_supported_rt(&col->res, powerSwitchRT.data());
  oc_collection_add_mandatory_rt(&col->res, powerSwitchRT.data());
  ASSERT_TRUE(oc_add_collection_v1(&col->res));

  oc::DynamicResourceHandler handlers1{};
  handlers1.onGet = onRequest;

  auto dr1 = oc::makeDynamicResourceToAdd(
    "Collection Resource 1", std::string(kColDynamicURI1),
    { std::string(powerSwitchRT), "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
    handlers1);
  oc_resource_t *res1 = oc::TestDevice::AddDynamicResource(dr1, kDeviceID1);
  ASSERT_NE(nullptr, res1);
  oc_link_t *link1 = oc_new_link(res1);
  ASSERT_NE(link1, nullptr);
  oc_collection_add_link(&col->res, link1);

  col.release();
}

#endif /* OC_COLLECTIONS */

#endif // OC_DYNAMIC_ALLOCATION

#ifdef OC_IDD_API
bool
TestETagWithServer::addIntrospectionData(size_t device)
{
  auto idd_fs = std::ifstream("introspectiontest_IDD.cbor",
                              std::ios::in | std::ios::binary);
  if (!idd_fs.good()) {
    return false;
  }
  std::vector<uint8_t> idd{};
  std::for_each(std::istreambuf_iterator<char>(idd_fs),
                std::istreambuf_iterator<char>(),
                [&idd](char c) { idd.push_back(c); });
  oc_set_introspection_data(device, idd.data(), idd.size());
  return true;
}
#endif /* OC_IDD_API */

// check that all resources have initialized etags
TEST_F(TestETagWithServer, ETagsInitialized)
{
  oc::IterateAllResources([](const oc_resource_t *resource) {
    EXPECT_NE(0, oc_resource_get_etag(resource));
  });
}

TEST_F(TestETagWithServer, ETagWrapAround)
{
  oc_etag_set_global(0);
  // TODO: check that all resources have reinitialized etags with the wrapped
  // value
}

#ifdef OC_DYNAMIC_ALLOCATION

// check that newly created resources have etags
TEST_F(TestETagWithServer, NewResources)
{
  auto *dyn = addDynamicResource("Dynamic Resource 3", "/dyn3",
                                 { "oic.d.dynamic", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, kDeviceID1);
  ASSERT_NE(nullptr, dyn);
  EXPECT_NE(0, oc_resource_get_etag(dyn));

#ifdef OC_COLLECTIONS
  auto col1 = oc::NewCollection("col1", "/col1", kDeviceID1);
  ASSERT_NE(nullptr, col1);
  EXPECT_NE(0, oc_resource_get_etag(&col1->res));
#endif /* OC_COLLECTIONS */

  // clean-up
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(dyn, true));
}

#endif // OC_DYNAMIC_ALLOCATION

#ifdef OC_STORAGE

static void
setAllETags(uint64_t etag)
{
  oc::IterateAllResources(
    [etag](oc_resource_t *resource) { oc_resource_set_etag(resource, etag); });
}

static bool
isETagStorageEmpty(size_t device, bool platform = false)
{
  std::string store =
    platform ? OC_ETAG_PLATFORM_STORE_NAME : OC_ETAG_STORE_NAME;

  long ret = oc_storage_data_load(
    store.c_str(), device, [](const oc_rep_t *, size_t, void *) { return 0; },
    nullptr);
  if (ret > 0) {
    return false;
  }
  return true;
}

TEST_F(TestETagWithServer, DumpAndLoad)
{
#ifdef OC_SECURITY
  selfOnboard();
#endif /* OC_SECURITY */

#ifdef OC_COLLECTIONS
  auto col1 = oc::NewCollection("col1", "/col1", kDeviceID1);
  ASSERT_NE(nullptr, col1);
  oc_collection_add(col1.get());

  auto col2 = oc::NewCollection("col2", "/col2", kDeviceID2);
  ASSERT_NE(nullptr, col2);
  oc_collection_add(col2.get());
#endif /* OC_COLLECTIONS */

  // set all etags to 1337
  setAllETags(1337);
  // store etags to the storage
  EXPECT_TRUE(oc_etag_dump());

  std::vector<oc_resource_t *> dynResources{};
#ifdef OC_DYNAMIC_ALLOCATION
  // new resource without etag set, will get etag set by oc_etag_get
  auto *dyn = addDynamicResource("Dynamic Resource 3", "/dyn3",
                                 { "oic.d.dynamic", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, kDeviceID1);
  ASSERT_NE(nullptr, dyn);
  dynResources.push_back(dyn);
#endif // OC_DYNAMIC_ALLOCATION

  // clear all etags
  setAllETags(0);

  // load etags from the storage and clear the storage
  EXPECT_TRUE(oc_etag_load_and_clear());

  // check if etags of resources that are saved to storage are set to 1337
  oc::IterateAllResources([&dynResources](const oc_resource_t *resource) {
    if (oc_etag_dump_ignore_resource(oc_string(resource->uri),
                                     oc_string_len(resource->uri))) {
      return;
    }
#ifdef OC_INTROSPECTION
    if (std::string(oc_string(resource->uri)) == OC_INTROSPECTION_DATA_URI &&
        oc_introspection_get_data(resource->device, nullptr, 0) <= 0) {
      return;
    }
#endif /* OC_INTROSPECTION */

    if (!dynResources.empty()) {
      if (std::find(std::begin(dynResources), std::end(dynResources),
                    resource) != std::end(dynResources)) {
        EXPECT_NE(0, oc_resource_get_etag(resource));
        return;
      }
      // adding a dynamic resource will change the payload of /oic/res
      // resource
      if (resource->device == kDeviceID1 &&
          std::string(oc_string(resource->uri)) == OCF_RES_URI) {
        EXPECT_NE(1337, oc_resource_get_etag(resource));
        return;
      }
    }

    EXPECT_EQ(1337, oc_resource_get_etag(resource))
      << "unexpected ETag for resource " << oc_string(resource->uri);
  });

  // storage should be empty
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    EXPECT_TRUE(isETagStorageEmpty(i));
  }

  // clean-up
#ifdef OC_DYNAMIC_ALLOCATION
  for (auto *dr : dynResources) {
    ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(dr, true));
  }
#endif // OC_DYNAMIC_ALLOCATION
}

#ifdef OC_SECURITY

static bool
isPlatformResourceURI(const std::string &uri)
{
  return uri == "/oic/p"
#ifdef OC_HAS_FEATURE_PLGD_TIME
         || uri == PLGD_TIME_URI
#endif /* OC_HAS_FEATURE_PLGD_TIME */
    ;
}

// if device is not in RFNOP state then ETag data of resources associated with
// the device should not be loaded
TEST_F(TestETagWithServer, IgnoreDataIfDeviceNotInRFNOP)
{
  // set all etags to 1337
  setAllETags(1337);
  // store etags to the storage
  EXPECT_TRUE(oc_etag_dump());

  // clear all etags
  setAllETags(0);
  // load etags from the storage and clear the storage
  EXPECT_TRUE(oc_etag_load_and_clear());

  oc::IterateAllResources([](const oc_resource_t *resource) {
    if (oc_etag_dump_ignore_resource(oc_string(resource->uri),
                                     oc_string_len(resource->uri))) {
      return;
    }
    std::string resource_uri = oc_string(resource->uri);
    // platform resources are not associated with any device, so the data should
    // loaded
    if (isPlatformResourceURI(resource_uri)) {
      return;
    }

    // all other resources are associated with devices not in RFOTM state, so
    // the data should not be loaded
    EXPECT_NE(1337, oc_resource_get_etag(resource)) << "unexpected ETag for "
                                                       "resource "
                                                    << resource_uri;
  });
}

// reset device should reset etags of all non-platform resources and truncate
// storage of non-platform ETag data
TEST_F(TestETagWithServer, OnReset)
{
  // set all etags to 1337
  setAllETags(1337);
  // store etags to the storage
  EXPECT_TRUE(oc_etag_dump());

  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    size_t deviceID = oc_core_get_num_devices() - i - 1;
    oc_reset_device_v1(deviceID, true);
    for (size_t j = 0; j < deviceID; ++j) {
      EXPECT_FALSE(isETagStorageEmpty(j));
    }
    EXPECT_TRUE(isETagStorageEmpty(deviceID));
    // platform resources storage should not be cleared
    EXPECT_FALSE(isETagStorageEmpty(0, true));

    oc::IterateAllResources([deviceID](const oc_resource_t *resource) {
      if (oc_etag_dump_ignore_resource(oc_string(resource->uri),
                                       oc_string_len(resource->uri))) {
        return;
      }
      std::string resource_uri = oc_string(resource->uri);
      if (isPlatformResourceURI(resource_uri)) {
        EXPECT_EQ(1337, oc_resource_get_etag(resource))
          << "unexpected ETag for resource " << resource_uri;
        return;
      }
      if (resource->device >= deviceID) {
        EXPECT_NE(1337, oc_resource_get_etag(resource))
          << "unexpected ETag for resource " << resource_uri;
        return;
      }
      EXPECT_EQ(1337, oc_resource_get_etag(resource))
        << "unexpected ETag for resource " << resource_uri;
    });
  }

  // small time to process events/messages generated by the reset
  oc::TestDevice::PoolEventsMsV1(10ms);
}

#endif /* OC_SECURITY */

TEST_F(TestETagWithServer, SkipDumpOfEmptyETags)
{
#ifdef OC_SECURITY
  selfOnboard();
#endif /* OC_SECURITY */

  // set all etags to 0
  setAllETags(OC_ETAG_UNINITIALIZED);
  // no etags should be stored
  ASSERT_TRUE(oc_etag_dump());

  // all etags should be reinitialized by oc_etag_load_from_storage
  uint64_t max_etag = oc_etag_global();
  EXPECT_TRUE(oc_etag_load_from_storage(false));
  oc::IterateAllResources([&max_etag](const oc_resource_t *resource) {
    EXPECT_LT(max_etag, oc_resource_get_etag(resource))
      << "unexpected ETag for resource " << oc_string(resource->uri);
  });
}

static int
encodeResourceETag(CborEncoder *encoder, const std::string &uri, int64_t etag)
{
  int err = oc_rep_encode_text_string(encoder, uri.c_str(), uri.length());
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  err |= oc_rep_encoder_create_map(encoder, &etag_map, CborIndefiniteLength);
  std::string key = "etag";
  err |= oc_rep_encode_text_string(&etag_map, key.c_str(), key.length());
  err |= oc_rep_encode_int(&etag_map, etag);
  err |= oc_rep_encoder_close_container(encoder, &etag_map);
  return err;
}

TEST_F(TestETagWithServer, IgnoreInvalidStorageData)
{
#ifdef OC_SECURITY
  selfOnboard();
#endif /* OC_SECURITY */

  constexpr uint64_t kETag = 1337;
  // set all etags to 1337
  setAllETags(kETag);

  auto empty_storage = [](size_t, void *) {
    oc_rep_start_root_object();
    oc_rep_end_root_object();
    return 0;
  };
  // put {} to the storage of platform resources so we can ignore it
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_PLATFORM_STORE_NAME, 0,
                                    empty_storage, nullptr));
#ifdef OC_DYNAMIC_ALLOCATION
  // put {} to the storage of the second device so we can ignore it
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID2,
                                    empty_storage, nullptr));
#endif // OC_DYNAMIC_ALLOCATION

  // expected storage data:
  // {
  //   "<uri>": {
  //     "etag": <etag in uint64_t format>,
  //   },
  //   ...
  // }

  auto store_encode_single_string = [](size_t, void *) {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, uri, "/oic/d");
    oc_rep_end_root_object();
    return 0;
  };
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID1,
                                    store_encode_single_string, nullptr));
  EXPECT_TRUE(oc_etag_load_from_storage(true));
  // no etag should be changed
  oc::IterateAllResources([kETag](const oc_resource_t *resource) {
    EXPECT_EQ(kETag, oc_resource_get_etag(resource));
  });

  auto store_encode_invalid_type = [](size_t, void *) {
    oc_rep_start_root_object();
    std::string uri = "/oic/d";
    int err =
      oc_rep_encode_text_string(oc_rep_object(root), uri.c_str(), uri.length());
    CborEncoder etag_map;
    memset(&etag_map, 0, sizeof(etag_map));
    err |= oc_rep_encoder_create_map(oc_rep_object(root), &etag_map,
                                     CborIndefiniteLength);
    std::string key = "etag";
    err |= oc_rep_encode_text_string(&etag_map, key.c_str(), key.length());
    std::string value = "invalid";
    err |= oc_rep_encode_text_string(&etag_map, value.c_str(), value.length());
    err |= oc_rep_encoder_close_container(oc_rep_object(root), &etag_map);
    oc_rep_end_root_object();
    return err;
  };
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID1,
                                    store_encode_invalid_type, nullptr));
  EXPECT_TRUE(oc_etag_load_from_storage(true));
  // no etag should be changed
  oc::IterateAllResources([kETag](const oc_resource_t *resource) {
    EXPECT_EQ(kETag, oc_resource_get_etag(resource));
  });

  auto store_encode_invalid_value = [](size_t, void *) {
    oc_rep_start_root_object();
    int err = encodeResourceETag(oc_rep_object(root), "/oic/p", 0);
    err |= encodeResourceETag(oc_rep_object(root), "/oic/d", -1);
    oc_rep_end_root_object();
    return err;
  };
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID1,
                                    store_encode_invalid_value, nullptr));
  EXPECT_TRUE(oc_etag_load_from_storage(true));
  // no etag should be changed
  oc::IterateAllResources([kETag](const oc_resource_t *resource) {
    EXPECT_EQ(kETag, oc_resource_get_etag(resource));
  });
}

TEST_F(TestETagWithServer, LoadGlobalETagFromStorage)
{
  uint64_t max_etag = oc_etag_global();
  if (max_etag == 0) {
    max_etag = oc_etag_get();
  }
  constexpr oc_clock_time_t kOneDay = 24 * 60 * 60 * OC_CLOCK_SECOND;
  max_etag += kOneDay;

  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);
  oc_resource_set_etag(platform, max_etag);

  ASSERT_TRUE(oc_etag_dump());
  EXPECT_TRUE(oc_etag_load_from_storage(true));

  // the global etag should be > than the maximal etag of all resources
  EXPECT_GT(oc_etag_global(), max_etag);
}

// if storage is not properly initialized then oc_etag_dump should fail
TEST_F(TestETagWithServer, Dump_FailNoStorage)
{
  ASSERT_EQ(0, oc::TestStorage.Clear());
  EXPECT_FALSE(oc_etag_dump());
  ASSERT_EQ(0, oc::TestStorage.Config());
}

// if the storage is empty then oc_etag_load_from_storage should use
// oc_etag_get to set etags on all resources
TEST_F(TestETagWithServer, ClearStorage)
{
#ifdef OC_HAS_FEATURE_PLGD_TIME
  plgd_time_set_time(oc_clock_time());
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef OC_SECURITY
  selfOnboard();
#endif /* OC_SECURITY */

  // set all etags to 1337
  setAllETags(1337);
  // store etags to the storage
  ASSERT_TRUE(oc_etag_dump());

  // clear the storage
  ASSERT_TRUE(oc_etag_clear_storage());
  EXPECT_FALSE(oc_etag_load_from_storage(false));

  oc::IterateAllResources([](const oc_resource_t *resource) {
    // nor 0 nor 1337
    EXPECT_NE(0, oc_resource_get_etag(resource))
      << "zero etag for resource " << oc_string(resource->uri);
    EXPECT_NE(1337, oc_resource_get_etag(resource))
      << "etag 1337 for resource " << oc_string(resource->uri);
  });

#ifdef OC_HAS_FEATURE_PLGD_TIME
  plgd_time_set_time(0);
  plgd_time_set_status(PLGD_TIME_STATUS_IN_SYNC);
#endif /* OC_HAS_FEATURE_PLGD_TIME */
}

// if storage is not properly initialized then oc_etag_clear_storage should
// fail
TEST_F(TestETagWithServer, ClearStorage_Fail)
{
  ASSERT_EQ(0, oc::TestStorage.Clear());
  EXPECT_FALSE(oc_etag_clear_storage());
  ASSERT_EQ(0, oc::TestStorage.Config());
}

// if storage is not properly initialized then oc_etag_load_and_clear should
// fail
TEST_F(TestETagWithServer, LoadAndClear_Fail)
{
  ASSERT_EQ(0, oc::TestStorage.Clear());
  EXPECT_FALSE(oc_etag_load_and_clear());
  ASSERT_EQ(0, oc::TestStorage.Config());
}

#endif // OC_STORAGE

#ifdef OC_HAS_FEATURE_CRC_ENCODER

TEST_F(TestETagWithServer, GetCRC64_Fail)
{
  std::string uri = "/res1";
  oc_resource_t res{};
  res.uri = OC_MMEM(&uri[0], uri.length() + 1, nullptr);

  uint64_t crc64 = 0;
  EXPECT_EQ(-1, oc_resource_get_crc64(&res, &crc64));
}

TEST_F(TestETagWithServer, GetCRC64)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  uint64_t crc64_first = 0;
  ASSERT_EQ(OC_RESOURCE_CRC64_OK,
            oc_resource_get_crc64(platform, &crc64_first));

  uint64_t crc64_second = 0;
  ASSERT_EQ(OC_RESOURCE_CRC64_OK,
            oc_resource_get_crc64(platform, &crc64_second));

  EXPECT_EQ(crc64_first, crc64_second);
}

TEST_F(TestETagWithServer, GetCRC64Changed)
{
  oc_resource_t *plt = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, plt);

  oc_platform_info_t *plti = oc_core_get_platform_info();
  ASSERT_NE(nullptr, plti);

  oc_platform_info_t plti_copy{};
  memcpy(&plti_copy.pi, plti, sizeof(plti_copy.pi));
  oc_copy_string(&plti_copy.mfg_name, &plti->mfg_name);

  uint64_t crc64_1 = 0;
  ASSERT_EQ(OC_RESOURCE_CRC64_OK, oc_resource_get_crc64(plt, &crc64_1));

  do {
    oc_gen_uuid(&plti->pi);
  } while (oc_uuid_is_equal(plti_copy.pi, plti->pi));

  uint64_t crc64_2 = 0;
  ASSERT_EQ(OC_RESOURCE_CRC64_OK, oc_resource_get_crc64(plt, &crc64_2));
  EXPECT_NE(crc64_1, crc64_2);

  std::string mfg_name{ "plgd.dev" };
  oc_set_string(&plti->mfg_name, mfg_name.c_str(), mfg_name.length());

  uint64_t crc64_3 = 0;
  ASSERT_EQ(OC_RESOURCE_CRC64_OK, oc_resource_get_crc64(plt, &crc64_3));
  EXPECT_NE(crc64_2, crc64_3);
  EXPECT_NE(crc64_1, crc64_3);

  // restore original values, which should result in the original checksum
  memcpy(&plti->pi, &plti_copy.pi, sizeof(plti_copy.pi));
  oc_copy_string(&plti->mfg_name, &plti_copy.mfg_name);

  uint64_t crc64_4 = 0;
  ASSERT_EQ(OC_RESOURCE_CRC64_OK, oc_resource_get_crc64(plt, &crc64_4));
  EXPECT_EQ(crc64_1, crc64_4);

  oc_free_string(&plti_copy.mfg_name);
}

#if defined(OC_SERVER) && defined(OC_COLLECTIONS)

TEST_F(TestETagWithServer, GetCRC64Collection)
{
  auto *col = oc_get_collection_by_uri(kCollectionURI.data(),
                                       kCollectionURI.length(), kDeviceID1);
  ASSERT_NE(nullptr, col);

  uint64_t crc64_1{};
  ASSERT_EQ(OC_RESOURCE_CRC64_OK, oc_resource_get_crc64(&col->res, &crc64_1));

  uint64_t crc64_2{};
  auto *link =
    oc_get_link_by_uri(col, kColDynamicURI1.data(), kColDynamicURI1.length());
  ASSERT_NE(nullptr, link);

  ASSERT_TRUE(
    oc_collection_remove_link_and_notify(&col->res, link, false, false));
  ASSERT_EQ(OC_RESOURCE_CRC64_OK, oc_resource_get_crc64(&col->res, &crc64_2));
  EXPECT_NE(crc64_1, crc64_2);

  oc_collection_add_link(&col->res, link);
  uint64_t crc64_3{};
  ASSERT_EQ(OC_RESOURCE_CRC64_OK, oc_resource_get_crc64(&col->res, &crc64_3));
  EXPECT_EQ(crc64_1, crc64_3);
}

#endif // OC_SERVER && OC_COLLECTIONS

using CheckSumMap = std::map<std::string, uint64_t, std::less<>>;

static bool
storeChecksums(oc_resource_t *resource, void *data)
{
  auto uri = std::string(oc_string(resource->uri));
  if (oc_etag_dump_ignore_resource(oc_string(resource->uri),
                                   oc_string_len(resource->uri))) {
    return true;
  }
  auto &checksums = *static_cast<CheckSumMap *>(data);
  uint64_t crc64 = 0;
  if (oc_resource_get_crc64(resource, &crc64) < 0) {
    throw std::string("failed to get crc64 for resource(") + uri + ")";
  }
  checksums[uri] = crc64;
  return true;
}

TEST_F(TestETagWithServer, GetCRC64AllResources)
{
  // iterate all resources -> store to map[uri]checksum
  std::map<std::string, uint64_t, std::less<>> checksums_1{};
  try {
    oc_resources_iterate(kDeviceID1, true, true, true, true, storeChecksums,
                         &checksums_1);
  } catch (const std::string &err) {
    FAIL() << err;
  }
  ASSERT_FALSE(checksums_1.empty());

  // iterate all resources for the second time
  std::map<std::string, uint64_t, std::less<>> checksums_2{};
  try {
    oc_resources_iterate(kDeviceID1, true, true, true, true, storeChecksums,
                         &checksums_2);
  } catch (const std::string &err) {
    FAIL() << err;
  }
  ASSERT_FALSE(checksums_2.empty());

  // compare maps
  ASSERT_EQ(checksums_1.size(), checksums_2.size());
  for (const auto &[uri, checksum] : checksums_1) {
    auto it2 = checksums_2.find(uri);
    ASSERT_NE(checksums_2.end(), it2);
    EXPECT_EQ(checksum, it2->second)
      << "checksum for resource(" << uri << ") is different";
  }
}

TEST_F(TestETagWithServer, EncodeResource)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  EXPECT_EQ(OC_RESOURCE_ENCODE_OK,
            oc_etag_encode_resource_etag(oc_rep_object(root), platform));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());

  oc_rep_t *obj = nullptr;
  ASSERT_TRUE(oc_rep_get_object(rep.get(), oc_string(platform->uri), &obj));
  ASSERT_NE(nullptr, obj);

  int64_t etag = 0;
  ASSERT_TRUE(oc_rep_get_int(obj, "etag", &etag));
  EXPECT_EQ(oc_resource_get_etag(platform), static_cast<uint64_t>(etag));

  uint64_t expectedCrc = 0;
  ASSERT_EQ(OC_RESOURCE_CRC64_OK,
            oc_resource_get_crc64(platform, &expectedCrc));
  int64_t crc = 0;
  ASSERT_TRUE(oc_rep_get_int(obj, "crc", &crc));
  EXPECT_EQ(expectedCrc, static_cast<uint64_t>(crc));
}

TEST_F(TestETagWithServer, EncodeResource_FailBufferTooSmall)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  oc::RepPool pool{ 8 };
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  EXPECT_EQ(OC_RESOURCE_ENCODE_ERROR,
            oc_etag_encode_resource_etag(oc_rep_object(root), platform));
  EXPECT_NE(CborNoError, oc_rep_get_cbor_errno());
}

TEST_F(TestETagWithServer, DecodeResource)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  EXPECT_EQ(OC_RESOURCE_ENCODE_OK,
            oc_etag_encode_resource_etag(oc_rep_object(root), platform));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());
  oc_rep_t *platformRep = nullptr;
  ASSERT_TRUE(
    oc_rep_get_object(rep.get(), oc_string(platform->uri), &platformRep));

  uint64_t etag = 0;
  EXPECT_TRUE(oc_etag_decode_resource_etag(platform, platformRep, &etag));
  EXPECT_EQ(oc_resource_get_etag(platform), etag);
}

constexpr std::string_view kETagKey{ "etag" };
constexpr std::string_view kCRCKey{ "crc" };

TEST_F(TestETagWithServer, DecodeResource_FailMissingETag)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  oc::RepPool pool{};
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  int err = oc_rep_encoder_create_map(oc_rep_get_encoder(), &etag_map,
                                      CborIndefiniteLength);
  err |= oc_rep_encode_text_string(&etag_map, kCRCKey.data(), kCRCKey.length());
  err |= oc_rep_encode_uint(&etag_map, 0);
  err |= oc_rep_encoder_close_container(oc_rep_get_encoder(), &etag_map);
  ASSERT_EQ(CborNoError, err);
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  uint64_t etag = 0;
  EXPECT_FALSE(oc_etag_decode_resource_etag(platform, rep.get(), &etag));
}

TEST_F(TestETagWithServer, DecodeResource_FailInvalidETag)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  oc::RepPool pool{};
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  int err = oc_rep_encoder_create_map(oc_rep_get_encoder(), &etag_map,
                                      CborIndefiniteLength);
  err |=
    oc_rep_encode_text_string(&etag_map, kETagKey.data(), kETagKey.length());
  err |= oc_rep_encode_uint(&etag_map, OC_ETAG_UNINITIALIZED);
  err |= oc_rep_encode_text_string(&etag_map, kCRCKey.data(), kCRCKey.length());
  err |= oc_rep_encode_uint(&etag_map, 0);
  err |= oc_rep_encoder_close_container(oc_rep_get_encoder(), &etag_map);
  ASSERT_EQ(CborNoError, err);
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  uint64_t etag = 0;
  EXPECT_FALSE(oc_etag_decode_resource_etag(platform, rep.get(), &etag));
}

TEST_F(TestETagWithServer, DecodeResource_FailMissingCRC)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  oc::RepPool pool{};
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  int err = oc_rep_encoder_create_map(oc_rep_get_encoder(), &etag_map,
                                      CborIndefiniteLength);
  err |=
    oc_rep_encode_text_string(&etag_map, kETagKey.data(), kETagKey.length());
  err |= oc_rep_encode_uint(&etag_map, oc_resource_get_etag(platform));
  err |= oc_rep_encoder_close_container(oc_rep_get_encoder(), &etag_map);
  ASSERT_EQ(CborNoError, err);
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  uint64_t etag = 0;
  EXPECT_FALSE(oc_etag_decode_resource_etag(platform, rep.get(), &etag));
}

TEST_F(TestETagWithServer, DecodeResource_FailNoResourcePayload)
{
  std::string uri = "/test";
  oc_resource_t res{};
  res.uri = OC_MMEM(&uri[0], uri.length() + 1, nullptr);
  res.etag = 1337;

  oc::RepPool pool{};
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  int err = oc_rep_encoder_create_map(oc_rep_get_encoder(), &etag_map,
                                      CborIndefiniteLength);
  err |=
    oc_rep_encode_text_string(&etag_map, kETagKey.data(), kETagKey.length());
  err |= oc_rep_encode_uint(&etag_map, res.etag);
  err |= oc_rep_encode_text_string(&etag_map, kCRCKey.data(), kCRCKey.length());
  err |= oc_rep_encode_uint(&etag_map, 42);
  err |= oc_rep_encoder_close_container(oc_rep_get_encoder(), &etag_map);
  ASSERT_EQ(CborNoError, err);
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  uint64_t etag = 0;
  EXPECT_FALSE(oc_etag_decode_resource_etag(&res, rep.get(), &etag));
}

TEST_F(TestETagWithServer, DecodeResource_InvalidChecksum)
{
  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);

  oc::RepPool pool{};
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  int err = oc_rep_encoder_create_map(oc_rep_get_encoder(), &etag_map,
                                      CborIndefiniteLength);
  err |=
    oc_rep_encode_text_string(&etag_map, kETagKey.data(), kETagKey.length());
  err |= oc_rep_encode_uint(&etag_map, oc_resource_get_etag(platform));
  err |= oc_rep_encode_text_string(&etag_map, kCRCKey.data(), kCRCKey.length());
  err |= oc_rep_encode_uint(&etag_map, 42);
  err |= oc_rep_encoder_close_container(oc_rep_get_encoder(), &etag_map);
  ASSERT_EQ(CborNoError, err);
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  uint64_t etag = 0;
  EXPECT_FALSE(oc_etag_decode_resource_etag(platform, rep.get(), &etag));
}

#endif // OC_HAS_FEATURE_CRC_ENCODER

template<oc_status_t CODE>
static void
getHandlerCheckCode(oc_client_response_t *data)
{
  oc::TestDevice::Terminate();
  EXPECT_EQ(CODE, data->code);
  *static_cast<bool *>(data->user_data) = true;
  OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
}

TEST_F(TestETagWithServer, GetResourceWithETag)
{
  // get insecure connection to the testing device
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID1);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  oc_resource_t *res = oc_core_get_resource_by_index(OCF_D, kDeviceID1);
  ASSERT_NE(nullptr, res);
  oc_resource_set_etag(res, 1337);

  // send get request to the /oic/d resource
  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_request(OC_GET, oc_string(res->uri), &ep, nullptr,
                            timeout.count(), getHandlerCheckCode<OC_STATUS_OK>,
                            LOW_QOS, &invoked, nullptr, nullptr));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  invoked = false;
  using etag_t = std::array<uint8_t, COAP_ETAG_LEN>;
  auto configure_req = [](coap_packet_t *req, const void *data) {
    auto etag = static_cast<const etag_t *>(data);
    coap_options_set_etag(req, etag->data(),
                          static_cast<uint8_t>(etag->size()));
  };
  etag_t etag{};
  memcpy(etag.data(), &res->etag, sizeof(res->etag));
  ASSERT_TRUE(oc_do_request(OC_GET, oc_string(res->uri), &ep, nullptr,
                            timeout.count(),
                            getHandlerCheckCode<OC_STATUS_NOT_MODIFIED>,
                            LOW_QOS, &invoked, configure_req, &etag));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

#ifdef OC_DYNAMIC_ALLOCATION

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

// resource with a support for batch interface but it doesn't set ETag in the
// request handler, so there should be no ETag in the response
TEST_F(TestETagWithServer, GetResourceWithETagAndCustomBatchHandlerNoETag)
{
  // create a resource with support for batch interface
  auto *dyn = addDynamicResource(
    "Dynamic Resource 3", "/dyn3", { "oic.d.dynamic", "oic.d.test" },
    { OC_IF_BASELINE, OC_IF_R, OC_IF_B }, kDeviceID1);

  // in the handler oc_set_send_response_etag() should be called to set ETag
  // if etag is not set then no ETag will be sent in the response

  // get insecure connection to the testing device
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID1);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto getHandler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_OK, data->code);
    EXPECT_EQ(0, data->etag.length);
    *static_cast<bool *>(data->user_data) = true;
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
  };

  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_request(OC_GET, oc_string(dyn->uri), &ep, "if=" OC_IF_B_STR,
                            timeout.count(), getHandler, LOW_QOS, &invoked,
                            nullptr, nullptr));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  // clean-up
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(dyn, true));
}

// resource with a support for batch interface and uses
// oc_set_send_response_etag to set ETag in the request handler
TEST_F(TestETagWithServer, GetResourceWithETagAndCustomBatchHandler)
{
  static std::array<uint8_t, 1> etag = { 42 };

  oc::DynamicResourceHandler handlers{};
  handlers.onGet = [](oc_request_t *request, oc_interface_mask_t iface,
                      void *) {
    if (iface == OC_IF_B) {
      ASSERT_EQ(0,
                oc_set_send_response_etag(request, etag.data(), etag.size()));
      if (request->etag_len == 1 && request->etag[0] == etag[0]) {
        oc_send_response(request, OC_STATUS_NOT_MODIFIED);
        return;
      }
      oc_rep_begin_root_object();
      oc_rep_set_boolean(root, empty, false);
      oc_rep_end_root_object();
      oc_send_response(request, OC_STATUS_OK);
      return;
    }
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  };
  auto *dyn = oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd("Dynamic Resource 3", "/dyn3",
                                 { "oic.d.dynamic", "oic.d.test" },
                                 {
                                   OC_IF_BASELINE,
                                   OC_IF_R,
                                   OC_IF_B,
                                 },
                                 handlers),
    kDeviceID1);

  // get insecure connection to the testing device
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID1);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto getHandler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
    ASSERT_EQ(etag.size(), data->etag.length);
    EXPECT_EQ(0, memcmp(etag.data(), data->etag.value, etag.size()));
    *static_cast<bool *>(data->user_data) = true;
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
  };

  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_request(OC_GET, oc_string(dyn->uri), &ep, "if=" OC_IF_B_STR,
                            timeout.count(), getHandler, LOW_QOS, &invoked,
                            nullptr, nullptr));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  auto getHandlerWithETag = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_NOT_MODIFIED, data->code);
    ASSERT_EQ(etag.size(), data->etag.length);
    EXPECT_EQ(0, memcmp(etag.data(), data->etag.value, etag.size()));
    *static_cast<bool *>(data->user_data) = true;
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
  };
  invoked = false;
  auto configure_req = [](coap_packet_t *req, const void *) {
    coap_options_set_etag(req, etag.data(), static_cast<uint8_t>(etag.size()));
  };
  ASSERT_TRUE(oc_do_request(OC_GET, oc_string(dyn->uri), &ep, "if=" OC_IF_B_STR,
                            timeout.count(), getHandlerWithETag, LOW_QOS,
                            &invoked, configure_req, nullptr));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  // clean-up
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(dyn, true));
}

#endif // !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

#endif // OC_DYNAMIC_ALLOCATION

#endif // OC_HAS_FEATURE_ETAG
