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

#include "api/oc_client_api_internal.h"
#include "api/oc_con_resource_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_etag_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/coap_options.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/observe.h"
#include "oc_api.h"
#include "oc_base64.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Collection.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Utility.h"
#include "util/oc_macros_internal.h"

#ifdef OC_SECURITY
#include "security/oc_security_internal.h"
#include "security/oc_sdi_internal.h"
#endif /* OC_SECURITY */

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std::chrono_literals;

namespace {
constexpr size_t kDeviceID{ 0 };

constexpr std::string_view kDynamicURI1 = "/dyn/discoverable";
constexpr std::string_view kDynamicURI2 = "/dyn/undiscoverable";
constexpr std::string_view kDynamicURI3 = "/dyn/observable";

constexpr std::string_view kCollectionURI = "/col";
constexpr std::string_view kColDynamicURI1 = "/col/discoverable";
constexpr std::string_view kColDynamicURI2 = "/col/undiscoverable";

const int g_latency{ oc_core_get_latency() };

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
const long g_max_app_data_size{ oc_get_max_app_data_size() };
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */

struct DiscoveryLinkData
{
  std::string rel;
  std::string anchor;
  std::string href;
  std::vector<std::string> resourceTypes;
  std::vector<oc_interface_mask_t> interfaces;
  oc_resource_properties_t properties;
  std::string tagPosDesc;
  std::string tagFuncDesc;
  std::string tagLocation;
  std::vector<double> tagPosRel;
};

using DiscoveryLinkDataMap = std::unordered_map<std::string, DiscoveryLinkData>;

struct DiscoveryBatchItem
{
  std::string deviceUUID;
  std::string href;
#ifdef OC_HAS_FEATURE_ETAG
  std::vector<uint8_t> etag;
#endif /* OC_HAS_FEATURE_ETAG */
};

using DiscoveryBatchData = std::unordered_map<std::string, DiscoveryBatchItem>;

} // namespace

struct DynamicResourceData
{
  int power;
};

class TestDiscoveryWithServer : public ::testing::Test {
public:
  static void SetUpTestCase()
  {
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
    oc_set_max_app_data_size(16384);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */

    // all endpoints should have lat attribute if latency is !=0
    oc_core_set_latency(42);

    ASSERT_TRUE(oc::TestDevice::StartServer());

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_CON, kDeviceID, false,
                                     OC_PERM_RETRIEVE | OC_PERM_UPDATE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#ifdef OC_DYNAMIC_ALLOCATION
    addDynamicResources();

#ifdef OC_COLLECTIONS
    addColletions();
#endif /* OC_COLLECTIONS */
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();

    // restore defaults
    oc_core_set_latency(g_latency);
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
    oc_set_max_app_data_size(g_max_app_data_size);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */
  }

  void SetUp() override
  {
    coap_observe_counter_reset();
  }

#ifdef OC_DYNAMIC_ALLOCATION
  static void onGetDynamicResource(oc_request_t *request, oc_interface_mask_t,
                                   void *user_data)
  {
    const auto *data = static_cast<DynamicResourceData *>(user_data);
    oc_rep_start_root_object();
    oc_rep_set_int(root, power, data->power);
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
  }

  static void addDynamicResources();

#ifdef OC_COLLECTIONS
  static void addColletions();
#endif /* OC_COLLECTIONS */

  static std::unordered_map<std::string, DynamicResourceData> dynamicResources;
#endif // OC_DYNAMIC_ALLOCATION

#ifdef OC_HAS_FEATURE_ETAG
  static void assertETag(oc_coap_etag_t etag1, uint64_t etag2)
  {
    ASSERT_EQ(sizeof(etag2), etag1.length);
    std::array<uint8_t, sizeof(etag2)> etag2_buf{};
    memcpy(&etag2_buf[0], &etag2, etag2_buf.size());
    ASSERT_EQ(0, memcmp(&etag1.value[0], &etag2_buf[0], etag1.length));
  }

  static void assertResourceETag(oc_coap_etag_t etag,
                                 const oc_resource_t *resource)
  {
    ASSERT_NE(nullptr, resource);
    assertETag(etag, resource->etag);
  }

  static void assertDiscoveryETag(oc_coap_etag_t etag,
                                  const oc_endpoint_t *endpoint, size_t device,
                                  bool is_batch = false)
  {
    if (is_batch) {
      assertETag(etag, oc_discovery_get_batch_etag(endpoint, device));
    } else {
      const oc_resource_t *discovery =
        oc_core_get_resource_by_index(OCF_RES, device);
      assertResourceETag(etag, discovery);
    }
  }

  static void assertBatchETag(oc_coap_etag_t etag, size_t device,
                              const DiscoveryBatchData &bd)
  {
    const oc_resource_t *discovery =
      oc_core_get_resource_by_index(OCF_RES, device);
    ASSERT_NE(nullptr, discovery);
    uint64_t max_etag = discovery->etag;
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

#endif /* OC_HAS_FEATURE_ETAG */
};

#ifdef OC_DYNAMIC_ALLOCATION

std::unordered_map<std::string, DynamicResourceData>
  TestDiscoveryWithServer::dynamicResources{};

void
TestDiscoveryWithServer::addDynamicResources()
{
  oc::DynamicResourceHandler handlers1{};
  dynamicResources[std::string(kDynamicURI1)] = { 42 };
  handlers1.onGet = onGetDynamicResource;
  handlers1.onGetData = &dynamicResources[std::string(kDynamicURI1)];

  oc::DynamicResourceHandler handlers2{};
  dynamicResources[std::string(kDynamicURI2)] = { 1337 };
  handlers2.onGet = onGetDynamicResource;
  handlers2.onGetData = &dynamicResources[std::string(kDynamicURI2)];

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
    oc_resource_t *res = oc::TestDevice::AddDynamicResource(dr, kDeviceID);
    ASSERT_NE(nullptr, res);

    oc_resource_tag_pos_desc(res, OC_POS_TOP);
    oc_resource_tag_func_desc(res, OC_ENUM_ACTIVE);
    oc_resource_tag_locn(res, OCF_LOCN_RECEIPTIONROOM);
    oc_resource_tag_pos_rel(res, 1, 33, 7);

#ifdef OC_OSCORE
    // add secure multicast endpoints to list of endpoints
    oc_resource_set_secure_mcast(res, true);
#endif /* OC_OSCORE */
  }
}

#ifdef OC_COLLECTIONS
void
TestDiscoveryWithServer::addColletions()
{
  constexpr std::string_view powerSwitchRT = "oic.d.power";

  auto col = oc::NewCollection("col", kCollectionURI, kDeviceID, "oic.wk.col");
  ASSERT_NE(nullptr, col);
  oc_resource_set_discoverable(&col->res, true);
  oc_collection_add_supported_rt(&col->res, powerSwitchRT.data());
  oc_collection_add_mandatory_rt(&col->res, powerSwitchRT.data());
  ASSERT_TRUE(oc_add_collection_v1(&col->res));

  oc::DynamicResourceHandler handlers1{};
  dynamicResources[std::string(kColDynamicURI1)] = { 404 };
  handlers1.onGet = onGetDynamicResource;
  handlers1.onGetData = &dynamicResources[std::string(kColDynamicURI1)];

  auto dr1 = oc::makeDynamicResourceToAdd(
    "Collection Resource 1", std::string(kColDynamicURI1),
    { std::string(powerSwitchRT), "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
    handlers1);
  oc_resource_t *res1 = oc::TestDevice::AddDynamicResource(dr1, kDeviceID);
  ASSERT_NE(nullptr, res1);
  oc_link_t *link1 = oc_new_link(res1);
  ASSERT_NE(link1, nullptr);
  oc_collection_add_link(&col->res, link1);

  oc::DynamicResourceHandler handlers2{};
  dynamicResources[std::string(kColDynamicURI2)] = { 1 };
  handlers2.onGet = onGetDynamicResource;
  handlers2.onGetData = &dynamicResources[std::string(kColDynamicURI2)];

  auto dr2 = oc::makeDynamicResourceToAdd(
    "Collection Resource 2", std::string(kColDynamicURI2),
    { std::string(powerSwitchRT), "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
    handlers2, 0);
  oc_resource_t *res2 = oc::TestDevice::AddDynamicResource(dr2, kDeviceID);
  ASSERT_NE(nullptr, res2);
  oc_link_t *link2 = oc_new_link(res2);
  ASSERT_NE(link2, nullptr);
  oc_collection_add_link(&col->res, link2);

  col.release();
}

#endif /* OC_COLLECTIONS */

#endif // OC_DYNAMIC_ALLOCATION

TEST_F(TestDiscoveryWithServer, GetResourceByIndex_F)
{
  EXPECT_EQ(nullptr,
            oc_core_get_resource_by_index(OCF_RES, /*device*/ SIZE_MAX));
}

TEST_F(TestDiscoveryWithServer, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_RES, kDeviceID));
}

TEST_F(TestDiscoveryWithServer, GetResourceByURI_F)
{
  EXPECT_EQ(nullptr, oc_core_get_resource_by_uri_v1(
                       OCF_RES_URI, OC_CHAR_ARRAY_LEN(OCF_RES_URI),
                       /*device*/ SIZE_MAX));
}

TEST_F(TestDiscoveryWithServer, GetResourceByURI)
{
  oc_resource_t *res = oc_core_get_resource_by_uri_v1(
    OCF_RES_URI, OC_CHAR_ARRAY_LEN(OCF_RES_URI), kDeviceID);
  EXPECT_NE(nullptr, res);

  EXPECT_STREQ(OCF_RES_URI, oc_string(res->uri));
}

template<oc_status_t CODE>
static void
getRequestWithDomainQuery(const std::string &query)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(CODE, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, &ep, query.c_str(),
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

#ifdef OC_SECURITY

TEST_F(TestDiscoveryWithServer, GetRequest_FailPrivateSecurityDomain)
{
  oc_sec_sdi_t *sdi = oc_sec_sdi_get(kDeviceID);
  ASSERT_NE(nullptr, sdi);
  sdi->priv = true;

  oc_uuid_t uuid{};
  std::array<char, OC_UUID_LEN> uuid_str{};
  oc_uuid_to_str(&uuid, &uuid_str[0], uuid_str.size());
  std::string query = OCF_RES_QUERY_SDUUID "=" + std::string(uuid_str.data());

  getRequestWithDomainQuery<OC_REQUEST_TIMEOUT>(query);

  // restore default
  oc_sec_sdi_clear(sdi);
}

TEST_F(TestDiscoveryWithServer, GetRequest_FailInvalidSecurityDomain)
{
  // bad format of uuid
  std::string query = OCF_RES_QUERY_SDUUID "=42";
  getRequestWithDomainQuery<OC_REQUEST_TIMEOUT>(query);
}

TEST_F(TestDiscoveryWithServer, GetRequest_FailWrongSecurityDomain)
{
  oc_sec_sdi_t *sdi = oc_sec_sdi_get(kDeviceID);
  ASSERT_NE(nullptr, sdi);

  oc_uuid_t uuid1;
  oc_gen_uuid(&uuid1);
  memcpy(&sdi->uuid.id, uuid1.id, sizeof(uuid1.id));

  // non-matching uuid
  oc_uuid_t uuid2;
  do {
    oc_gen_uuid(&uuid2);
  } while (memcmp(uuid1.id, uuid2.id, sizeof(uuid2.id)) == 0);

  std::array<char, OC_UUID_LEN> uuid_str{};
  oc_uuid_to_str(&uuid2, &uuid_str[0], uuid_str.size());
  std::string query = OCF_RES_QUERY_SDUUID "=" + std::string(uuid_str.data());

  getRequestWithDomainQuery<OC_REQUEST_TIMEOUT>(query);

  // restore default
  oc_sec_sdi_clear(sdi);
}

#endif /* OC_SECURITY */

// payloads are too large for static buffers
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)

static void
matchResourceLink(const oc_resource_t *resource, const DiscoveryLinkData &link)
{
  // href
  EXPECT_STREQ(link.href.c_str(), oc_string(resource->uri));

  // resource types
  auto resourceTypes = oc::GetVector(resource->types);
  EXPECT_EQ(link.resourceTypes.size(), resourceTypes.size());
  for (const auto &rt : link.resourceTypes) {
    EXPECT_NE(std::end(resourceTypes),
              std::find(std::begin(resourceTypes), std::end(resourceTypes), rt))
      << "resource type: " << rt << " not found";
  }

  // interfaces
  unsigned iface_mask = 0;
  for (const auto &iface : link.interfaces) {
    iface_mask |= iface;
  }
  EXPECT_EQ(iface_mask, resource->interfaces);

  // properties
  EXPECT_EQ(link.properties, resource->properties & OCF_RES_POLICY_PROPERTIES);
}

static void
verifyLinks(const DiscoveryLinkDataMap &links)
{
#ifdef OC_SERVER
  auto verifyUndiscoverable = [&links](std::string_view uri) {
    oc_resource_t *res =
      oc_ri_get_app_resource_by_uri(uri.data(), uri.length(), kDeviceID);
    ASSERT_NE(nullptr, res);
    ASSERT_EQ(0, res->properties & OC_DISCOVERABLE);
    EXPECT_EQ(std::end(links), links.find(std::string(uri)));
  };

  auto verifyDiscoverable = [&links](std::string_view uri) {
    oc_resource_t *res =
      oc_ri_get_app_resource_by_uri(uri.data(), uri.length(), kDeviceID);
    ASSERT_NE(nullptr, res);
    ASSERT_NE(0, res->properties & OC_DISCOVERABLE);
    const auto &linkData = links.find(std::string(uri));
    ASSERT_NE(std::end(links), linkData);
    matchResourceLink(res, linkData->second);
  };

  verifyDiscoverable(kDynamicURI1);
  verifyUndiscoverable(kDynamicURI2);

#ifdef OC_COLLECTIONS
  oc_collection_t *col = oc_get_collection_by_uri(
    kCollectionURI.data(), kCollectionURI.length(), kDeviceID);
  ASSERT_NE(nullptr, col);
  const auto &colLink = links.find(std::string(kCollectionURI));
  ASSERT_NE(std::end(links), colLink);
  matchResourceLink(&col->res, colLink->second);

  for (const oc_link_t *link = oc_collection_get_links(&col->res);
       link != nullptr; link = link->next) {
    const auto &linkData = links.find(oc_string(link->resource->uri));
    if ((link->resource->properties & OC_DISCOVERABLE) == 0) {
      EXPECT_EQ(std::end(links), links.find(std::string(kDynamicURI2)));
      continue;
    }
    ASSERT_NE(std::end(links), linkData);
    matchResourceLink(link->resource, linkData->second);
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
}

TEST_F(TestDiscoveryWithServer, GetRequestWithSecurityDomain)
{
  oc_uuid_t uuid;
  oc_gen_uuid(&uuid);

#ifdef OC_SECURITY
  oc_sec_sdi_t *sdi = oc_sec_sdi_get(kDeviceID);
  ASSERT_NE(nullptr, sdi);
  memcpy(&sdi->uuid.id, uuid.id, sizeof(uuid.id));
#endif /* OC_SECURITY */

  std::array<char, OC_UUID_LEN> uuid_str{};
  oc_uuid_to_str(&uuid, &uuid_str[0], uuid_str.size());
  std::string query = OCF_RES_QUERY_SDUUID "=" + std::string(uuid_str.data());

  getRequestWithDomainQuery<OC_STATUS_OK>(query);

#ifdef OC_SECURITY
  // restore defaults
  oc_sec_sdi_clear(sdi);
#endif /* OC_SECURITY */
}

static DiscoveryLinkData
parseLink(const oc_rep_t *link)
{
  DiscoveryLinkData linkData{};

  char *str;
  size_t str_len;
  // rel: string
  if (oc_rep_get_string(link, "rel", &str, &str_len)) {
    linkData.rel = std::string(str, str_len);
  }

  // anchor: string
  if (oc_rep_get_string(link, "anchor", &str, &str_len)) {
    linkData.anchor = std::string(str, str_len);
  }

  // href: string
  if (oc_rep_get_string(link, "href", &str, &str_len)) {
    linkData.href = std::string(str, str_len);
  }

  // rt: array of strings
  oc_string_array_t str_array;
  size_t str_array_len;
  if (oc_rep_get_string_array(link, "rt", &str_array, &str_array_len)) {
    for (size_t i = 0; i < str_array_len; ++i) {
      linkData.resourceTypes.emplace_back(
        oc_string_array_get_item(str_array, i));
    }
  }

  // if: array of strings
  if (oc_rep_get_string_array(link, "if", &str_array, &str_array_len)) {
    for (size_t i = 0; i < str_array_len; ++i) {
      std::string iface_str = oc_string_array_get_item(str_array, i);
      oc_interface_mask_t iface =
        oc_ri_get_interface_mask(iface_str.c_str(), iface_str.length());
      if (iface == 0) {
        continue;
      }
      linkData.interfaces.emplace_back(iface);
    }
  }

  // p: {"bm": int}
  if (oc_rep_t * obj; oc_rep_get_object(link, "p", &obj)) {
    if (int64_t properties; oc_rep_get_int(obj, "bm", &properties)) {
      linkData.properties = static_cast<oc_resource_properties_t>(properties);
    }
  }

  // tag-pos-desc: string
  if (oc_rep_get_string(link, "tag-pos-desc", &str, &str_len)) {
    linkData.tagPosDesc = std::string(str, str_len);
  }

  // tag-func-desc: string
  if (oc_rep_get_string(link, "tag-func-desc", &str, &str_len)) {
    linkData.tagFuncDesc = std::string(str, str_len);
  }

  // tag-locn: string
  if (oc_rep_get_string(link, "tag-locn", &str, &str_len)) {
    linkData.tagLocation = std::string(str, str_len);
  }

  // tag-pos-rel: double[3]
  double *pos_rel;
  if (size_t pos_rel_size;
      oc_rep_get_double_array(link, "tag-pos-rel", &pos_rel, &pos_rel_size)) {
    for (size_t i = 0; i < pos_rel_size; ++i) {
      linkData.tagPosRel.emplace_back(pos_rel[i]);
    }
  }

  return linkData;
}

static DiscoveryLinkDataMap
parseLinks(const oc_rep_t *rep)
{
  DiscoveryLinkDataMap links{};
  for (; rep != nullptr; rep = rep->next) {
    auto link = parseLink(rep->value.object);
    links[link.href] = link;
  }
  return links;
}

// default interface - LL
// payload contains array of discoverable resources
// [
//   {
//     "rel": "self", // for /oic/res only
//     "anchor": "ocf://03ddc383-a500-41f8-75a6-5c3e51d97906",
//     "href": "/oc/con",
//     "rt": [
//         "oic.wk.con"
//     ],
//     "if": [
//         "oic.if.rw",
//         "oic.if.baseline"
//     ],
//     "p": {
//         "bm": 3
//     },
//     "eps": null
//     "tag-pos-desc": <string>
//     "tag-func-desc": <string>
//     "tag-locn": string
//     "tag-pos-rel": double[3]
//   },
//   ...
// ]
TEST_F(TestDiscoveryWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
#ifdef OC_HAS_FEATURE_ETAG
    assertDiscoveryETag(data->etag, data->endpoint, data->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<DiscoveryLinkDataMap *>(data->user_data) =
      parseLinks(data->payload);
  };

  DiscoveryLinkDataMap links{};
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, &ep, nullptr, timeout.count(),
                                     get_handler, HIGH_QOS, &links));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_FALSE(links.empty());

  verifyLinks(links);
}

struct DiscoveryBaselineData
{
  oc::BaselineData baseline;
  std::string sduuid;
  std::string sdname;
  DiscoveryLinkDataMap links;
};

static DiscoveryBaselineData
parseBaselinePayload(const oc_rep_t *payload)
{
  const oc_rep_t *rep = payload->value.object;
  DiscoveryBaselineData data{};
  if (auto bl_opt = oc::ParseBaselineData(rep)) {
    data.baseline = *bl_opt;
  }

  char *str;
  size_t str_len;
  // sduuid: string
  if (oc_rep_get_string(rep, "sduuid", &str, &str_len)) {
    data.sduuid = std::string(str, str_len);
  }

  // sdname: string
  if (oc_rep_get_string(rep, "sdname", &str, &str_len)) {
    data.sdname = std::string(str, str_len);
  }

  // links
  if (oc_rep_t *obj = nullptr; oc_rep_get_object_array(rep, "links", &obj)) {
    data.links = parseLinks(obj);
  }
  return data;
}

// baseline interface:
// {
//   <baseline properties>
// #ifdef OC_SECURITY
//   if (!sdi.priv) {
//     "sduuid": <uuid string>
//     "sdname": <string>
//   }
// #endif
//
//   "links": [
//     <link1>,
//     <link2>,
//     ...
//   ]
// }
TEST_F(TestDiscoveryWithServer, GetRequestBaseline)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

#ifdef OC_SECURITY
  oc_uuid_t uuid;
  oc_gen_uuid(&uuid);
  oc_sec_sdi_t *sdi = oc_sec_sdi_get(kDeviceID);
  ASSERT_NE(nullptr, sdi);
  memcpy(&sdi->uuid.id, uuid.id, sizeof(uuid.id));
  const std::string_view sdname = "Test Security Domain";
  oc_new_string(&sdi->name, sdname.data(), sdname.length());
#endif /* OC_SECURITY */

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
#ifdef OC_HAS_FEATURE_ETAG
    assertDiscoveryETag(data->etag, data->endpoint, data->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *baseline = static_cast<DiscoveryBaselineData *>(data->user_data);
    *baseline = parseBaselinePayload(data->payload);
  };

  DiscoveryBaselineData baseline{};
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, &ep, "if=" OC_IF_BASELINE_STR,
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &baseline));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_FALSE(baseline.links.empty());

#ifdef OC_SECURITY
  std::array<char, OC_UUID_LEN> uuid_str{};
  oc_uuid_to_str(&sdi->uuid, &uuid_str[0], uuid_str.size());
  EXPECT_STREQ(std::string(uuid_str.data()).c_str(), baseline.sduuid.c_str());
  EXPECT_STREQ(oc_string(sdi->name), baseline.sdname.c_str());
#endif /* OC_SECURITY */

  verifyLinks(baseline.links);

#ifdef OC_SECURITY
  // restore defaults
  oc_sec_sdi_clear(sdi);
#endif /* OC_SECURITY */
}

#ifdef OC_RES_BATCH_SUPPORT

struct batch_resources_t
{
  const oc_endpoint_t *endpoint;
  std::vector<const oc_resource_t *> resources;
};

static batch_resources_t
getBatchResources(const oc_endpoint_t *endpoint)
{
  batch_resources_t batch{};
  batch.endpoint = endpoint;

  oc_resources_iterate(
    kDeviceID, true, true, true, true,
    [](oc_resource_t *resource, void *data) {
      if (auto *br = static_cast<batch_resources_t *>(data);
          oc_discovery_resource_is_in_batch_response(resource, br->endpoint,
                                                     true)) {
        br->resources.emplace_back(resource);
      }
      return true;
    },
    &batch);
  return batch;
}

#ifndef OC_SECURITY

static void
verifyBatchPayloadResource(const DiscoveryBatchData &dbd,
                           const oc_resource_t *resource)
{
  ASSERT_NE(nullptr, resource);
  const auto &it = dbd.find(std::string(oc_string(resource->uri)));
  ASSERT_NE(std::end(dbd), it)
    << "resource: " << oc_string(resource->uri) << " not found";
#ifdef OC_HAS_FEATURE_ETAG
  oc_coap_etag_t etag{};
  std::copy(it->second.etag.begin(), it->second.etag.end(), etag.value);
  etag.length = static_cast<uint8_t>(it->second.etag.size());
  TestDiscoveryWithServer::assertResourceETag(etag, resource);
#endif /* OC_HAS_FEATURE_ETAG */
}

static void
verifyBatchPayload(const DiscoveryBatchData &dbd,
                   const std::vector<const oc_resource_t *> &expected)
{
  ASSERT_EQ(expected.size(), dbd.size());
  for (const auto *resource : expected) {
    verifyBatchPayloadResource(dbd, resource);
  }
}

static void
verifyBatchPayload(const DiscoveryBatchData &dbd, const oc_endpoint_t *endpoint)
{
  auto br = getBatchResources(endpoint);
  verifyBatchPayload(dbd, br.resources);
}

#endif /* !OC_SECURITY */

static DiscoveryBatchData
parseBatchPayload(const oc_rep_t *payload)
{
  auto extractUUIDAndURI =
    [](std::string_view href) -> std::pair<std::string, std::string> {
    // skip past "ocf:// prefix"
    std::string_view input = href.substr(6);
    size_t uriStart = input.find('/');

    if (uriStart == std::string_view::npos) {
      return std::make_pair("", "");
    }
    // Extract the UUID and the URI as separate substrings
    std::string_view uuid = input.substr(0, uriStart - 1);
    std::string_view uri = input.substr(uriStart);
    return std::make_pair(std::string(uuid), std::string(uri));
  };

  DiscoveryBatchData data{};
  for (const oc_rep_t *rep = payload; rep != nullptr; rep = rep->next) {
    const oc_rep_t *obj = rep->value.object;
    DiscoveryBatchItem bi{};
    char *str;
    size_t str_len;
    // href: string
    if (oc_rep_get_string(obj, "href", &str, &str_len)) {
      std::string_view href(str, str_len);
      auto [uuid, uri] = extractUUIDAndURI(href);
      bi.deviceUUID = uuid;
      bi.href = uri;
    }

#ifdef OC_HAS_FEATURE_ETAG
    // etag: byte string
    if (oc_rep_get_byte_string(obj, "etag", &str, &str_len)) {
      bi.etag.resize(str_len);
      std::copy(&str[0], &str[str_len], std::begin(bi.etag));
    }
#endif /* OC_HAS_FEATURE_ETAG */

    if (!bi.href.empty()) {
      data[bi.href] = bi;
    }
  }

  return data;
}

// batch interface
// [
//   {
//     "href": "ocf://<device uuid>/<resource uri>",
//     "rep": {
//        <GET representation with default interface>
//      }
//   },
//   ...
// ]
TEST_F(TestDiscoveryWithServer, GetRequestBatch)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *batch = static_cast<DiscoveryBatchData *>(data->user_data);
    *batch = parseBatchPayload(data->payload);
#ifdef OC_SECURITY
    // need secure endpoint to get batch response if OC_SECURITY is enabled
    ASSERT_EQ(OC_STATUS_BAD_REQUEST, data->code);
#else /* !OC_SECURITY */
    ASSERT_EQ(OC_STATUS_OK, data->code);
#ifdef OC_HAS_FEATURE_ETAG
    assertDiscoveryETag(data->etag, data->endpoint, data->endpoint->device,
                        true);
    // the response etag should be the highest etag contained the payload
    assertBatchETag(data->etag, data->endpoint->device, *batch);
#endif /* OC_HAS_FEATURE_ETAG */
#endif /* OC_SECURITY */
  };

  DiscoveryBatchData data{};
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, &ep, "if=" OC_IF_B_STR,
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &data));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

#ifdef OC_SECURITY
  EXPECT_TRUE(data.empty());
#else  /* !OC_SECURITY */
  ASSERT_FALSE(data.empty());
  verifyBatchPayload(data, &ep);
#endif /* OC_SECURITY */
}

#ifdef OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES

static std::string
encodeETagToBase64(const oc_coap_etag_t *etag)
{
  std::array<uint8_t, 12> etagB64{};
  int b64_len =
    oc_base64_encode_v1(OC_BASE64_ENCODING_URL, false, &etag->value[0],
                        etag->length, &etagB64[0], etagB64.size());
  if (b64_len == -1) {
    throw std::string("base64 encode failed");
  }
  std::string etagStr{};
  etagStr.insert(etagStr.end(), etagB64.data(),
                 etagB64.data() + static_cast<size_t>(b64_len));
  return etagStr;
}

static std::string
encodeETagToBase64(uint64_t etag)
{
  oc_coap_etag_t etagBytes{};
  memcpy(&etagBytes.value[0], &etag, sizeof(etag));
  etagBytes.length = sizeof(etag);
  return encodeETagToBase64(&etagBytes);
}

static std::string
testBatchIncrementalChangesQuery(const std::vector<uint64_t> &etags)
{
  std::string query = "if=" OC_IF_B_STR;
  if (etags.empty()) {
    return query + "&" OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY;
  }

  size_t count = 0;
  for (auto etag : etags) {
    if (count == 0) {
      query += "&" OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY "=";
    } else {
      query += ",";
    }
    query += encodeETagToBase64(etag);
    ++count;
    if (count == 6) {
      count = 0;
    }
  }
  return query;
}

static void
testBatchIncrementalChanges(
  const oc_endpoint_t *ep, const oc_coap_etag_t *etag0,
  const std::string &query, oc_status_t expectedCode = OC_STATUS_OK,
  const std::vector<const oc_resource_t *> &expected = {})
{
  struct DiscoveryBatchResponse
  {
    oc_status_t code;
    DiscoveryBatchData bd;
  };

  auto getHandler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *dbr = static_cast<DiscoveryBatchResponse *>(data->user_data);
    dbr->code = data->code;
    dbr->bd = parseBatchPayload(data->payload);
#ifdef OC_SECURITY
    // need secure endpoint to get batch response if OC_SECURITY is enabled
    ASSERT_EQ(OC_STATUS_BAD_REQUEST, data->code);
#else  /* !OC_SECURITY */
    ASSERT_TRUE(OC_STATUS_OK == data->code ||
                OC_STATUS_NOT_MODIFIED == data->code);
    TestDiscoveryWithServer::assertDiscoveryETag(data->etag, data->endpoint,
                                                 data->endpoint->device, true);
#endif /* OC_SECURITY */
  };

  DiscoveryBatchResponse dbr{};
  auto timeout = 1s;
  auto configureReq = [](coap_packet_t *req, const void *data) {
    if (data == nullptr) {
      return;
    }
    const auto *etag = static_cast<const oc_coap_etag_t *>(data);
    coap_options_set_etag(req, etag->value, etag->length);
  };
  ASSERT_TRUE(oc_do_request(OC_GET, OCF_RES_URI, ep, query.c_str(),
                            timeout.count(), getHandler, HIGH_QOS, &dbr,
                            configureReq, etag0));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

#ifdef OC_SECURITY
  EXPECT_TRUE(dbr.bd.empty());
  (void)expectedCode;
  (void)expected;
#else  /* !OC_SECURITY */
  ASSERT_EQ(expectedCode, dbr.code);
  if (dbr.code == OC_STATUS_OK) {
    ASSERT_FALSE(dbr.bd.empty());
    verifyBatchPayload(dbr.bd, expected);
  }
  if (dbr.code == OC_STATUS_NOT_MODIFIED) {
    EXPECT_TRUE(dbr.bd.empty());
  }
#endif /* OC_SECURITY */
}

static void
testBatchIncrementalChanges(
  const oc_endpoint_t *ep, uint64_t etag0, const std::string &query,
  oc_status_t expectedCode = OC_STATUS_OK,
  const std::vector<const oc_resource_t *> &expected = {})
{
  if (etag0 == OC_ETAG_UNINITIALIZED) {
    testBatchIncrementalChanges(ep, nullptr, query, expectedCode, expected);
    return;
  }

  oc_coap_etag_t coapETag{};
  memcpy(&coapETag.value[0], &etag0, sizeof(etag0));
  coapETag.length = sizeof(etag0);
  testBatchIncrementalChanges(ep, &coapETag, query, expectedCode, expected);
}

TEST_F(TestDiscoveryWithServer, GetRequestBatchIncremental_Single)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto br = getBatchResources(&ep);
  // sort in descending order
  std::sort(br.resources.begin(), br.resources.end(),
            [](const oc_resource_t *a, const oc_resource_t *b) {
              return a->etag > b->etag;
            });
  ASSERT_LT(1, br.resources.size());
  uint64_t etag0 = br.resources[br.resources.size() / 2 - 1]->etag;
  ASSERT_NE(OC_ETAG_UNINITIALIZED, etag0);

  std::vector<const oc_resource_t *> expected{};
  std::for_each(br.resources.begin(), br.resources.end(),
                [&expected, etag0](const oc_resource_t *resource) {
                  if (resource->etag > etag0) {
                    expected.emplace_back(resource);
                  }
                });
  testBatchIncrementalChanges(&ep, etag0, testBatchIncrementalChangesQuery({}),
                              OC_STATUS_OK, expected);
}

// Invalid ETag0 should be ignored
TEST_F(TestDiscoveryWithServer,
       GetRequestBatchIncremental_Single_InvalidIncrementalETag0)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  // invalid ETag0: size of bytes not equal to sizeof(uint64_t), it should be
  // ignored and should receive all resources
  std::vector<uint8_t> etag0Bytes{ 'e', 't', 'a', 'g', '0' };
  assert(etag0Bytes.size() <= COAP_ETAG_LEN);
  oc_coap_etag_t etag0{};
  memcpy(&etag0.value[0], &etag0Bytes[0], etag0Bytes.size());
  etag0.length = static_cast<uint8_t>(etag0Bytes.size());

  auto br = getBatchResources(&ep);
  ASSERT_FALSE(br.resources.empty());

  testBatchIncrementalChanges(&ep, &etag0, testBatchIncrementalChangesQuery({}),
                              OC_STATUS_OK, br.resources);
}

// invalid ETags in the query should be ignored, but if a single valid ETag is
// found then is should be used
TEST_F(TestDiscoveryWithServer, GetRequestBatchIncremental_InvalidETags)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  // get non-batch resources
  batch_resources_t nonBatch{};
  nonBatch.endpoint = &ep;
  oc_resources_iterate(
    kDeviceID, true, true, true, true,
    [](oc_resource_t *resource, void *data) {
      if (auto *br = static_cast<batch_resources_t *>(data);
          !oc_discovery_resource_is_in_batch_response(resource, br->endpoint,
                                                      false)) {
        br->resources.emplace_back(resource);
      }
      return true;
    },
    &nonBatch);

  std::string query =
    "if=" OC_IF_B_STR "&" OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY "=12345,67890";
  for (size_t i = 0; i < 2 && i < nonBatch.resources.size(); ++i) {
    query += ",";
    query += encodeETagToBase64(nonBatch.resources[i]->etag);
  }
  query += ",,leetETag";
  query += "&" OC_ETAG_QUERY_INCREMENTAL_CHANGES_KEY "=,,";
  for (size_t i = 2; i < 4 && i < nonBatch.resources.size(); ++i) {
    query += ",";
    std::string etagStr = std::to_string(nonBatch.resources[i]->etag);
    if (etagStr.length() > COAP_ETAG_LEN) {
      etagStr.resize(COAP_ETAG_LEN);
    }
    oc_coap_etag_t etag{};
    memcpy(&etag.value[0], etagStr.data(), etagStr.length());
    etag.length = static_cast<uint8_t>(etagStr.length());
    query += encodeETagToBase64(&etag);
  }

  auto br = getBatchResources(&ep);
  ASSERT_LT(1, br.resources.size());
  // sort in descending order
  std::sort(br.resources.begin(), br.resources.end(),
            [](const oc_resource_t *a, const oc_resource_t *b) {
              return a->etag > b->etag;
            });
  uint64_t valid = br.resources[br.resources.size() / 2 - 1]->etag;
  query += "," + encodeETagToBase64(valid);
  query += ",end";

  std::vector<const oc_resource_t *> expected{};
  std::for_each(br.resources.begin(), br.resources.end(),
                [&expected, valid](const oc_resource_t *resource) {
                  if (resource->etag > valid) {
                    expected.emplace_back(resource);
                  }
                });
  testBatchIncrementalChanges(&ep, nullptr, query, OC_STATUS_OK, expected);
}

TEST_F(TestDiscoveryWithServer,
       GetRequestBatchIncremental_Single_InvalidIncrementalUpdates)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto br = getBatchResources(&ep);
  ASSERT_FALSE(br.resources.empty());
  // sort in descending order
  std::sort(br.resources.begin(), br.resources.end(),
            [](const oc_resource_t *a, const oc_resource_t *b) {
              return a->etag > b->etag;
            });
  // no resource should match (> highest etag), so we should get all resources
  uint64_t etag0 = br.resources[0]->etag + 1;
  testBatchIncrementalChanges(
    &ep, etag0,
    testBatchIncrementalChangesQuery({ etag0 + 1, etag0 + 2, etag0 + 3 }),
    OC_STATUS_OK, br.resources);
}

// Test with multiple etags in the query, sorted in descending order, so only
// the first should trigger the iteration of resources and subsequent ETag
// candidates should be skipped because they have a lower value
TEST_F(TestDiscoveryWithServer, GetRequestBatchIncremental_Multiple)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto br = getBatchResources(&ep);
  ASSERT_LT(1, br.resources.size());
  // sort in descending order
  std::sort(br.resources.begin(), br.resources.end(),
            [](const oc_resource_t *a, const oc_resource_t *b) {
              return a->etag > b->etag;
            });
  // set etag0 so it will not match any resource, which should result in
  // the query getting examined
  uint64_t etag0 = br.resources[0]->etag + 1;

  uint64_t pivot = br.resources[br.resources.size() / 2 - 1]->etag - 1;
  std::vector<uint64_t> etags{};
  std::vector<const oc_resource_t *> expected{};
  std::for_each(br.resources.begin(), br.resources.end(),
                [&etags, &expected, pivot](const oc_resource_t *resource) {
                  if (resource->etag > pivot) {
                    expected.emplace_back(resource);
                  } else {
                    etags.emplace_back(resource->etag);
                  }
                });
  testBatchIncrementalChanges(&ep, etag0,
                              testBatchIncrementalChangesQuery(etags),
                              OC_STATUS_OK, expected);
}

// Test with multiple etags in the query, sorted in ascending order, so all
// candidates should trigger resources iteration and the last value should be
// finally used as the ETag
TEST_F(TestDiscoveryWithServer, GetRequestBatchIncremental_MultipleAscending)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto br = getBatchResources(&ep);
  ASSERT_LT(1, br.resources.size());
  // sort in ascending order
  std::sort(br.resources.begin(), br.resources.end(),
            [](const oc_resource_t *a, const oc_resource_t *b) {
              return a->etag < b->etag;
            });
  // set etag0 so it will not match any resource, which should result in
  // the query getting examined
  uint64_t etag0 = br.resources[0]->etag + 1;

  uint64_t pivot = br.resources[br.resources.size() / 2 - 1]->etag - 1;
  std::vector<uint64_t> etags{};
  std::vector<const oc_resource_t *> expected{};
  std::for_each(br.resources.begin(), br.resources.end(),
                [&etags, &expected, pivot](const oc_resource_t *resource) {
                  if (resource->etag > pivot) {
                    expected.emplace_back(resource);
                  } else {
                    etags.emplace_back(resource->etag);
                  }
                });
  testBatchIncrementalChanges(&ep, etag0,
                              testBatchIncrementalChangesQuery(etags),
                              OC_STATUS_OK, expected);
}

/// Test will all batch resources etags in query, one of them is the latest
/// updated thus we should receive a VALID response with empty payload
TEST_F(TestDiscoveryWithServer, GetRequestBatchIncremental_AllAscending)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto br = getBatchResources(&ep);
  // sort in ascending order
  std::sort(br.resources.begin(), br.resources.end(),
            [](const oc_resource_t *a, const oc_resource_t *b) {
              return a->etag < b->etag;
            });
  std::vector<uint64_t> etags{};
  std::for_each(br.resources.begin(), br.resources.end(),
                [&etags](const oc_resource_t *resource) {
                  etags.emplace_back(resource->etag);
                });

  testBatchIncrementalChanges(&ep, static_cast<uint64_t>(OC_ETAG_UNINITIALIZED),
                              testBatchIncrementalChangesQuery(etags),
                              OC_STATUS_NOT_MODIFIED);
}

#endif /* OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES */

#endif /* OC_RES_BATCH_SUPPORT */

#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE

// observe with default (LL) interface
TEST_F(TestDiscoveryWithServer, Observe)
{
  ASSERT_TRUE(oc_get_con_res_announced());

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  struct observeData
  {
    DiscoveryLinkDataMap links;
    int observe;
  };
  auto onObserve = [](oc_client_response_t *cr) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, cr->code);
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload, true).data());
    auto *od = static_cast<observeData *>(cr->user_data);
    od->observe = cr->observe_option;
    if (cr->observe_option == OC_COAP_OPTION_OBSERVE_REGISTER ||
        cr->observe_option >= OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE) {
#ifdef OC_HAS_FEATURE_ETAG
      assertDiscoveryETag(cr->etag, cr->endpoint, cr->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
      od->links = parseLinks(cr->payload);
    }
  };
  observeData od{};
  ASSERT_TRUE(
    oc_do_observe(OCF_RES_URI, &ep, nullptr, onObserve, HIGH_QOS, &od));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, od.observe);
  ASSERT_FALSE(od.links.empty());
  verifyLinks(od.links);
  od.observe = 0;
  od.links.clear();

  // adding a resource should trigger an observe notification
  oc::DynamicResourceHandler handlers{};
  dynamicResources[std::string(kDynamicURI3)] = { 2001 };
  handlers.onGet = onGetDynamicResource;
  handlers.onGetData = &dynamicResources[std::string(kDynamicURI3)];
  oc_resource_t *res = oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd("Dynamic Resource 3",
                                 std::string(kDynamicURI3),
                                 { "oic.d.observable", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, handlers),
    kDeviceID);
  ASSERT_NE(nullptr, res);
  oc_resource_set_observable(res, true);

  int repeats = 0;
  while (od.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, od.observe);
  ASSERT_FALSE(od.links.empty());
  verifyLinks(od.links);
  od.observe = 0;
  od.links.clear();

  // deleting the resource should also trigger an observe notification
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(res, true));
  repeats = 0;
  while (od.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE + 1, od.observe);
  ASSERT_FALSE(od.links.empty());
  verifyLinks(od.links);
  od.observe = 0;
  od.links.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (od.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, od.observe);
}

// observe with baseline interface
TEST_F(TestDiscoveryWithServer, ObserveBaseline)
{
  ASSERT_TRUE(oc_get_con_res_announced());

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  struct observeBaselineData
  {
    DiscoveryBaselineData baseline;
    int observe;
  };
  auto onObserve = [](oc_client_response_t *cr) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, cr->code);
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload, true).data());
    auto *obd = static_cast<observeBaselineData *>(cr->user_data);
    obd->observe = cr->observe_option;
    if (cr->observe_option == OC_COAP_OPTION_OBSERVE_REGISTER ||
        cr->observe_option >= OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE) {
#ifdef OC_HAS_FEATURE_ETAG
      assertDiscoveryETag(cr->etag, cr->endpoint, cr->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
      obd->baseline = parseBaselinePayload(cr->payload);
    }
  };
  observeBaselineData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_BASELINE_STR,
                            onObserve, HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.baseline.links.empty());
  verifyLinks(obd.baseline.links);
  obd.observe = 0;
  obd.baseline.links.clear();

  // adding a resource should trigger an observe notification
  oc::DynamicResourceHandler handlers{};
  dynamicResources[std::string(kDynamicURI3)] = { 2001 };
  handlers.onGet = onGetDynamicResource;
  handlers.onGetData = &dynamicResources[std::string(kDynamicURI3)];
  oc_resource_t *res = oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd(
      "Dynamic Resource 3", std::string(kDynamicURI3),
      { "oic.d.observable", "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
      handlers, OC_DISCOVERABLE | OC_OBSERVABLE),
    kDeviceID);
  ASSERT_NE(nullptr, res);

  int repeats = 0;
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, obd.observe);
  ASSERT_FALSE(obd.baseline.links.empty());
  verifyLinks(obd.baseline.links);
  obd.observe = 0;
  obd.baseline.links.clear();

  // deleting the resource should also trigger an observe notification
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(res, true));
  repeats = 0;
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE + 1, obd.observe);
  ASSERT_FALSE(obd.baseline.links.empty());
  verifyLinks(obd.baseline.links);
  obd.observe = 0;
  obd.baseline.links.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, obd.observe);
}

#ifdef OC_RES_BATCH_SUPPORT

#ifdef OC_SECURITY

TEST_F(TestDiscoveryWithServer, ObserveBatch_F)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto onObserve = [](oc_client_response_t *cr) {
    oc::TestDevice::Terminate();
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload, true).data());
    *static_cast<bool *>(cr->user_data) = true;
    // insecure batch interface requests are unsupported
    EXPECT_EQ(OC_STATUS_BAD_REQUEST, cr->code);
    EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, cr->observe_option);
  };

  bool invoked = false;
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onObserve,
                            HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_TRUE(invoked);

  // no observers should exist
  ASSERT_EQ(0, oc_list_length(coap_get_observers()));
}

// TEST_F(TestDiscoveryWithServer, ObserveBatch)
// {
// TODO: add support for using secure endpoints for communication in tests
// }

#else /* !OC_SECURITY */

struct observeBatchData
{
  DiscoveryBatchData batch;
  int observe;
};

static void
onBatchObserve(oc_client_response_t *cr)
{
  oc::TestDevice::Terminate();
  OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
         oc::RepPool::GetJson(cr->payload, true).data());
  ASSERT_EQ(OC_STATUS_OK, cr->code);
  auto *obd = static_cast<observeBatchData *>(cr->user_data);
  obd->observe = cr->observe_option;
  obd->batch = parseBatchPayload(cr->payload);
#ifdef OC_HAS_FEATURE_ETAG
  TestDiscoveryWithServer::assertDiscoveryETag(cr->etag, cr->endpoint,
                                               cr->endpoint->device, true);
  if (cr->observe_option == OC_COAP_OPTION_OBSERVE_REGISTER ||
      cr->observe_option == OC_COAP_OPTION_OBSERVE_NOT_SET) {
    // we have a full payload and the response etag should be the highest etag
    // contained the payload
    TestDiscoveryWithServer::assertBatchETag(cr->etag, cr->endpoint->device,
                                             obd->batch);
  }
#endif /* OC_HAS_FEATURE_ETAG */
}

static void
updateResourceByPost(std::string_view uri, const oc_endpoint_t *endpoint,
                     const std::function<void()> &payloadFn)
{
  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(uri.data(), endpoint, nullptr, post_handler, LOW_QOS,
                           &invoked));
  payloadFn();
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

TEST_F(TestDiscoveryWithServer, ObserveBatchWithResourceUpdate)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  observeBatchData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onBatchObserve,
                            HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  // all resources should be in the first payload
  verifyBatchPayload(obd.batch, &ep);
  obd.observe = 0;
  obd.batch.clear();

  oc_device_info_t *info = oc_core_get_device_info(kDeviceID);
  ASSERT_NE(nullptr, info);
  std::string deviceName = oc_string(info->name);
  // updating the name by the /oc/con resource should trigger a batch observe
  // notification with /oc/con and /oic/d resources
  updateResourceByPost(OC_CON_URI, &ep, [deviceName]() {
    oc_rep_start_root_object();
    oc_rep_set_text_string_v1(root, n, deviceName.c_str(), deviceName.length());
    oc_rep_end_root_object();
  });

  int repeats = 0;
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_LE(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  std::vector<const oc_resource_t *> expected{};
  auto *device = oc_core_get_resource_by_index(OCF_D, kDeviceID);
  ASSERT_NE(nullptr, device);
  if ((device->properties & OC_DISCOVERABLE) != 0) {
    expected.emplace_back(device);
  }
  auto *con = oc_core_get_resource_by_index(OCF_CON, kDeviceID);
  ASSERT_NE(nullptr, con);
  if ((con->properties & OC_DISCOVERABLE) != 0) {
    expected.emplace_back(con);
  }
  verifyBatchPayload(obd.batch, expected);
  obd.observe = 0;
  obd.batch.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  // response should be a full batch GET payload with observe option not set
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  verifyBatchPayload(obd.batch, &ep);
}

TEST_F(TestDiscoveryWithServer, ObserveBatchWithResourceAdded)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  observeBatchData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onBatchObserve,
                            HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  // all resources should be in the first payload
  verifyBatchPayload(obd.batch, &ep);
  obd.observe = 0;
  obd.batch.clear();

  // adding a resource should trigger an observe notification
  oc::DynamicResourceHandler handlers{};
  dynamicResources[std::string(kDynamicURI3)] = { 2001 };
  handlers.onGet = onGetDynamicResource;
  handlers.onGetData = &dynamicResources[std::string(kDynamicURI3)];
  oc_resource_t *res = oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd(
      "Dynamic Resource 3", std::string(kDynamicURI3),
      { "oic.d.observable", "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
      handlers, OC_DISCOVERABLE | OC_OBSERVABLE),
    kDeviceID);
  ASSERT_NE(nullptr, res);

  int repeats = 0;
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_LE(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  obd.observe = 0;
  obd.batch.clear();

  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(res, true));
  repeats = 0;
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE + 1, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  obd.observe = 0;
  obd.batch.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (obd.observe == 0 && repeats < 50) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  // response should be a full batch GET payload with observe option not set
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  verifyBatchPayload(obd.batch, &ep);
}

TEST_F(TestDiscoveryWithServer, ObserveBatchWithEmptyPayload)
{
  // TODO: remove resource from payload -> make it undiscoverable in runtime and
  // see what happens
}

#endif /* OC_SECURITY */

#endif /* OC_RES_BATCH_SUPPORT */

#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */

#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */
