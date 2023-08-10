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

#include "api/oc_discovery_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
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
#include "security/oc_sdi_internal.h"
#endif /* OC_SECURITY */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std::chrono_literals;

namespace {
constexpr size_t kDeviceID{ 0 };

constexpr std::string_view kDynamicURI1 = "/dyn/discoverable";
constexpr std::string_view kDynamicURI2 = "/dyn/undiscoverable";

constexpr std::string_view kCollectionURI = "/col";
constexpr std::string_view kDynamicURI3 = "/col/discoverable";
constexpr std::string_view kDynamicURI4 = "/col/undiscoverable";

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

DiscoveryLinkData
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

DiscoveryLinkDataMap
parseLinks(const oc_rep_t *rep)
{
  DiscoveryLinkDataMap links{};
  for (; rep != nullptr; rep = rep->next) {
    auto link = parseLink(rep->value.object);
    links[link.href] = link;
  }
  return links;
}

void
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

struct DiscoveryBaselineData
{
  oc::BaselineData baseline;
  std::string sduuid;
  std::string sdname;
  DiscoveryLinkDataMap links;
};

DiscoveryBaselineData
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

struct DiscoveryBatchItem
{
  std::string deviceUUID;
  std::string href;
#ifdef OC_HAS_FEATURE_ETAG
  std::vector<uint8_t> etag;
#endif /* OC_HAS_FEATURE_ETAG */
};

using DiscoveryBatchData = std::unordered_map<std::string, DiscoveryBatchItem>;

DiscoveryBatchData
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

  static void verifyLinks(const DiscoveryLinkDataMap &links);

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
    oc::makeDynamicResourceToAdd(
      "Dynamic Resource 2", std::string(kDynamicURI2),
      { "oic.d.undiscoverable", "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
      handlers2, true, false),
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

  oc::DynamicResourceHandler handlers3{};
  dynamicResources[std::string(kDynamicURI3)] = { 404 };
  handlers3.onGet = onGetDynamicResource;
  handlers3.onGetData = &dynamicResources[std::string(kDynamicURI3)];

  auto dr3 = oc::makeDynamicResourceToAdd(
    "Dynamic Resource 3", std::string(kDynamicURI3),
    { std::string(powerSwitchRT), "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
    handlers3);
  oc_resource_t *res3 = oc::TestDevice::AddDynamicResource(dr3, kDeviceID);
  ASSERT_NE(nullptr, res3);
  oc_link_t *link1 = oc_new_link(res3);
  ASSERT_NE(link1, nullptr);
  oc_collection_add_link(&col->res, link1);

  oc::DynamicResourceHandler handlers4{};
  dynamicResources[std::string(kDynamicURI4)] = { 1 };
  handlers4.onGet = onGetDynamicResource;
  handlers4.onGetData = &dynamicResources[std::string(kDynamicURI4)];

  auto dr4 = oc::makeDynamicResourceToAdd(
    "Dynamic Resource 4", std::string(kDynamicURI4),
    { std::string(powerSwitchRT), "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
    handlers4, true, false);
  oc_resource_t *res4 = oc::TestDevice::AddDynamicResource(dr4, kDeviceID);
  ASSERT_NE(nullptr, res4);
  oc_link_t *link2 = oc_new_link(res4);
  ASSERT_NE(link2, nullptr);
  oc_collection_add_link(&col->res, link2);

  col.release();
}

#endif /* OC_COLLECTIONS */

#endif // OC_DYNAMIC_ALLOCATION

void
TestDiscoveryWithServer::verifyLinks(const DiscoveryLinkDataMap &links)
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
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(CODE, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, ep, query.c_str(),
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
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
#ifdef OC_HAS_FEATURE_ETAG
    assertDiscoveryETag(data->etag, data->endpoint, data->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *links = static_cast<DiscoveryLinkDataMap *>(data->user_data);
    *links = parseLinks(data->payload);
  };

  DiscoveryLinkDataMap links{};
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, ep, nullptr, timeout.count(),
                                     get_handler, HIGH_QOS, &links));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_FALSE(links.empty());

  verifyLinks(links);
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
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

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
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, ep, "if=" OC_IF_BASELINE_STR,
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
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

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
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, ep, "if=" OC_IF_B_STR,
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &data));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

#ifdef OC_SECURITY
  EXPECT_TRUE(data.empty());
#else /* !OC_SECURITY */
  EXPECT_FALSE(data.empty());

  auto verifyDiscoverable = [&data](const oc_resource_t *resource) {
    ASSERT_NE(nullptr, resource);
    ASSERT_NE(0, resource->properties & OC_DISCOVERABLE);
    const auto &it = data.find(std::string(oc_string(resource->uri)));
    ASSERT_NE(std::end(data), it);
#ifdef OC_HAS_FEATURE_ETAG
    oc_coap_etag_t etag{};
    std::copy(it->second.etag.begin(), it->second.etag.end(), etag.value);
    etag.length = static_cast<uint8_t>(it->second.etag.size());
    assertResourceETag(etag, resource);
#endif /* OC_HAS_FEATURE_ETAG */
  };

  auto verifyUndiscoverable = [&data](const oc_resource_t *resource) {
    ASSERT_NE(nullptr, resource);
    ASSERT_EQ(0, resource->properties & OC_DISCOVERABLE);
    EXPECT_EQ(std::end(data), data.find(std::string(oc_string(resource->uri))));
  };

  verifyDiscoverable(oc_ri_get_app_resource_by_uri(
    kDynamicURI1.data(), kDynamicURI1.length(), kDeviceID));
  verifyUndiscoverable(oc_ri_get_app_resource_by_uri(
    kDynamicURI2.data(), kDynamicURI2.length(), kDeviceID));

#ifdef OC_COLLECTIONS
  oc_collection_t *col = oc_get_collection_by_uri(
    kCollectionURI.data(), kCollectionURI.length(), kDeviceID);
  ASSERT_NE(nullptr, col);
  verifyDiscoverable(&col->res);

  for (const oc_link_t *link = oc_collection_get_links(&col->res);
       link != nullptr; link = link->next) {
    if ((link->resource->properties & OC_DISCOVERABLE) == 0) {
      verifyUndiscoverable(link->resource);
      continue;
    }
    verifyDiscoverable(link->resource);
  }

#endif /* OC_COLLECTIONS */
#endif /* OC_SECURITY */
}

#endif /* OC_RES_BATCH_SUPPORT */

#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */
