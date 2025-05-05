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

#include "discovery.h"

#include "api/oc_discovery_internal.h"
#include "api/oc_resource_internal.h"
#include "messaging/coap/observe_internal.h"
#include "oc_api.h"
#include "oc_buffer_settings.h"
#include "oc_core_res.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Utility.h"

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_etag_internal.h"
#endif /* OC_HAS_FEATURE_ETAG */

#ifdef OC_COLLECTIONS
#include "tests/gtest/Collection.h"
#endif /* OC_COLLECTIONS */

#include "gtest/gtest.h"

namespace oc::discovery {

LinkData
ParseLink(const oc_rep_t *link)
{
  LinkData linkData{};

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

LinkDataMap
ParseLinks(const oc_rep_t *rep)
{
  LinkDataMap links{};
  for (; rep != nullptr; rep = rep->next) {
    auto link = ParseLink(rep->value.object);
    links[link.href] = link;
  }
  return links;
}

BaselineData
ParseBaseline(const oc_rep_t *rep)
{
  const oc_rep_t *obj = rep->value.object;
  BaselineData data{};
  if (auto bl_opt = ParseBaselineData(obj)) {
    data.baseline = *bl_opt;
  }

  char *str;
  size_t str_len;
  // sduuid: string
  if (oc_rep_get_string(obj, OCF_RES_PROP_SDUUID, &str, &str_len)) {
    data.sduuid = std::string(str, str_len);
  }

  // sdname: string
  if (oc_rep_get_string(obj, OCF_RES_PROP_SDNAME, &str, &str_len)) {
    data.sdname = std::string(str, str_len);
  }

  // links
  if (oc_rep_t *links = nullptr;
      oc_rep_get_object_array(obj, "links", &links)) {
    data.links = ParseLinks(links);
  }
  return data;
}

#ifdef OC_RES_BATCH_SUPPORT

BatchData
ParseBatch(const oc_rep_t *payload)
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

  BatchData data{};
  for (const oc_rep_t *rep = payload; rep != nullptr; rep = rep->next) {
    const oc_rep_t *obj = rep->value.object;
    BatchItem bi{};
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

#endif /* OC_RES_BATCH_SUPPORT */

#ifdef OC_HAS_FEATURE_ETAG

void
AssertETag(oc_coap_etag_t etag, const oc_endpoint_t *endpoint, size_t device,
           bool is_batch)
{
#ifdef OC_RES_BATCH_SUPPORT
  if (is_batch) {
    oc::AssertETag(etag, oc_discovery_get_batch_etag(endpoint, device));
    return;
  }
#else  /* !OC_RES_BATCH_SUPPORT */
  (void)endpoint;
  (void)is_batch;
#endif /* OC_RES_BATCH_SUPPORT */
  const oc_resource_t *discovery =
    oc_core_get_resource_by_index(OCF_RES, device);
  oc::AssertResourceETag(etag, discovery);
}

#ifdef OC_RES_BATCH_SUPPORT

void
AssertBatchETag(oc_coap_etag_t etag, size_t device, const BatchData &bd)
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
  oc::AssertETag(etag, max_etag);
}

#endif /* OC_RES_BATCH_SUPPORT */

#endif /* OC_HAS_FEATURE_ETAG */

} // namespace oc::discovery

namespace {

const int g_latency{ oc_core_get_latency() };

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
const long g_max_app_data_size{ oc_get_max_app_data_size() };
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */

}

void
TestDiscoveryWithServer::SetUpTestCase()
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
};

void
TestDiscoveryWithServer::TearDownTestCase()
{
  oc::TestDevice::StopServer();

  // restore defaults
  oc_core_set_latency(g_latency);
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
  oc_set_max_app_data_size(g_max_app_data_size);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */
}

void
TestDiscoveryWithServer::SetUp()
{
  coap_observe_counter_reset();
}

void
TestDiscoveryWithServer::TearDown()
{
  oc::TestDevice::Reset();
}

std::unordered_map<std::string, DynamicResourceData>
  TestDiscoveryWithServer::dynamicResources{};

void
TestDiscoveryWithServer::onGetDynamicResource(oc_request_t *request,
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
TestDiscoveryWithServer::onGetEmptyDynamicResource(oc_request_t *request,
                                                   oc_interface_mask_t, void *)
{
  oc_rep_start_root_object();
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

void
TestDiscoveryWithServer::onGetIgnoredDynamicResource(oc_request_t *request,
                                                     oc_interface_mask_t,
                                                     void *)
{
  oc_send_response(request, OC_IGNORE);
}

void
TestDiscoveryWithServer::addDynamicResources()
{
  oc::DynamicResourceHandler handlers1{};
  dynamicResources[kDynamicURI1] = { 42 };
  handlers1.onGet = onGetDynamicResource;
  handlers1.onGetData = &dynamicResources[kDynamicURI1];

  oc::DynamicResourceHandler handlers2{};
  dynamicResources[kDynamicURI2] = { 1337 };
  handlers2.onGet = onGetDynamicResource;
  handlers2.onGetData = &dynamicResources[kDynamicURI2];

  oc::DynamicResourceHandler handlers3{};
  handlers3.onGet = onGetEmptyDynamicResource;

  oc::DynamicResourceHandler handlers4{};
  handlers4.onGet = onGetIgnoredDynamicResource;

  std::vector<oc::DynamicResourceToAdd> dynResources = {
    oc::makeDynamicResourceToAdd("Dynamic Resource 1", kDynamicURI1,
                                 { "oic.d.discoverable", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, handlers1),
    oc::makeDynamicResourceToAdd("Dynamic Resource 2", kDynamicURI2,
                                 { "oic.d.undiscoverable", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, handlers2, 0),
    oc::makeDynamicResourceToAdd(
      "Dynamic Resource 3", kDynamicURI3, { "oic.d.observable", "oic.d.test" },
      { OC_IF_BASELINE, OC_IF_R }, handlers3, OC_DISCOVERABLE | OC_OBSERVABLE),
    oc::makeDynamicResourceToAdd("Dynamic Resource 4", kDynamicURIIgnored,
                                 { "oic.d.ignored", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, handlers4,
                                 OC_DISCOVERABLE | OC_OBSERVABLE),
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
  const std::string powerSwitchRT = "oic.d.power";

  auto col = oc::NewCollection("col", kCollectionURI, kDeviceID, "oic.wk.col");
  ASSERT_NE(nullptr, col);
  oc_resource_set_discoverable(&col->res, true);
  oc_collection_add_supported_rt(&col->res, powerSwitchRT.c_str());
  oc_collection_add_mandatory_rt(&col->res, powerSwitchRT.c_str());
  ASSERT_TRUE(oc_add_collection_v1(&col->res));

  oc::DynamicResourceHandler handlers1{};
  dynamicResources[kColDynamicURI1] = { 404 };
  handlers1.onGet = onGetDynamicResource;
  handlers1.onGetData = &dynamicResources[kColDynamicURI1];
  auto dr1 = oc::makeDynamicResourceToAdd(
    "Collection Resource 1", kColDynamicURI1, { powerSwitchRT, "oic.d.test" },
    { OC_IF_BASELINE, OC_IF_R }, handlers1);
  oc_resource_t *res1 = oc::TestDevice::AddDynamicResource(dr1, kDeviceID);
  ASSERT_NE(nullptr, res1);
  oc_link_t *link1 = oc_new_link(res1);
  ASSERT_NE(link1, nullptr);
  oc_collection_add_link(&col->res, link1);

  oc::DynamicResourceHandler handlers2{};
  dynamicResources[kColDynamicURI2] = { 1 };
  handlers2.onGet = onGetDynamicResource;
  handlers2.onGetData = &dynamicResources[kColDynamicURI2];
  auto dr2 = oc::makeDynamicResourceToAdd(
    "Collection Resource 2", kColDynamicURI2, { powerSwitchRT, "oic.d.test" },
    { OC_IF_BASELINE, OC_IF_R }, handlers2, 0);
  oc_resource_t *res2 = oc::TestDevice::AddDynamicResource(dr2, kDeviceID);
  ASSERT_NE(nullptr, res2);
  oc_link_t *link2 = oc_new_link(res2);
  ASSERT_NE(link2, nullptr);
  oc_collection_add_link(&col->res, link2);

  oc::DynamicResourceHandler handlers3{};
  handlers3.onGet = onGetEmptyDynamicResource;
  auto dr3 = oc::makeDynamicResourceToAdd(
    "Collection Resource 3", kColDynamicURI3, { powerSwitchRT, "oic.d.test" },
    { OC_IF_BASELINE, OC_IF_R }, handlers3, OC_DISCOVERABLE | OC_OBSERVABLE);
  oc_resource_t *res3 = oc::TestDevice::AddDynamicResource(dr3, kDeviceID);
  ASSERT_NE(nullptr, res3);
  oc_link_t *link3 = oc_new_link(res3);
  ASSERT_NE(link3, nullptr);
  oc_collection_add_link(&col->res, link3);

  col.release();
}
#endif /* OC_COLLECTIONS */

void
TestDiscoveryWithServer::matchResourceLink(const oc_resource_t *resource,
                                           const oc::discovery::LinkData &link)
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

void
TestDiscoveryWithServer::verifyLinks(const oc::discovery::LinkDataMap &links)
{
#ifdef OC_SERVER
  auto verifyUndiscoverable = [&links](const std::string &uri) {
    oc_resource_t *res =
      oc_ri_get_app_resource_by_uri(uri.c_str(), uri.length(), kDeviceID);
    ASSERT_NE(nullptr, res);
    ASSERT_EQ(0, res->properties & OC_DISCOVERABLE);
    EXPECT_EQ(std::end(links), links.find(uri));
  };

  auto verifyDiscoverable = [&links](const std::string &uri) {
    oc_resource_t *res =
      oc_ri_get_app_resource_by_uri(uri.c_str(), uri.length(), kDeviceID);
    ASSERT_NE(nullptr, res);
    ASSERT_NE(0, res->properties & OC_DISCOVERABLE);
    const auto &linkData = links.find(uri);
    ASSERT_NE(std::end(links), linkData);
    matchResourceLink(res, linkData->second);
  };

  verifyDiscoverable(kDynamicURI1);
  verifyUndiscoverable(kDynamicURI2);
  verifyDiscoverable(kDynamicURI3);

#ifdef OC_COLLECTIONS
  oc_collection_t *col = oc_get_collection_by_uri(
    kCollectionURI.c_str(), kCollectionURI.length(), kDeviceID);
  ASSERT_NE(nullptr, col);
  const auto &colLink = links.find(kCollectionURI);
  ASSERT_NE(std::end(links), colLink);
  matchResourceLink(&col->res, colLink->second);

  for (const oc_link_t *link = oc_collection_get_links(&col->res);
       link != nullptr; link = link->next) {
    const auto &linkData = links.find(oc_string(link->resource->uri));
    if ((link->resource->properties & OC_DISCOVERABLE) == 0) {
      EXPECT_EQ(std::end(links), links.find(kDynamicURI2));
      continue;
    }
    ASSERT_NE(std::end(links), linkData);
    matchResourceLink(link->resource, linkData->second);
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
}

#ifdef OC_RES_BATCH_SUPPORT

TestDiscoveryWithServer::batch_resources_t
TestDiscoveryWithServer::getBatchResources(const oc_endpoint_t *endpoint)
{
  batch_resources_t batch{};
  batch.endpoint = endpoint;

  oc_resources_iterate(
    kDeviceID, true, true, true, true,
    [](oc_resource_t *resource, void *data) {
      if (kDynamicURIIgnored == oc_string(resource->uri)) {
        // resource that returns OC_IGNORE shouldn't be in the batch payload
        return true;
      }
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
verifyBatchPayloadResource(const oc::discovery::BatchData &dbd,
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
  oc::AssertResourceETag(etag, resource);
#endif /* OC_HAS_FEATURE_ETAG */
}

void
TestDiscoveryWithServer::verifyBatchPayload(
  const oc::discovery::BatchData &dbd,
  const std::vector<const oc_resource_t *> &expected)
{
  ASSERT_EQ(expected.size(), dbd.size());
  for (const auto *resource : expected) {
    verifyBatchPayloadResource(dbd, resource);
  }
}

void
TestDiscoveryWithServer::verifyBatchPayload(const oc::discovery::BatchData &dbd,
                                            const oc_endpoint_t *endpoint)
{
  auto br = getBatchResources(endpoint);
  verifyBatchPayload(dbd, br.resources);
}

#endif /* !OC_SECURITY */

#endif /* OC_RES_BATCH_SUPPORT */
