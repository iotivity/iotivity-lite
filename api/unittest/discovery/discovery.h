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

#pragma once

#include "oc_endpoint.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "tests/gtest/Resource.h"
#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ETAG
#include "messaging/coap/oc_coap.h"
#endif /* OC_HAS_FEATURE_ETAG */

#include <cstdint>
#include <string>
#include <gtest/gtest.h>
#include <vector>
#include <unordered_map>

namespace oc::discovery {

struct LinkData
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

using LinkDataMap = std::unordered_map<std::string, LinkData>;

struct BaselineData
{
  oc::BaselineData baseline;
  std::string sduuid;
  std::string sdname;
  LinkDataMap links;
};

LinkData ParseLink(const oc_rep_t *link);

LinkDataMap ParseLinks(const oc_rep_t *rep);

BaselineData ParseBaseline(const oc_rep_t *rep);

#ifdef OC_RES_BATCH_SUPPORT

struct BatchItem
{
  std::string deviceUUID;
  std::string href;
#ifdef OC_HAS_FEATURE_ETAG
  std::vector<uint8_t> etag;
#endif /* OC_HAS_FEATURE_ETAG */
};

using BatchData = std::unordered_map<std::string, BatchItem>;

BatchData ParseBatch(const oc_rep_t *payload);

#endif /* OC_RES_BATCH_SUPPORT */

#ifdef OC_HAS_FEATURE_ETAG

void AssertETag(oc_coap_etag_t etag, const oc_endpoint_t *endpoint,
                size_t device, bool is_batch = false);

#ifdef OC_RES_BATCH_SUPPORT

void AssertBatchETag(oc_coap_etag_t etag, size_t device, const BatchData &bd);

#endif /* OC_RES_BATCH_SUPPORT */

#endif /* OC_HAS_FEATURE_ETAG */

} // namespace oc::discovery

struct DynamicResourceData
{
  int power;
};

class TestDiscoveryWithServer : public ::testing::Test {
public:
  static void SetUpTestCase();
  static void TearDownTestCase();
  void TearDown() override;

  static void onGetDynamicResource(oc_request_t *request,
                                   oc_interface_mask_t interface,
                                   void *user_data);
  static void onGetEmptyDynamicResource(oc_request_t *request,
                                        oc_interface_mask_t interface,
                                        void *user_data);

  static void addDynamicResources();
#ifdef OC_COLLECTIONS
  static void addColletions();
#endif /* OC_COLLECTIONS */

  static void matchResourceLink(const oc_resource_t *resource,
                                const oc::discovery::LinkData &link);
  static void verifyLinks(const oc::discovery::LinkDataMap &links);

#ifdef OC_RES_BATCH_SUPPORT

  struct batch_resources_t
  {
    const oc_endpoint_t *endpoint;
    std::vector<const oc_resource_t *> resources;
  };

  static batch_resources_t getBatchResources(const oc_endpoint_t *endpoint);

#ifndef OC_SECURITY
  static void verifyBatchPayload(
    const oc::discovery::BatchData &dbd,
    const std::vector<const oc_resource_t *> &expected);
  static void verifyBatchPayload(const oc::discovery::BatchData &dbd,
                                 const oc_endpoint_t *endpoint);
#endif /* !OC_SECURITY */

#endif /* OC_RES_BATCH_SUPPORT */

  static std::unordered_map<std::string, DynamicResourceData> dynamicResources;
};

constexpr size_t kDeviceID{ 0 };

constexpr std::string_view kDynamicURI1 = "/dyn/discoverable";
constexpr std::string_view kDynamicURI2 = "/dyn/undiscoverable";
constexpr std::string_view kDynamicURI3 = "/dyn/empty";

#ifdef OC_COLLECTIONS

constexpr std::string_view kCollectionURI = "/col";
constexpr std::string_view kColDynamicURI1 = "/col/discoverable";
constexpr std::string_view kColDynamicURI2 = "/col/undiscoverable";
constexpr std::string_view kColDynamicURI3 = "/col/empty";

#endif /* OC_COLLECTIONS */
