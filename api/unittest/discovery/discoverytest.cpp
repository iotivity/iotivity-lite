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

#include "api/oc_client_api_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_etag_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_base64.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Collection.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
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

class TestDiscovery : public testing::Test {};

TEST_F(TestDiscovery, IsDiscoveryURI_F)
{
  EXPECT_FALSE(oc_is_discovery_resource_uri(OC_STRING_VIEW_NULL));
  EXPECT_FALSE(oc_is_discovery_resource_uri(OC_STRING_VIEW("")));
}

TEST_F(TestDiscovery, IsDiscoveryURI_P)
{
  std::string uri = OCF_RES_URI;
  EXPECT_TRUE(
    oc_is_discovery_resource_uri(oc_string_view(uri.c_str(), uri.length())));
  uri = uri.substr(1, uri.length() - 1);
  EXPECT_TRUE(
    oc_is_discovery_resource_uri(oc_string_view(uri.c_str(), uri.length())));
}

} // namespace

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
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
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
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
#ifdef OC_HAS_FEATURE_ETAG
    oc::discovery::AssertETag(data->etag, data->endpoint,
                              data->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
    *static_cast<oc::discovery::LinkDataMap *>(data->user_data) =
      oc::discovery::ParseLinks(data->payload);
  };

  oc::discovery::LinkDataMap links{};
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_RES_URI, &ep, nullptr, timeout.count(),
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
    oc::discovery::AssertETag(data->etag, data->endpoint,
                              data->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
    *static_cast<oc::discovery::BaselineData *>(data->user_data) =
      oc::discovery::ParseBaseline(data->payload);
  };

  oc::discovery::BaselineData baseline{};
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
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
    auto batch = static_cast<oc::discovery::BatchData *>(data->user_data);
    *batch = oc::discovery::ParseBatch(data->payload);
#ifdef OC_SECURITY
    // need secure endpoint to get batch response if OC_SECURITY is enabled
    ASSERT_EQ(OC_STATUS_BAD_REQUEST, data->code);
#else /* !OC_SECURITY */
    ASSERT_EQ(OC_STATUS_OK, data->code);
#ifdef OC_HAS_FEATURE_ETAG
    oc::discovery::AssertETag(data->etag, data->endpoint,
                              data->endpoint->device, true);
    // the response etag should be the highest etag contained the payload
    oc::discovery::AssertBatchETag(data->etag, data->endpoint->device, *batch);
#endif /* OC_HAS_FEATURE_ETAG */
#endif /* OC_SECURITY */
  };

  oc::discovery::BatchData data{};
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
    oc::discovery::BatchData bd;
  };

  auto getHandler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
    auto *dbr = static_cast<DiscoveryBatchResponse *>(data->user_data);
    dbr->code = data->code;
    dbr->bd = oc::discovery::ParseBatch(data->payload);
#ifdef OC_SECURITY
    // need secure endpoint to get batch response if OC_SECURITY is enabled
    ASSERT_EQ(OC_STATUS_BAD_REQUEST, data->code);
#else  /* !OC_SECURITY */
    ASSERT_TRUE(OC_STATUS_OK == data->code ||
                OC_STATUS_NOT_MODIFIED == data->code);
    oc::discovery::AssertETag(data->etag, data->endpoint,
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
    TestDiscoveryWithServer::verifyBatchPayload(dbr.bd, expected);
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

#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */
