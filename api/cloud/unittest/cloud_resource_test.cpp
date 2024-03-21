/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_core_res.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_macros_internal.h"

#include <cstddef>
#include <gtest/gtest.h>
#include <string>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };

struct CloudEndpointData
{
  std::string uri;
  std::string id;
};

struct CloudResourceData
{
  std::string apn;
  std::string cis;
  std::vector<CloudEndpointData> servers;
  oc_uuid_t sid;
  int clec;
  std::string cps;

  static std::vector<CloudEndpointData> decodeArray(const oc_rep_t *servers)
  {
    std::vector<CloudEndpointData> result{};
    for (const oc_rep_t *server = servers; server != nullptr;
         server = server->next) {
      const oc_rep_t *rep = oc_rep_get_by_type_and_key(
        server->value.object, OC_REP_STRING, "uri", OC_CHAR_ARRAY_LEN("uri"));
      if (rep == nullptr) {
        continue;
      }
      std::string uri = oc_string(rep->value.string);

      rep = oc_rep_get_by_type_and_key(server->value.object, OC_REP_STRING,
                                       "id", OC_CHAR_ARRAY_LEN("id"));
      if (rep == nullptr) {
        continue;
      }
      std::string id = oc_string(rep->value.string);

      result.emplace_back(CloudEndpointData{ uri, id });
    }

    return result;
  }

  static oc_uuid_t decodeSid(const oc_string_t &sid)
  {
    oc_uuid_t result{};
    oc_str_to_uuid(oc_string(sid), &result);
    return result;
  }

  static CloudResourceData decode(const oc_rep_t *rep)
  {
    CloudResourceData crd{};
    for (; rep != nullptr; rep = rep->next) {
      if (oc_rep_is_property_with_type(
            rep, OC_REP_STRING, OCF_COAPCLOUDCONF_PROP_AUTHPROVIDER,
            OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_PROP_AUTHPROVIDER))) {
        crd.apn = std::string(oc_string(rep->value.string));
        continue;
      }
      if (oc_rep_is_property_with_type(
            rep, OC_REP_STRING, OCF_COAPCLOUDCONF_PROP_CISERVER,
            OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_PROP_CISERVER))) {
        crd.cis = std::string(oc_string(rep->value.string));
        continue;
      }
      if (oc_rep_is_property_with_type(
            rep, OC_REP_OBJECT_ARRAY, OCF_COAPCLOUDCONF_PROP_CISERVERS,
            OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_PROP_CISERVERS))) {
        crd.servers = decodeArray(rep->value.object_array);
        continue;
      }
      if (oc_rep_is_property_with_type(
            rep, OC_REP_STRING, OCF_COAPCLOUDCONF_PROP_SERVERID,
            OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_PROP_SERVERID))) {
        crd.sid = decodeSid(rep->value.string);
        continue;
      }
      if (oc_rep_is_property_with_type(
            rep, OC_REP_INT, OCF_COAPCLOUDCONF_PROP_LASTERRORCODE,
            OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_PROP_LASTERRORCODE))) {
        crd.clec = static_cast<decltype(crd.clec)>(rep->value.integer);
        continue;
      }
      if (oc_rep_is_property_with_type(
            rep, OC_REP_STRING, OCF_COAPCLOUDCONF_PROP_PROVISIONINGSTATUS,
            OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_PROP_PROVISIONINGSTATUS))) {
        crd.cps = std::string(oc_string(rep->value.string));
        continue;
      }
    }
    return crd;
  }
};

class TestCloudResource : public testing::Test {};

TEST_F(TestCloudResource, CpsToString)
{
  EXPECT_STREQ(OC_CPS_UNINITIALIZED_STR,
               oc_cps_to_string(OC_CPS_UNINITIALIZED).data);
  EXPECT_STREQ(OC_CPS_READYTOREGISTER_STR,
               oc_cps_to_string(OC_CPS_READYTOREGISTER).data);
  EXPECT_STREQ(OC_CPS_REGISTERING_STR,
               oc_cps_to_string(OC_CPS_REGISTERING).data);
  EXPECT_STREQ(OC_CPS_REGISTERED_STR, oc_cps_to_string(OC_CPS_REGISTERED).data);
  EXPECT_STREQ(OC_CPS_FAILED_STR, oc_cps_to_string(OC_CPS_FAILED).data);
  EXPECT_STREQ(OC_CPS_DEREGISTERING_STR,
               oc_cps_to_string(OC_CPS_DEREGISTERING).data);

  EXPECT_EQ(nullptr, oc_cps_to_string(static_cast<oc_cps_t>(-1)).data);
}

class TestCloudResourceWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_COAPCLOUDCONF, kDeviceID, false,
                                     OC_PERM_RETRIEVE | OC_PERM_UPDATE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void TearDown() override { oc::TestDevice::Reset(); }
};

TEST_F(TestCloudResourceWithServer, GetResourceByIndex_F)
{
  EXPECT_EQ(nullptr, oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, /*device*/
                                                   SIZE_MAX));
}

TEST_F(TestCloudResourceWithServer, GetResourceByIndex)
{
  EXPECT_NE(nullptr,
            oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, kDeviceID));
}

TEST_F(TestCloudResourceWithServer, GetResourceByURI_F)
{
  EXPECT_EQ(nullptr,
            oc_core_get_resource_by_uri_v1(
              OCF_COAPCLOUDCONF_URI, OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_URI),
              /*device*/ SIZE_MAX));
}

TEST_F(TestCloudResourceWithServer, GetResourceByURI)
{
  oc_resource_t *res = oc_core_get_resource_by_uri_v1(
    OCF_COAPCLOUDCONF_URI, OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_URI), kDeviceID);
  EXPECT_NE(nullptr, res);

  EXPECT_STREQ(OCF_COAPCLOUDCONF_URI, oc_string(res->uri));
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

template<oc_status_t CODE = OC_STATUS_OK>
static void
getRequest(CloudResourceData *crd = nullptr)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  struct get_handler_data
  {
    bool invoked;
    CloudResourceData *crd;
  };
  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
    auto ghd = static_cast<get_handler_data *>(data->user_data);
    ghd->invoked = true;
    ASSERT_EQ(CODE, data->code);
    if (data->code == OC_STATUS_OK && ghd->crd != nullptr) {
      *ghd->crd = CloudResourceData::decode(data->payload);
    }
  };

  auto timeout = 1s;
  get_handler_data ghd{ false, crd };
  ASSERT_TRUE(oc_do_get_with_timeout(OCF_COAPCLOUDCONF_URI, &ep, nullptr,
                                     timeout.count(), get_handler, LOW_QOS,
                                     &ghd));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(ghd.invoked);
}

TEST_F(TestCloudResourceWithServer, GetRequest)
{
  CloudResourceData crd{};
  getRequest(&crd);

  EXPECT_TRUE(crd.apn.empty());
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_CIS, crd.cis.c_str());
  EXPECT_TRUE(oc_uuid_is_equal(OCF_COAPCLOUDCONF_DEFAULT_SID, crd.sid));
  EXPECT_EQ(OC_CPS_UNINITIALIZED_STR, crd.cps);
  EXPECT_EQ(0, crd.clec);
}

TEST_F(TestCloudResourceWithServer, GetRequest_NoCloudServers)
{
  // remove default
  auto *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  CloudResourceData crd{};
  getRequest(&crd);

  EXPECT_TRUE(crd.apn.empty());
  EXPECT_TRUE(crd.cis.empty());
  EXPECT_TRUE(oc_uuid_is_equal(OCF_COAPCLOUDCONF_DEFAULT_SID, crd.sid));
  EXPECT_EQ(OC_CPS_UNINITIALIZED_STR, crd.cps);
  EXPECT_EQ(0, crd.clec);

  // restore default store
  oc_cloud_store_initialize(&ctx->store, nullptr, nullptr);
}

template<typename Fn, oc_status_t CODE = OC_STATUS_BAD_REQUEST>
static void
postRequest(const Fn &encodeFn, CloudResourceData *crd = nullptr)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  struct post_handler_data
  {
    bool invoked;
    CloudResourceData *crd;
  };
  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s",
           oc::RepPool::GetJson(data->payload, true).data());
    auto phd = static_cast<post_handler_data *>(data->user_data);
    phd->invoked = true;
    ASSERT_EQ(CODE, data->code);
    if (data->code == OC_STATUS_CHANGED && phd->crd != nullptr) {
      *phd->crd = CloudResourceData::decode(data->payload);
    }
  };

  post_handler_data phd{ false, crd };
  ASSERT_TRUE(oc_init_post(OCF_COAPCLOUDCONF_URI, &ep, nullptr, post_handler,
                           LOW_QOS, &phd));

  if (encodeFn != nullptr) {
    encodeFn();
  }

  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(phd.invoked);
}

TEST_F(TestCloudResourceWithServer, PostRequest_FailMissingCis)
{
  auto encode = []() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, at, "access_token");
    oc_rep_set_text_string(root, sid, "00000000-0000-0000-0000-000000000000");
    oc_rep_end_root_object();
  };
  postRequest(encode);
}

TEST_F(TestCloudResourceWithServer, PostRequest_FailMissingAccessToken)
{
  auto encode = []() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cis, "coap://mock.plgd.dev");
    oc_rep_set_text_string(root, sid, "00000000-0000-0000-0000-000000000000");
    oc_rep_end_root_object();
  };
  postRequest(encode);
}

/// for sid and at properties, missing and empty values are equivalent
TEST_F(TestCloudResourceWithServer, PostRequest_FailMissingSid)
{
  auto encode = []() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cis, "coap://mock.plgd.dev");
    oc_rep_set_text_string(root, at, "access_token");
    oc_rep_set_text_string(root, sid, "");
    oc_rep_end_root_object();
  };
  postRequest(encode);
}

TEST_F(TestCloudResourceWithServer, PostRequest_InvalidSid)
{
  auto encode = []() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cis, "coap://mock.plgd.dev");
    oc_rep_set_text_string(root, at, "access_token");
    oc_rep_set_text_string(root, sid, "invalid"); // not a valid UUID
    oc_rep_end_root_object();
  };
  postRequest(encode);
}

TEST_F(TestCloudResourceWithServer, PostRequest_FailSetCps)
{
  auto encode = []() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cps, OC_CPS_REGISTERED_STR);
    oc_rep_end_root_object();
  };
  postRequest(encode);
}

TEST_F(TestCloudResourceWithServer, PostRequest_FailInvalidState)
{
  // in registering or registered state, the only allowed change is to request
  // deregistration by sending a POST request with the cis property set to an
  // empty string OC_CPS_REGISTERING OC_CPS_REGISTERED
  auto *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  cloud_set_cps(ctx, OC_CPS_REGISTERING);
  postRequest([]() {
    // no-op
  });

  cloud_set_cps(ctx, OC_CPS_REGISTERED);
  postRequest([]() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cis, "coap://mock.plgd.dev");
    oc_rep_end_root_object();
  });

  cloud_context_clear(ctx);
}

TEST_F(TestCloudResourceWithServer, PostRequest_MultipleServers)
{
  auto encode = []() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cis, "coap://mock.plgd.dev");
    oc_rep_set_text_string(root, at, "access_token");
    oc_rep_set_text_string(root, sid, "00000000-0000-0000-0000-000000000000");
    std::string_view key{ "x.org.iotivity.servers" };
    oc_rep_encode_text_string(oc_rep_object(root), key.data(), key.length());
    oc_rep_begin_array(oc_rep_object(root), servers);
    oc_rep_object_array_begin_item(servers);
    oc_rep_set_text_string(servers, uri, "coaps://plgd.dev");
    oc_rep_set_text_string(servers, id, "00000000-0000-0000-0000-000000000000");
    oc_rep_object_array_end_item(servers);
    oc_rep_end_array(oc_rep_object(root), servers);
    oc_rep_end_root_object();
  };
  postRequest<decltype(encode), OC_STATUS_CHANGED>(encode);

  const auto *addresses = &oc_cloud_get_context(kDeviceID)->store.ci_servers;
  ASSERT_EQ(2, oc_endpoint_addresses_size(addresses));
  EXPECT_TRUE(oc_endpoint_addresses_contains(
    addresses, OC_STRING_VIEW("coap://mock.plgd.dev")));
  EXPECT_TRUE(oc_endpoint_addresses_contains(
    addresses, OC_STRING_VIEW("coaps://plgd.dev")));
  // the server from the sid property should be selected
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    addresses, OC_STRING_VIEW("coap://mock.plgd.dev")));
}

TEST_F(TestCloudResourceWithServer, PostRequest_Deregister)
{
  auto *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  cloud_set_cps(ctx, OC_CPS_REGISTERED);

  auto encode = []() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cis, "");
    oc_rep_end_root_object();
  };
  CloudResourceData crd{};
  postRequest<decltype(encode), OC_STATUS_CHANGED>(encode, &crd);

  // resource should be reset to default values
  EXPECT_TRUE(crd.apn.empty());
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_CIS, crd.cis.c_str());
  EXPECT_TRUE(oc_uuid_is_equal(OCF_COAPCLOUDCONF_DEFAULT_SID, crd.sid));
  EXPECT_EQ(OC_CPS_UNINITIALIZED_STR, crd.cps);
  EXPECT_EQ(0, crd.clec);
}

TEST_F(TestCloudResourceWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#if defined(OC_SECURITY) && !defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_COAPCLOUDCONF_URI, nullptr, code);
}

TEST_F(TestCloudResourceWithServer, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#ifdef OC_SECURITY
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_COAPCLOUDCONF_URI, nullptr,
                             code);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
