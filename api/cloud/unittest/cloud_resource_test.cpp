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

#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_core_res.h"
#include "oc_ri.h"
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

struct CloudResourceData
{
  std::string apn;
  std::string cis;
  std::string sid;
  int clec;
  std::string cps;

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
            rep, OC_REP_STRING, OCF_COAPCLOUDCONF_PROP_SERVERID,
            OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_PROP_SERVERID))) {
        crd.sid = std::string(oc_string(rep->value.string));
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

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }

  void SetUp() override
  {
    // TODO: rm
    oc_log_set_level(OC_LOG_LEVEL_DEBUG);
  }

  void TearDown() override
  {
    // TODO: rm
    oc_log_set_level(OC_LOG_LEVEL_INFO);
  }
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

TEST_F(TestCloudResourceWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<CloudResourceData *>(data->user_data) =
      CloudResourceData::decode(data->payload);
  };

  auto timeout = 1s;
  CloudResourceData crd{};
  ASSERT_TRUE(oc_do_get_with_timeout(OCF_COAPCLOUDCONF_URI, &ep, nullptr,
                                     timeout.count(), get_handler, LOW_QOS,
                                     &crd));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(crd.apn.empty());
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_CIS, crd.cis.c_str());
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_SID, crd.sid.c_str());
  EXPECT_EQ(OC_CPS_UNINITIALIZED_STR, crd.cps);
  EXPECT_EQ(0, crd.clec);
}

TEST_F(TestCloudResourceWithServer, PostRequest)
{
  // TODO
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
