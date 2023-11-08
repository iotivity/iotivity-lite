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

#ifdef OC_MNT

#include "api/oc_mnt_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_core_res.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"

#include <gtest/gtest.h>
#include <string>

static constexpr size_t kDeviceID{ 0 };

using namespace std::chrono_literals;

class TestMaintenance : public testing::Test {};

TEST_F(TestMaintenance, IsMaintenanceURI_F)
{
  EXPECT_FALSE(oc_is_maintenance_resource_uri(OC_STRING_VIEW_NULL));
  EXPECT_FALSE(oc_is_maintenance_resource_uri(OC_STRING_VIEW("")));
}

TEST_F(TestMaintenance, IsMaintenanceURI_P)
{
  std::string uri = OCF_MNT_URI;
  EXPECT_TRUE(
    oc_is_maintenance_resource_uri(oc_string_view(uri.c_str(), uri.length())));
  uri = uri.substr(1, uri.length() - 1);
  EXPECT_TRUE(
    oc_is_maintenance_resource_uri(oc_string_view(uri.c_str(), uri.length())));
}

class TestMaintenanceWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    // TODO rm
    oc_log_set_level(OC_LOG_LEVEL_DEBUG);

    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_MNT, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();

    oc_log_set_level(OC_LOG_LEVEL_INFO);
  }
};

TEST_F(TestMaintenanceWithServer, GetResourceByIndex_F)
{
  EXPECT_EQ(nullptr,
            oc_core_get_resource_by_index(OCF_MNT, /*device*/ SIZE_MAX));
}

TEST_F(TestMaintenanceWithServer, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_MNT, kDeviceID));
}

TEST_F(TestMaintenanceWithServer, CoreGetResourceV1_P)
{
  std::string uri = OCF_MNT_URI;
  oc_resource_t *res =
    oc_core_get_resource_by_uri_v1(uri.c_str(), uri.length(), kDeviceID);

  ASSERT_NE(nullptr, res);
  EXPECT_EQ(uri.length(), oc_string_len(res->uri));
}

struct mntBaseData
{
  bool factoryReset;
};

static bool
parseMnt(const oc_rep_t *rep, mntBaseData &mntData)
{
  bool factoryReset;
  if (!oc_rep_get_bool(rep, "fr", &factoryReset)) {
    return false;
  }
  mntData.factoryReset = factoryReset;
  return true;
}

static void
getRequestWithQuery(const std::string &query)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_OK, data->code);
    *static_cast<bool *>(data->user_data) = true;
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
    mntBaseData mntData{};
    EXPECT_TRUE(parseMnt(data->payload, mntData));
    EXPECT_FALSE(mntData.factoryReset);
  };

  auto timeout = 1s;
  bool invoked = false;
  ASSERT_TRUE(oc_do_get_with_timeout(
    OCF_MNT_URI, &ep, query.empty() ? nullptr : query.c_str(), timeout.count(),
    get_handler, HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

TEST_F(TestMaintenanceWithServer, GetRequest)
{
  getRequestWithQuery("");
}

TEST_F(TestMaintenanceWithServer, GetRequestBaseline)
{
  getRequestWithQuery("if=" OC_IF_BASELINE_STR);
}

TEST_F(TestMaintenanceWithServer, PostRequest)
{
  // TODO
}

TEST_F(TestMaintenanceWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#if defined(OC_SECURITY) && !defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_MNT_URI, nullptr, code);
}

TEST_F(TestMaintenanceWithServer, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#if defined(OC_SECURITY) && !defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_MNT_URI, nullptr, code);
}

#endif /* OC_MNT */
