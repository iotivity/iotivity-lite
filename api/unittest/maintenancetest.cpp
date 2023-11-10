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

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

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
  static void setupDevice()
  {
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_MNT, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
    setupDevice();
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
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

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

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

template<oc_status_t CODE = OC_STATUS_OK>
static void
getRequestWithQuery(const std::string &query = "")
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(CODE, data->code);
    *static_cast<bool *>(data->user_data) = true;
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload, true).data());
    if (data->code != OC_STATUS_OK) {
      return;
    }
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
  getRequestWithQuery();
}

TEST_F(TestMaintenanceWithServer, GetRequestBaseline)
{
  getRequestWithQuery("if=" OC_IF_BASELINE_STR);
}

TEST_F(TestMaintenanceWithServer, PostRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_CHANGED, data->code);
    *static_cast<bool *>(data->user_data) = true;
    OC_DBG("POST payload: %s",
           oc::RepPool::GetJson(data->payload, true).data());
  };

#if defined(OC_SECURITY) && defined(OC_TEST)
  oc_pstat_set_reset_delay_ms(100);
#endif /* OC_SECURITY && OC_TEST */

  bool invoked = false;
  ASSERT_TRUE(
    oc_init_post(OCF_MNT_URI, &ep, nullptr, post_handler, HIGH_QOS, &invoked));
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, fr, true);
  oc_rep_end_root_object();
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

#ifdef OC_SECURITY
  ASSERT_TRUE(oc_reset_in_progress(kDeviceID));

// wait for the device to handle the factory reset
#ifdef OC_TEST
  oc::TestDevice::PoolEventsMsV1(100ms, true);
#else  /* !OC_TEST */
  oc::TestDevice::PoolEventsMs(OC_PSTAT_RESET_DELAY_MS, true);
#endif /* OC_TEST */
  ASSERT_FALSE(oc_reset_in_progress(kDeviceID));

  setupDevice();
#endif /* OC_SECURITY */
}

template<typename Fn, oc_status_t CODE = OC_STATUS_BAD_REQUEST>
static void
postRequestFail(const std::string &query, Fn encodeFn)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(CODE, data->code);
    *static_cast<bool *>(data->user_data) = true;
    OC_DBG("POST payload: %s",
           oc::RepPool::GetJson(data->payload, true).data());
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_MNT_URI, &ep, query.c_str(), post_handler,
                           HIGH_QOS, &invoked));

  encodeFn();

  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

TEST_F(TestMaintenanceWithServer, PostRequest_FailResetFalse)
{
  postRequestFail("", [] {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, fr, false);
    oc_rep_end_root_object();
  });
}

TEST_F(TestMaintenanceWithServer, PostRequest_FailInvalidPayload)
{
  postRequestFail("", [] {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, factory, "reset");
    oc_rep_end_root_object();
  });
}

#else /* OC_SECURITY && !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestMaintenanceWithServer, GetRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_GET, &ep, OCF_MNT_URI, nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

TEST_F(TestMaintenanceWithServer, PostRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_POST, &ep, OCF_MNT_URI, nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

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

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)

class TestMaintenanceWithConstrainedServer : public testing::Test {
public:
  static void setupDevice()
  {
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_MNT, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void SetUpTestCase()
  {
    // 30 is enough to encode the non-baseline interface payload, but not the
    // baseline interface payload
    defaultAppSize = static_cast<size_t>(oc_get_max_app_data_size());
    oc_set_max_app_data_size(30);

    ASSERT_TRUE(oc::TestDevice::StartServer());
    setupDevice();
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
    oc_set_max_app_data_size(defaultAppSize);
  }

private:
  static size_t defaultAppSize;
};

size_t TestMaintenanceWithConstrainedServer::defaultAppSize{};

TEST_F(TestMaintenanceWithConstrainedServer,
       GetRequestBaseline_FailCannotEncodePayload)
{
  getRequestWithQuery<OC_STATUS_INTERNAL_SERVER_ERROR>(
    "if=" OC_IF_BASELINE_STR);
}

TEST_F(TestMaintenanceWithConstrainedServer,
       PostRequest_FailCannotEncodePayload)
{
#if defined(OC_SECURITY) && defined(OC_TEST)
  oc_pstat_set_reset_delay_ms(0);
#endif /* OC_SECURITY && OC_TEST */

  auto encode = [] {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, fr, true);
    oc_rep_end_root_object();
  };
  postRequestFail<decltype(encode), OC_STATUS_INTERNAL_SERVER_ERROR>(
    "if=" OC_IF_BASELINE_STR, encode);

#ifdef OC_SECURITY
// wait for the device to handle the factory reset
#ifdef OC_TEST
  oc::TestDevice::PoolEventsMsV1(0ms, true);
#else  /* !OC_TEST */
  oc::TestDevice::PoolEventsMs(OC_PSTAT_RESET_DELAY_MS, true);
#endif /* OC_TEST */
  ASSERT_FALSE(oc_reset_in_progress(kDeviceID));

  setupDevice();
#endif /* OC_SECURITY */
}

#endif // OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#endif /* OC_MNT */
