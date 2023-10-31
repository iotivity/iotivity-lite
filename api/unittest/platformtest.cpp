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

#include "api/oc_core_res_internal.h"
#include "api/oc_platform_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_rep.h"
#include "port/oc_network_event_handler_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "oc_uuid.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <array>
#include <gtest/gtest.h>
#include <string>

static const std::string kManufacturerName{ "Samsung" };

static constexpr size_t kDeviceID{ 0 };

using namespace std::chrono_literals;

class TestPlatform : public testing::Test {
public:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
  }
  void TearDown() override
  {
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
};

TEST_F(TestPlatform, InitPlatform_P)
{
  EXPECT_EQ(0, oc_init_platform(kManufacturerName.c_str(), nullptr, nullptr));

  oc_platform_deinit();
}

TEST_F(TestPlatform, InitPlatform_F)
{
  std::vector<char> manufacturerName(OC_MAX_STRING_LENGTH + 1, 'a');
  ASSERT_EQ(-1, oc_init_platform(manufacturerName.data(), nullptr, nullptr));

  oc_platform_deinit();
}

TEST_F(TestPlatform, CoreInitPlatform_P)
{
  const oc_platform_info_t *oc_platform_info =
    oc_platform_init(kManufacturerName.c_str(), nullptr, nullptr);
  EXPECT_EQ(kManufacturerName.length(),
            oc_string_len(oc_platform_info->mfg_name));

  oc_platform_deinit();
}

TEST_F(TestPlatform, CoreGetResourceV1_P)
{
  oc_platform_init(kManufacturerName.c_str(), nullptr, nullptr);

  std::string uri = OCF_PLATFORM_URI;
  oc_resource_t *res =
    oc_core_get_resource_by_uri_v1(uri.c_str(), uri.length(), kDeviceID);

  ASSERT_NE(nullptr, res);
  EXPECT_EQ(uri.length(), oc_string_len(res->uri));

  oc_platform_deinit();
}

TEST_F(TestPlatform, IsPlatformURI_F)
{
  EXPECT_FALSE(oc_is_platform_resource_uri(OC_STRING_VIEW_NULL));
  EXPECT_FALSE(oc_is_platform_resource_uri(OC_STRING_VIEW("")));

  // missing the last character
  std::string uri = OCF_PLATFORM_URI;
  uri = uri.substr(0, uri.length() - 1);
  EXPECT_FALSE(
    oc_is_platform_resource_uri(oc_string_view(uri.c_str(), uri.length())));

  // one additional character
  uri = OCF_PLATFORM_URI;
  uri += "a";
  EXPECT_FALSE(
    oc_is_platform_resource_uri(oc_string_view(uri.c_str(), uri.length())));

  // same length, but different string
  uri = std::string(std::string(OCF_PLATFORM_URI).length() - 1, 'a');
  EXPECT_FALSE(
    oc_is_platform_resource_uri(oc_string_view(uri.c_str(), uri.length())));
  uri = std::string(std::string(OCF_PLATFORM_URI).length(), 'a');
  EXPECT_FALSE(
    oc_is_platform_resource_uri(oc_string_view(uri.c_str(), uri.length())));
}

TEST_F(TestPlatform, IsPlatformURI_P)
{
  std::string uri = OCF_PLATFORM_URI;
  EXPECT_TRUE(
    oc_is_platform_resource_uri(oc_string_view(uri.c_str(), uri.length())));

  uri = uri.substr(1, uri.length() - 1);
  EXPECT_TRUE(
    oc_is_platform_resource_uri(oc_string_view(uri.c_str(), uri.length())));
}

class TestPlatformWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

struct platformBaseData
{
  std::string pi;
  std::string manufacturerName;
};

static platformBaseData
parsePlatform(const oc_rep_t *rep)
{
  platformBaseData pData{};

  char *str;
  size_t str_len;
  // pi: string
  if (oc_rep_get_string(rep, "pi", &str, &str_len)) {
    pData.pi = std::string(str, str_len);
  }
  // mnmn: string
  if (oc_rep_get_string(rep, "mnmn", &str, &str_len)) {
    pData.manufacturerName = std::string(str, str_len);
  }

  return pData;
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
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    platformBaseData pbd = parsePlatform(data->payload);
    EXPECT_STREQ(oc_string(oc_core_get_platform_info()->mfg_name),
                 pbd.manufacturerName.c_str());
    std::array<char, OC_UUID_LEN> uuid{};
    oc_uuid_to_str(&oc_core_get_platform_info()->pi, &uuid[0], uuid.size());
    EXPECT_STREQ(uuid.data(), pbd.pi.c_str());
  };

  auto timeout = 1s;
  bool invoked = false;
  EXPECT_TRUE(oc_do_get_with_timeout(
    OCF_PLATFORM_URI, &ep, query.empty() ? nullptr : query.c_str(),
    timeout.count(), get_handler, HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

TEST_F(TestPlatformWithServer, GetRequest)
{
  getRequestWithQuery("");
}

TEST_F(TestPlatformWithServer, GetRequestBaseline)
{
  getRequestWithQuery("if=" OC_IF_BASELINE_STR);
}

TEST_F(TestPlatformWithServer, PostRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_POST, &ep, OCF_PLATFORM_URI, nullptr,
                             OC_STATUS_FORBIDDEN);
}

TEST_F(TestPlatformWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_PLATFORM_URI, nullptr,
                             OC_STATUS_FORBIDDEN);
}

TEST_F(TestPlatformWithServer, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_PLATFORM_URI, nullptr,
                             OC_STATUS_FORBIDDEN);
}

// TODO: add tests for dump (oc_sec_dump_unique_ids) and load
// (oc_sec_load_unique_ids)
