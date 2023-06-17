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

#include "oc_config.h"

#ifdef OC_INTROSPECTION

#include "api/oc_introspection_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_core_res.h"
#include "oc_introspection.h"
#include "oc_log.h"
#include "oc_ri.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Storage.h"

#include <algorithm>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <vector>

constexpr size_t kDeviceID = 0;

class TestIntrospectionWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_log_set_level(OC_LOG_LEVEL_DEBUG);

    ASSERT_EQ(0, oc::TestStorage.Config());
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_INTROSPECTION_WK, kDeviceID, false,
                                     OC_PERM_RETRIEVE));
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_INTROSPECTION_DATA, false, kDeviceID,
                                     OC_PERM_RETRIEVE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#ifdef OC_IDD_API
    std::vector<uint8_t> idd{};
    auto idd_fs = std::ifstream("introspectiontest_IDD.cbor",
                                std::ios::in | std::ios::binary);
    std::for_each(std::istreambuf_iterator<char>(idd_fs),
                  std::istreambuf_iterator<char>(),
                  [&idd](char c) { idd.push_back(c); });
    idd_ = std::move(idd);
    oc_set_introspection_data(kDeviceID, idd_.data(), idd_.size());
#endif /* OC_IDD_API */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
    ASSERT_EQ(0, oc::TestStorage.Clear());
  }

#ifdef OC_IDD_API
  static std::vector<uint8_t> idd_;
#endif /* OC_IDD_API */
};

#ifdef OC_IDD_API
std::vector<uint8_t> TestIntrospectionWithServer::idd_{};
#endif /* OC_IDD_API */

TEST_F(TestIntrospectionWithServer, GetResource)
{
  EXPECT_NE(nullptr,
            oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, kDeviceID));
}

TEST_F(TestIntrospectionWithServer, GetDataResource)
{
  EXPECT_NE(nullptr,
            oc_core_get_resource_by_index(OCF_INTROSPECTION_DATA, kDeviceID));
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

TEST_F(TestIntrospectionWithServer, GetRequest)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    *static_cast<bool *>(data->user_data) = true;
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
  };

  bool invoked = false;
  EXPECT_TRUE(oc_do_get(OC_INTROSPECTION_WK_URI, ep, "if=" OC_IF_BASELINE_STR,
                        get_handler, HIGH_QOS, &invoked));
  oc::TestDevice::PoolEvents(5);
  EXPECT_TRUE(invoked);
}

#ifdef OC_DYNAMIC_ALLOCATION

// the IDD data is too large for non-dynamic allocation and byte pool gets
// exhausted

TEST_F(TestIntrospectionWithServer, GetDataRequest)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    *static_cast<bool *>(data->user_data) = true;
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
  };

  bool invoked = false;
  EXPECT_TRUE(oc_do_get(OC_INTROSPECTION_DATA_URI, ep, "if=" OC_IF_BASELINE_STR,
                        get_handler, HIGH_QOS, &invoked));
  oc::TestDevice::PoolEvents(5);
  EXPECT_TRUE(invoked);
}

#endif /* OC_DYNAMIC_ALLOCATION */

TEST_F(TestIntrospectionWithServer, PostRequest_FailMethodNotSupported)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);
  oc::testNotSupportedMethod(OC_POST, ep, OC_INTROSPECTION_WK_URI, nullptr,
                             OC_STATUS_FORBIDDEN);
}

TEST_F(TestIntrospectionWithServer, PostDataRequest_FailMethodNotSupported)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);
#ifdef OC_SECURITY
  // introspection data is a not secured resource, but the request handler will
  // fail authorization
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_POST, ep, OC_INTROSPECTION_DATA_URI, nullptr,
                             code);
}

TEST_F(TestIntrospectionWithServer, PutRequest_FailMethodNotSupported)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);
  oc::testNotSupportedMethod(OC_PUT, ep, OC_INTROSPECTION_WK_URI, nullptr,
                             OC_STATUS_FORBIDDEN);
}

TEST_F(TestIntrospectionWithServer, PutDataRequest_FailMethodNotSupported)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);
#ifdef OC_SECURITY
  // introspection data is a not secured resource, but the request handler will
  // fail authorization
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_PUT, ep, OC_INTROSPECTION_DATA_URI, nullptr,
                             code);
}

TEST_F(TestIntrospectionWithServer, DeleteRequest_FailMethodNotSupported)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);
  oc::testNotSupportedMethod(OC_DELETE, ep, OC_INTROSPECTION_WK_URI, nullptr,
                             OC_STATUS_FORBIDDEN);
}

TEST_F(TestIntrospectionWithServer, DeleteDataRequest_FailMethodNotSupported)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

#ifdef OC_SECURITY
  // introspection data is a not secured resource, but the request handler will
  // fail authorization
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_DELETE, ep, OC_INTROSPECTION_DATA_URI, nullptr,
                             code);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#endif /* OC_INTROSPECTION */
