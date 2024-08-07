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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#ifdef _WIN32
// don't define max() macro
#define NOMINMAX
#endif /* _WIN32 */

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_helpers_internal.h"
#include "oc_config.h"
#include "port/oc_random.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"

#include "gtest/gtest.h"

#include <array>
#include <cstdint>
#include <limits>
#include <string>

using namespace std::chrono_literals;

class TestClientCB : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }

  void SetUp() override
  {
    TestClientCB::responseHandlerInvoked = false;
    TestClientCB::discoveryHandlerInvoked = false;
    TestClientCB::discoveryAllHandlerInvoked = false;
    oc_client_cbs_init();
  }

  void TearDown() override { oc_client_cbs_shutdown(); }

  static oc_client_cb_t *allocDummyClientCB(
    const std::string &uri, const oc_endpoint_t *endpoint = nullptr,
    oc_method_t method = OC_GET);

  static void responseHandler(oc_client_response_t *)
  {
    TestClientCB::responseHandlerInvoked = true;
  }

  static oc_discovery_flags_t discoveryHandler(const char *, const char *,
                                               oc_string_array_t,
                                               oc_interface_mask_t,
                                               const oc_endpoint_t *,
                                               oc_resource_properties_t, void *)
  {
    TestClientCB::discoveryHandlerInvoked = true;
    return OC_STOP_DISCOVERY;
  }

  static oc_discovery_flags_t discoveryAllHandler(
    const char *, const char *, oc_string_array_t, oc_interface_mask_t,
    const oc_endpoint_t *, oc_resource_properties_t, bool, void *)
  {
    TestClientCB::discoveryAllHandlerInvoked = true;
    return OC_STOP_DISCOVERY;
  }

  static bool responseHandlerInvoked;
  static bool discoveryHandlerInvoked;
  static bool discoveryAllHandlerInvoked;
};

bool TestClientCB::responseHandlerInvoked = false;
bool TestClientCB::discoveryHandlerInvoked = false;
bool TestClientCB::discoveryAllHandlerInvoked = false;

oc_client_cb_t *
TestClientCB::allocDummyClientCB(const std::string &uri,
                                 const oc_endpoint_t *endpoint,
                                 oc_method_t method)
{
  oc_client_handler_t handler = {
    /*response=*/responseHandler,
    /*discovery=*/discoveryHandler,
    /*discovery_all=*/discoveryAllHandler,
  };
  return oc_ri_alloc_client_cb(uri.c_str(), endpoint, method,
                               /*query*/ nullptr, handler, LOW_QOS,
                               /*user_data*/ nullptr);
}

TEST_F(TestClientCB, Alloc)
{
  oc_client_cb_t *cb = allocDummyClientCB("/test");
  ASSERT_NE(nullptr, cb);

  EXPECT_STREQ("/test", oc_string(cb->uri));
  EXPECT_TRUE(oc_ri_is_client_cb_valid(cb));
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestClientCB, Alloc_Fail)
{
  for (int i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS + 1; ++i) {
    oc_client_cb_t *cb = allocDummyClientCB("/test" + std::to_string(i));
    ASSERT_NE(nullptr, cb);
  }

  oc_client_cb_t *cb = allocDummyClientCB("/fail");
  EXPECT_EQ(nullptr, cb);
  EXPECT_FALSE(oc_ri_is_client_cb_valid(cb));
}

#endif /* !OC_DYNAMIC_ALLOCATION */

TEST_F(TestClientCB, Free)
{
  oc_client_cb_t *cb = allocDummyClientCB("/test");
  ASSERT_NE(nullptr, cb);

  oc_client_cb_free(cb);
  EXPECT_FALSE(oc_ri_is_client_cb_valid(cb));
}

TEST_F(TestClientCB, FindByToken)
{
  oc_client_cb_t *cb1 = allocDummyClientCB("/token-1");
  ASSERT_NE(nullptr, cb1);
  oc_client_cb_t *cb2 = allocDummyClientCB("/token-2");
  ASSERT_NE(nullptr, cb2);

  uint8_t empty{ 0 };
  EXPECT_EQ(nullptr, oc_ri_find_client_cb_by_token(&empty, 1));

  std::array<uint8_t, COAP_TOKEN_LEN> token;
  oc_random_buffer(&token[0], token.size());

  oc_client_cb_t *cb =
    oc_ri_find_client_cb_by_token(cb1->token, cb1->token_len);
  EXPECT_EQ(cb1, cb);
  cb = oc_ri_find_client_cb_by_token(cb2->token, cb2->token_len);
  EXPECT_EQ(cb2, cb);
}

TEST_F(TestClientCB, FindByMid)
{
  oc_client_cb_t *cb1 = allocDummyClientCB("/mid-1");
  ASSERT_NE(nullptr, cb1);
  oc_client_cb_t *cb2 = allocDummyClientCB("/mid-2");
  ASSERT_NE(nullptr, cb2);

  EXPECT_EQ(nullptr,
            oc_ri_find_client_cb_by_mid(std::numeric_limits<uint16_t>::max()));

  oc_client_cb_t *cb = oc_ri_find_client_cb_by_mid(cb1->mid);
  EXPECT_EQ(cb1, cb);
  cb = oc_ri_find_client_cb_by_mid(cb2->mid);
  EXPECT_EQ(cb2, cb);
}

TEST_F(TestClientCB, GetClientCB)
{
  std::string uri{ "/1" };
  std::string ep_str{ "coap://[ff02::152]" };
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);
  oc_method_t method{ OC_GET };

  oc_client_cb_t *cbToMatch = allocDummyClientCB(uri, &ep, method);
  ASSERT_NE(nullptr, cbToMatch);

  // non-matching URI
  ASSERT_EQ(nullptr, oc_ri_get_client_cb("/2", &ep, method));
  // non-matching endpoint
  oc_endpoint_t ep2 = oc::endpoint::FromString("coap://[ff02::158]");
  ASSERT_EQ(nullptr, oc_ri_get_client_cb(uri.c_str(), &ep2, method));
  // non-matching method
  ASSERT_EQ(nullptr, oc_ri_get_client_cb(uri.c_str(), &ep, OC_POST));

  oc_client_cb_t *cb = oc_ri_get_client_cb(uri.c_str(), &ep, method);
  EXPECT_EQ(cbToMatch, cb);
}

TEST_F(TestClientCB, RemoveByMid)
{
  oc_client_cb_t *cb1 = allocDummyClientCB("/mid-1");
  ASSERT_NE(nullptr, cb1);
  uint16_t mid1 = cb1->mid;
  oc_client_cb_t *cb2 = allocDummyClientCB("/mid-2");
  ASSERT_NE(nullptr, cb2);
  uint16_t mid2 = cb2->mid;

  EXPECT_NE(nullptr, oc_ri_find_client_cb_by_mid(mid1));
  EXPECT_NE(nullptr, oc_ri_find_client_cb_by_mid(mid2));
  oc_ri_free_client_cbs_by_mid(mid2);
  EXPECT_NE(nullptr, oc_ri_find_client_cb_by_mid(mid1));
  EXPECT_EQ(nullptr, oc_ri_find_client_cb_by_mid(mid2));
}

TEST_F(TestClientCB, RemoveByEndpoint)
{
  oc_endpoint_t ep1 = oc::endpoint::FromString("coap://[ff02::151]");
  oc_client_cb_t *cb1 = allocDummyClientCB("/mid-1", &ep1);
  ASSERT_NE(nullptr, cb1);
  uint16_t mid1 = cb1->mid;
  oc_client_cb_t *cb2 = allocDummyClientCB("/mid-2", &ep1);
  ASSERT_NE(nullptr, cb2);
  uint16_t mid2 = cb2->mid;
  oc_endpoint_t ep2 = oc::endpoint::FromString("coap://[ff02::152]");
  oc_client_cb_t *cb3 = allocDummyClientCB("/mid-3", &ep2);
  ASSERT_NE(nullptr, cb3);
  uint16_t mid3 = cb3->mid;

  EXPECT_NE(nullptr, oc_ri_find_client_cb_by_mid(mid1));
  EXPECT_NE(nullptr, oc_ri_find_client_cb_by_mid(mid2));
  EXPECT_NE(nullptr, oc_ri_find_client_cb_by_mid(mid3));
  oc_ri_free_client_cbs_by_endpoint(&ep1);
  EXPECT_EQ(nullptr, oc_ri_find_client_cb_by_mid(mid1));
  EXPECT_EQ(nullptr, oc_ri_find_client_cb_by_mid(mid2));
  EXPECT_NE(nullptr, oc_ri_find_client_cb_by_mid(mid3));
}

class TestClientCBWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void SetUp() override
  {
    TestClientCB::responseHandlerInvoked = false;
    TestClientCB::discoveryHandlerInvoked = false;
    TestClientCB::discoveryAllHandlerInvoked = false;
    oc_client_cbs_init();
  }

  void TearDown() override { oc::TestDevice::Reset(); }
};

TEST_F(TestClientCBWithServer, RemoveAsync)
{
  oc_client_cb_t *cb = TestClientCB::allocDummyClientCB("/test");
  ASSERT_NE(nullptr, cb);
  EXPECT_FALSE(oc_has_delayed_callback(cb, &oc_client_cb_remove_async, false));

  oc_set_delayed_callback(cb, &oc_client_cb_remove_async, 0);
  EXPECT_TRUE(oc_has_delayed_callback(cb, &oc_client_cb_remove_async, false));
  oc::TestDevice::PoolEventsMsV1(50ms);

  EXPECT_FALSE(oc_ri_is_client_cb_valid(cb));
}

TEST_F(TestClientCBWithServer, RemoveWithTimeoutAsync)
{
  oc_client_cb_t *cb = TestClientCB::allocDummyClientCB("/test");
  ASSERT_NE(nullptr, cb);
  EXPECT_FALSE(oc_has_delayed_callback(
    cb, &oc_client_cb_remove_with_notify_timeout_async, false));

  oc_set_delayed_callback_ms(cb, &oc_client_cb_remove_with_notify_timeout_async,
                             0);
  EXPECT_TRUE(oc_has_delayed_callback(
    cb, &oc_client_cb_remove_with_notify_timeout_async, false));
  oc::TestDevice::PoolEventsMsV1(50ms);

  EXPECT_TRUE(TestClientCB::responseHandlerInvoked);
  EXPECT_FALSE(oc_ri_is_client_cb_valid(cb));
}