/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifdef OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING

#include "api/oc_helpers_internal.h"
#include "api/oc_runtime_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_apis_internal.h"
#include "plgd/plgd_dps.h"
#include "plgd_dps_test.h"
#include "tests/gtest/RepPool.h"

#include "gtest/gtest.h"

#include <string>

static constexpr size_t kDeviceID = 0;

class DPSApisTest : public testing::Test {
public:
  static void SetUpTestCase() { oc_runtime_init(); }

  static void TearDownTestCase() { oc_runtime_shutdown(); }
};

TEST_F(DPSApisTest, IsEqualStringLen)
{
  EXPECT_TRUE(dps_is_equal_string_len({}, nullptr, 0));
  EXPECT_TRUE(dps_is_equal_string_len(OC_STRING_LOCAL(""), "", 0));
  EXPECT_TRUE(dps_is_equal_string_len(OC_STRING_LOCAL("test"), "test", 4));

  EXPECT_FALSE(dps_is_equal_string_len(OC_STRING_LOCAL(""), nullptr, 0));
  EXPECT_FALSE(dps_is_equal_string_len({}, "", 0));
  EXPECT_FALSE(dps_is_equal_string_len(OC_STRING_LOCAL("test"), "test1", 5));
  EXPECT_FALSE(dps_is_equal_string_len(OC_STRING_LOCAL("testA"), "testB", 5));
}

TEST_F(DPSApisTest, IsEqualString)
{
  EXPECT_TRUE(dps_is_equal_string({}, {}));
  EXPECT_TRUE(dps_is_equal_string(OC_STRING_LOCAL(""), OC_STRING_LOCAL("")));
  EXPECT_TRUE(
    dps_is_equal_string(OC_STRING_LOCAL("test"), OC_STRING_LOCAL("test")));

  EXPECT_FALSE(dps_is_equal_string(OC_STRING_LOCAL(""), {}));
  EXPECT_FALSE(dps_is_equal_string({}, OC_STRING_LOCAL("")));
  EXPECT_FALSE(
    dps_is_equal_string(OC_STRING_LOCAL("test"), OC_STRING_LOCAL("test1")));
  EXPECT_FALSE(
    dps_is_equal_string(OC_STRING_LOCAL("testA"), OC_STRING_LOCAL("testB")));
}

TEST_F(DPSApisTest, IsTimeoutError)
{
  EXPECT_TRUE(dps_is_timeout_error_code(OC_REQUEST_TIMEOUT));
  EXPECT_TRUE(dps_is_timeout_error_code(OC_TRANSACTION_TIMEOUT));

  std::vector<oc_status_t> nonTimeouts = {
    OC_STATUS_OK,
    OC_STATUS_CREATED,
    OC_STATUS_CHANGED,
    OC_STATUS_DELETED,
    OC_STATUS_BAD_REQUEST,
    OC_STATUS_UNAUTHORIZED,
    OC_STATUS_FORBIDDEN,
    OC_STATUS_NOT_FOUND,
    OC_STATUS_METHOD_NOT_ALLOWED,
    OC_STATUS_NOT_ACCEPTABLE,
    OC_STATUS_REQUEST_ENTITY_TOO_LARGE,
    OC_STATUS_UNSUPPORTED_MEDIA_TYPE,
    OC_STATUS_INTERNAL_SERVER_ERROR,
    OC_STATUS_NOT_IMPLEMENTED,
    OC_STATUS_BAD_GATEWAY,
    OC_STATUS_SERVICE_UNAVAILABLE,
    OC_STATUS_GATEWAY_TIMEOUT,
    OC_STATUS_PROXYING_NOT_SUPPORTED,
    OC_IGNORE,
    OC_PING_TIMEOUT, // should be returned only by oc_send_ping, which is not
                     // used in DPS
    OC_CONNECTION_CLOSED,
    OC_CANCELLED,
  };
  for (auto status : nonTimeouts) {
    EXPECT_FALSE(dps_is_timeout_error_code(status));
  }
}

TEST_F(DPSApisTest, IsConnectionError)
{
  EXPECT_TRUE(dps_is_connection_error_code(OC_STATUS_SERVICE_UNAVAILABLE));
  EXPECT_TRUE(dps_is_connection_error_code(OC_STATUS_GATEWAY_TIMEOUT));

  std::vector<oc_status_t> nonConnectionErrors = {
    OC_STATUS_OK,
    OC_STATUS_CREATED,
    OC_STATUS_CHANGED,
    OC_STATUS_DELETED,
    OC_STATUS_BAD_REQUEST,
    OC_STATUS_UNAUTHORIZED,
    OC_STATUS_FORBIDDEN,
    OC_STATUS_NOT_FOUND,
    OC_STATUS_METHOD_NOT_ALLOWED,
    OC_STATUS_NOT_ACCEPTABLE,
    OC_STATUS_REQUEST_ENTITY_TOO_LARGE,
    OC_STATUS_UNSUPPORTED_MEDIA_TYPE,
    OC_STATUS_INTERNAL_SERVER_ERROR,
    OC_STATUS_NOT_IMPLEMENTED,
    OC_STATUS_BAD_GATEWAY,
    OC_STATUS_PROXYING_NOT_SUPPORTED,
    OC_IGNORE,
    OC_PING_TIMEOUT, // should be returned only by oc_send_ping, which is not
                     // used in DPS
    OC_REQUEST_TIMEOUT,
    OC_CONNECTION_CLOSED,
    OC_TRANSACTION_TIMEOUT,
    OC_CANCELLED,
  };
  for (auto status : nonConnectionErrors) {
    EXPECT_FALSE(dps_is_connection_error_code(status));
  }
}

TEST_F(DPSApisTest, RedirectResponse)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  std::string ep1_uri = "/uri/1";
  std::string ep1_name = "name1";
  auto *ep1 =
    plgd_dps_add_endpoint_address(ctx.get(), ep1_uri.c_str(), ep1_uri.length(),
                                  ep1_name.c_str(), ep1_name.length());
  ASSERT_NE(nullptr, ep1);

  oc::RepPool pool{};
  auto handleRedirect = [&ctx, &pool](std::string_view redirecturi) {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, redirecturi, redirecturi.data());
    oc_rep_end_root_object();
    ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
    oc::oc_rep_unique_ptr rep = pool.ParsePayload();
    ASSERT_NE(nullptr, rep.get());
    ASSERT_TRUE(dps_handle_redirect_response(ctx.get(), rep.get()));
  };

  // ctx contains an endpoint, but with a different URI than the redirect
  std::string redirect{ "coap://mock.plgd.dev" };
  handleRedirect(redirect);
  const oc_string_t *selected_uri =
    oc_endpoint_addresses_selected_uri(&ctx->store.endpoints);
  ASSERT_NE(nullptr, selected_uri);
  EXPECT_STREQ(redirect.c_str(), oc_string(*selected_uri));
  const oc_string_t *selected_name =
    oc_endpoint_addresses_selected_name(&ctx->store.endpoints);
  ASSERT_NE(nullptr, selected_name);
  // the redirected URI should take name from the previously selected endpoint
  EXPECT_STREQ(ep1_name.c_str(), oc_string(*selected_name));
  EXPECT_EQ(1, oc_endpoint_addresses_size(&ctx->store.endpoints));

  // redirect to the selected endpoint
  handleRedirect(redirect);
  EXPECT_EQ(1, oc_endpoint_addresses_size(&ctx->store.endpoints));
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    &ctx->store.endpoints,
    oc_string_view(redirect.c_str(), redirect.length())));

  // ctx contains multiple endpoints, including the redirected one, which should
  // be selected
  ep1 =
    plgd_dps_add_endpoint_address(ctx.get(), ep1_uri.c_str(), ep1_uri.length(),
                                  ep1_name.c_str(), ep1_name.length());
  ASSERT_NE(nullptr, ep1);
  oc_endpoint_addresses_select(&ctx->store.endpoints, ep1);
  ASSERT_EQ(2, oc_endpoint_addresses_size(&ctx->store.endpoints));
  ASSERT_TRUE(oc_endpoint_addresses_is_selected(
    &ctx->store.endpoints, oc_string_view(ep1_uri.c_str(), ep1_uri.length())));
  handleRedirect(redirect);
  EXPECT_EQ(1, oc_endpoint_addresses_size(&ctx->store.endpoints));
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    &ctx->store.endpoints,
    oc_string_view(redirect.c_str(), redirect.length())));
}

TEST_F(DPSApisTest, RedirectResponse_Fail)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  oc::RepPool pool{};
  // missing redirecturi -> processing skipped
  oc_rep_begin_root_object();
  oc_rep_set_text_string(root, plgd, "dev");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  EXPECT_TRUE(dps_handle_redirect_response(ctx.get(), rep.get()));

  rep.reset();
  pool.Clear();
  // invalid redirecturi
  oc_rep_begin_root_object();
  oc_rep_set_text_string(root, redirecturi, "");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  EXPECT_FALSE(dps_handle_redirect_response(ctx.get(), rep.get()));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */