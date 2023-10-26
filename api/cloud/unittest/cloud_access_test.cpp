/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef OC_SECURITY

#include "api/client/oc_client_cb_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_cloud_access.h"
#include "oc_cloud_internal.h"
#include "oc_endpoint.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"

#include <gtest/gtest.h>

class TestCloudAccess : public testing::Test {
public:
  static oc_handler_t s_handler;
  static oc_endpoint_t s_endpoint;

  static void onPostResponse(oc_client_response_t *)
  {
    // no-op for tests
  }

  static int appInit(void)
  {
    int result = oc_init_platform("OCFCloud", nullptr, nullptr);
    result |= oc_add_device("/oic/d", "oic.d.light", "Cloud's Light",
                            "ocf.1.0.0", "ocf.res.1.0.0", nullptr, nullptr);
    return result;
  }

  static void signalEventLoop(void)
  {
    // no-op for tests
  }

  static void SetUpTestCase()
  {
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);

    s_endpoint = oc::endpoint::FromString("coap://224.0.1.187:5683");
  }

  static void TearDownTestCase() { oc_main_shutdown(); }

  void TearDown() override
  {
    oc::TestDevice::DropOutgoingMessages();
    coap_free_all_transactions();
    oc_client_cbs_shutdown();
  }
};

oc_handler_t TestCloudAccess::s_handler;
oc_endpoint_t TestCloudAccess::s_endpoint;

TEST_F(TestCloudAccess, cloud_access_register_p)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ &s_endpoint,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ onPostResponse,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret = oc_cloud_access_register(conf, "auth_provider", "auth_code", "uid",
                                      "access_token");

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestCloudAccess, cloud_access_register_f)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ nullptr,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ nullptr,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret = oc_cloud_access_register(conf, nullptr, nullptr, nullptr, nullptr);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, cloud_access_login_p)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ &s_endpoint,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ onPostResponse,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret = oc_cloud_access_login(conf, "uid", "access_token");

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestCloudAccess, cloud_access_login_f)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ nullptr,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ nullptr,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret = oc_cloud_access_login(conf, nullptr, nullptr);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, cloud_access_logout_p)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ &s_endpoint,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ onPostResponse,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret = oc_cloud_access_logout(conf, "uid", "access_token");

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestCloudAccess, cloud_access_logout_f)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ nullptr,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ nullptr,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret = oc_cloud_access_logout(conf, nullptr, nullptr);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, cloud_access_refresh_access_token_p)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ &s_endpoint,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ onPostResponse,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret =
    oc_cloud_access_refresh_access_token(conf, "apn", "uid", "refresh_token");

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestCloudAccess, cloud_access_refresh_access_token_f)
{
  // When
  oc_cloud_access_conf_t conf = {
    /*.endpoint = */ nullptr,
    /*.device = */ 0,
    /*.selected_identity_cred_id = */ -1,
    /*.handler = */ nullptr,
    /*.user_data = */ nullptr,
    /*.timeout=*/0,
  };
  bool ret =
    oc_cloud_access_refresh_access_token(conf, nullptr, nullptr, nullptr);

  // Then
  EXPECT_FALSE(ret);
}

#endif /* !OC_SECURITY */
