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

#include "api/cloud/oc_cloud_internal.h"
#include "oc_api.h"
#include "tests/gtest/Device.h"

#include <gtest/gtest.h>

static constexpr size_t kDeviceID{ 0 };

class TestCloud : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

TEST_F(TestCloud, oc_cloud_get_context)
{
  EXPECT_NE(nullptr, oc_cloud_get_context(kDeviceID));
  EXPECT_EQ(nullptr, oc_cloud_get_context(1));
}

TEST_F(TestCloud, cloud_status)
{
  oc_cloud_status_t status;
  memset(&status, 0, sizeof(status));
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ctx->store.status = OC_CLOUD_INITIALIZED;
  cloud_manager_cb(ctx);
  EXPECT_EQ(ctx->store.status, status);
}

TEST_F(TestCloud, cloud_set_last_error)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);

  cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
  ASSERT_EQ(CLOUD_ERROR_RESPONSE, ctx->last_error);
}

TEST_F(TestCloud, cloud_update_by_resource)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ctx->store.status = OC_CLOUD_FAILURE;

  cloud_conf_update_t data;
  data.access_token = "access_token";
  data.access_token_len = strlen(data.access_token);
  data.auth_provider = "auth_provider";
  data.auth_provider_len = strlen(data.auth_provider);
  data.ci_server = "ci_server";
  data.ci_server_len = strlen("ci_server");
  data.sid = "sid";
  data.sid_len = strlen(data.sid);

  cloud_update_by_resource(ctx, &data);

  EXPECT_STREQ(data.access_token, oc_string(ctx->store.access_token));
  EXPECT_STREQ(data.auth_provider, oc_string(ctx->store.auth_provider));
  EXPECT_STREQ(data.ci_server, oc_string(ctx->store.ci_server));
  EXPECT_STREQ(data.sid, oc_string(ctx->store.sid));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, ctx->store.status);
}

TEST_F(TestCloud, oc_cloud_provision_conf_resource)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);

  const char *access_token = "access_token";
  const char *auth_provider = "auth_provider";
  const char *ci_server = "ci_server";
  const char *sid = "sid";
  ASSERT_EQ(0, oc_cloud_provision_conf_resource(ctx, ci_server, access_token,
                                                sid, auth_provider));

  EXPECT_STREQ(access_token, oc_string(ctx->store.access_token));
  EXPECT_STREQ(auth_provider, oc_string(ctx->store.auth_provider));
  EXPECT_STREQ(ci_server, oc_string(ctx->store.ci_server));
  EXPECT_STREQ(sid, oc_string(ctx->store.sid));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, ctx->store.status);
}
