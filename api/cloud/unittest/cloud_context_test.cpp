/****************************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/oc_helpers_internal.h"

#include <gtest/gtest.h>

class TestCloudContext : public testing::Test {};

TEST_F(TestCloudContext, GetDevice)
{
  oc_cloud_context_t ctx{};
  ctx.device = 42;
  EXPECT_EQ(42, oc_cloud_get_device(&ctx));
}

TEST_F(TestCloudContext, GetApn)
{
  oc_cloud_context_t ctx{};
  ctx.store.auth_provider = OC_STRING_LOCAL("apn");
  EXPECT_STREQ("apn", oc_cloud_get_apn(&ctx));
}

TEST_F(TestCloudContext, GetCis)
{
  oc_cloud_context_t ctx{};
  ctx.store.ci_server = OC_STRING_LOCAL("cis");
  EXPECT_STREQ("cis", oc_cloud_get_cis(&ctx));
}

TEST_F(TestCloudContext, GetUid)
{
  oc_cloud_context_t ctx{};
  ctx.store.uid = OC_STRING_LOCAL("uid");
  EXPECT_STREQ("uid", oc_cloud_get_uid(&ctx));
}

TEST_F(TestCloudContext, GetAccessToken)
{
  oc_cloud_context_t ctx{};
  ctx.store.access_token = OC_STRING_LOCAL("access_token");
  EXPECT_STREQ("access_token", oc_cloud_get_at(&ctx));
}

TEST_F(TestCloudContext, GetSid)
{
  oc_cloud_context_t ctx{};
  ctx.store.sid = OC_STRING_LOCAL("sid");
  EXPECT_STREQ("sid", oc_cloud_get_sid(&ctx));
}

TEST_F(TestCloudContext, HasAccesToken)
{
  oc_cloud_context_t ctx{};

  EXPECT_FALSE(cloud_context_has_access_token(&ctx));
  EXPECT_FALSE(cloud_context_has_permanent_access_token(&ctx));

  ctx.store.access_token = OC_STRING_LOCAL("");
  EXPECT_FALSE(cloud_context_has_access_token(&ctx));
  EXPECT_FALSE(cloud_context_has_permanent_access_token(&ctx));

  ctx.store.access_token = OC_STRING_LOCAL("access_token");
  EXPECT_TRUE(cloud_context_has_access_token(&ctx));
  EXPECT_FALSE(cloud_context_has_permanent_access_token(&ctx));

  ctx.store.expires_in = -1;
  EXPECT_TRUE(cloud_context_has_access_token(&ctx));
  EXPECT_TRUE(cloud_context_has_permanent_access_token(&ctx));
}

TEST_F(TestCloudContext, HasRefreshToken)
{
  oc_cloud_context_t ctx{};

  EXPECT_FALSE(cloud_context_has_refresh_token(&ctx));

  ctx.store.refresh_token = OC_STRING_LOCAL("");
  EXPECT_FALSE(cloud_context_has_refresh_token(&ctx));

  ctx.store.refresh_token = OC_STRING_LOCAL("refresh_token");
  EXPECT_TRUE(cloud_context_has_refresh_token(&ctx));
}

TEST_F(TestCloudContext, SetIdentityCertChain)
{
  oc_cloud_context_t ctx{};
  EXPECT_EQ(0, oc_cloud_get_identity_cert_chain(&ctx));

  oc_cloud_set_identity_cert_chain(&ctx, 42);
  EXPECT_EQ(42, oc_cloud_get_identity_cert_chain(&ctx));
}

TEST_F(TestCloudContext, SetKeepalive)
{
  oc_cloud_context_t ctx{};

  auto on_response = [](bool, uint64_t *, uint16_t *, void *) { return true; };
  int user_data = 42;
  oc_cloud_set_keepalive(&ctx, on_response, &user_data);

  EXPECT_EQ(&user_data, ctx.keepalive.user_data);
  EXPECT_EQ(on_response, ctx.keepalive.on_response);
}
