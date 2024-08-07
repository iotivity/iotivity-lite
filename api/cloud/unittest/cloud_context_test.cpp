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
#include "api/oc_runtime_internal.h"
#include "oc_uuid.h"
#include "util/oc_features.h"

#include "gtest/gtest.h"
#include <vector>

class TestCloudContext : public testing::Test {
public:
  static void SetUpTestCase() { oc_runtime_init(); }

  static void TearDownTestCase() { oc_runtime_shutdown(); }
};

#ifndef OC_SECURITY

// insecure build to avoid pstat checks, which need valid device indexes
TEST_F(TestCloudContext, Init)
{
#ifdef OC_DYNAMIC_ALLOCATION
  size_t num_devices = 3;
#else  /* !OC_DYNAMIC_ALLOCATION */
  size_t num_devices = OC_MAX_NUM_DEVICES;
#endif /* OC_DYNAMIC_ALLOCATION */

  std::vector<oc_cloud_context_t *> contexts{};
  for (size_t i = 0; i < num_devices; ++i) {
    oc_cloud_context_t *ctx = cloud_context_init(i);
    ASSERT_NE(nullptr, ctx);
    EXPECT_EQ(i, oc_cloud_get_device(ctx));
    contexts.push_back(ctx);
  }

#ifndef OC_DYNAMIC_ALLOCATION
  oc_cloud_context_t *ctx = cloud_context_init(num_devices);
  ASSERT_EQ(nullptr, ctx);
#endif /* !OC_DYNAMIC_ALLOCATION */

  for (auto ctx : contexts) {
    cloud_context_deinit(ctx);
  }
}

#endif /* !OC_SECURITY */

TEST_F(TestCloudContext, Deinit)
{
  cloud_context_deinit(nullptr);
}

TEST_F(TestCloudContext, OnStatusChange)
{
  oc_cloud_context_t ctx{};

  auto onStatusChange = oc_cloud_get_on_status_change(&ctx);
  EXPECT_EQ(nullptr, onStatusChange.cb);
  EXPECT_EQ(nullptr, onStatusChange.user_data);

  auto onChangeCb = [](oc_cloud_context_t *, oc_cloud_status_t, void *) {
    // no-op
  };
  oc_cloud_set_on_status_change(&ctx, { onChangeCb, &ctx });

  onStatusChange = oc_cloud_get_on_status_change(&ctx);
  EXPECT_EQ(onChangeCb, onStatusChange.cb);
  EXPECT_EQ(&ctx, onStatusChange.user_data);
}

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
  EXPECT_STREQ("apn",
               oc_string(*oc_cloud_get_authorization_provider_name(&ctx)));
}

TEST_F(TestCloudContext, GetAccessToken)
{
  oc_cloud_context_t ctx{};
  ctx.store.access_token = OC_STRING_LOCAL("access_token");
  EXPECT_STREQ("access_token", oc_string(*oc_cloud_get_access_token(&ctx)));
}

TEST_F(TestCloudContext, GetRefreshToken)
{
  oc_cloud_context_t ctx{};
  ctx.store.refresh_token = OC_STRING_LOCAL("refresh_token");
  EXPECT_STREQ("refresh_token", oc_string(*oc_cloud_get_refresh_token(&ctx)));
}

TEST_F(TestCloudContext, GetUid)
{
  oc_cloud_context_t ctx{};
  ctx.store.uid = OC_STRING_LOCAL("uid");
  EXPECT_STREQ("uid", oc_string(*oc_cloud_get_user_id(&ctx)));
}

TEST_F(TestCloudContext, GetStatus)
{
  oc_cloud_context_t ctx{};
  ctx.store.status =
    OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED | OC_CLOUD_TOKEN_EXPIRY;
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED | OC_CLOUD_TOKEN_EXPIRY,
            oc_cloud_get_status(&ctx));
}

TEST_F(TestCloudContext, GetProvisioningStatus)
{
  oc_cloud_context_t ctx{};
  ctx.store.cps = OC_CPS_DEREGISTERING;
  EXPECT_EQ(OC_CPS_DEREGISTERING, oc_cloud_get_provisioning_status(&ctx));
}

TEST_F(TestCloudContext, GetCisAndSid)
{
  oc_cloud_context_t ctx{};

  oc_cloud_store_initialize(&ctx.store, nullptr, nullptr);
  auto cis = OC_STRING_VIEW("cis");
  oc_uuid_t sid;
  oc_gen_uuid(&sid);
  ASSERT_TRUE(oc_endpoint_addresses_reinit(
    &ctx.store.ci_servers, oc_endpoint_address_make_view_with_uuid(cis, sid)));
  const auto *ctx_cis = oc_cloud_get_server_uri(&ctx);
  ASSERT_NE(nullptr, ctx_cis);
  EXPECT_STREQ(cis.data, oc_string(*ctx_cis));
  EXPECT_TRUE(oc_uuid_is_equal(sid, *oc_cloud_get_server_id(&ctx)));

  oc_cloud_store_deinitialize(&ctx.store);
}

TEST_F(TestCloudContext, oc_cloud_get_server)
{
  oc_cloud_context_t ctx{};
  oc_endpoint_t *ep = oc_new_endpoint();
  ctx.cloud_ep = ep;
  ctx.cloud_ep_state = OC_SESSION_CONNECTED;
  EXPECT_EQ(ep, oc_cloud_get_server(&ctx));
  EXPECT_EQ(OC_SESSION_CONNECTED, oc_cloud_get_server_session_state(&ctx));

  oc_free_endpoint(ep);
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
