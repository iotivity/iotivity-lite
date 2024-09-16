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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_manager_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_provision_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_security_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_tag_internal.h"
#include "oc_acl.h"
#include "oc_cred.h"
#include "plgd_dps_test.h"
#include "plgd/plgd_time.h"
#include "tests/gtest/Device.h"

#include "gtest/gtest.h"

#include <array>

static constexpr size_t kDeviceID = 0;

using namespace std::chrono_literals;

class TestDPSManager : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

TEST_F(TestDPSManager, ChangeEndpointOnRetry)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  // set retry loop -> single attempt
  std::array<uint8_t, 1> arr{ 1 }; // 1s
  EXPECT_TRUE(
    plgd_dps_set_retry_configuration(ctx.get(), arr.data(), arr.size()));

  // set multiple DPS endpoints
  std::string ep1_uri = "coap://127.0.0.1:12345";
  ASSERT_NE(nullptr,
            plgd_dps_add_endpoint_address(ctx.get(), ep1_uri.c_str(),
                                          ep1_uri.length(), nullptr, 0));
  std::string ep2_uri = "coap+tcp://127.0.0.1:12345";
  ASSERT_NE(nullptr,
            plgd_dps_add_endpoint_address(ctx.get(), ep2_uri.c_str(),
                                          ep2_uri.length(), nullptr, 0));
  ASSERT_TRUE(oc_endpoint_addresses_is_selected(
    &ctx->store.endpoints, oc_string_view(ep1_uri.c_str(), ep1_uri.length())));

  // after one retry loop finishes, the endpoint should be changed
  // delay = [0s..0,5s] + timeout = 1s + random jitter ([0s..0,5s]) == around 2s
  // should be enough
  dps_provisioning_start(ctx.get());
  bool selected = false;
  for (int i = 0; i < 16; ++i) {
    oc::TestDevice::PoolEventsMsV1(200ms);
    selected = oc_endpoint_addresses_is_selected(
      &ctx->store.endpoints, oc_string_view(ep2_uri.c_str(), ep2_uri.length()));
    if (selected) {
      break;
    }
  }
  EXPECT_TRUE(selected);
}

TEST_F(TestDPSManager, StartAlreadyStarted)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int mfg_credid =
    dps::addIdentityCertificate(kDeviceID, identKey, rootKey, true);
  ASSERT_LT(0, mfg_credid);

  plgd_dps_context_t ctx{};
  dps_context_init(&ctx, kDeviceID);
  ctx.skip_verify = true;
  dps_context_list_add(&ctx);

  std::string ep_uri = "coap://127.0.0.1:12345";
  ASSERT_NE(nullptr, plgd_dps_add_endpoint_address(
                       &ctx, ep_uri.c_str(), ep_uri.length(), nullptr, 0));

  EXPECT_EQ(0, plgd_dps_manager_start(&ctx));
  EXPECT_EQ(0, plgd_dps_manager_start(&ctx));

  plgd_dps_manager_stop(&ctx);
  dps_context_list_remove(&ctx);
  dps_context_deinit(&ctx);
  ASSERT_TRUE(oc_sec_remove_cred_by_credid(mfg_credid, kDeviceID));
}

TEST_F(TestDPSManager, GetProvisionAndCloudObserverFlags)
{
  plgd_time_set_time(oc_clock_time());

  plgd_dps_context_t ctx{};
  dps_context_init(&ctx, kDeviceID);
  auto pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  uint32_t provision_flags = PLGD_DPS_HAS_TIME;
  uint8_t cloud_observer_status = 0;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

  oc_uuid_t owner;
  oc_gen_uuid(&owner);
  ASSERT_TRUE(dps_set_owner(&ctx, &owner));
  pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  provision_flags |= PLGD_DPS_HAS_OWNER;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

  auto *cloud_ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, cloud_ctx);
  std::string at{ "access_token" };
  oc_new_string(&cloud_ctx->store.access_token, at.c_str(), at.length());
  pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  provision_flags |= PLGD_DPS_HAS_CLOUD;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

#ifdef OC_DYNAMIC_ALLOCATION
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int root_credid = dps::addRootCertificate(kDeviceID, rootKey, false, true);
  ASSERT_LT(0, root_credid);
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int credid =
    dps::addIdentityCertificate(kDeviceID, identKey, rootKey, false, true);
  ASSERT_LT(0, credid);
  pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  provision_flags |= PLGD_DPS_HAS_CREDENTIALS;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

  ASSERT_TRUE(oc_sec_acl_add_bootstrap_acl(kDeviceID));
  auto *ace = (oc_sec_ace_t *)oc_list_head(oc_sec_get_acl(0)->subjects);
  EXPECT_NE(nullptr, ace);
  oc_set_string(&ace->tag, DPS_TAG, DPS_TAG_LEN);
  pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  provision_flags |= PLGD_DPS_HAS_ACLS;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

  cloud_ctx->store.status = OC_CLOUD_REGISTERED;
  pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  cloud_observer_status |= OC_CLOUD_REGISTERED;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

  cloud_ctx->cloud_manager = true;
  pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  provision_flags |= PLGD_DPS_CLOUD_STARTED;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

  cloud_ctx->store.status |= OC_CLOUD_LOGGED_IN;
  pof = dps_get_provision_and_cloud_observer_flags(&ctx);
  cloud_observer_status |= OC_CLOUD_LOGGED_IN;
  EXPECT_EQ(provision_flags, pof.provision_flags);
  EXPECT_EQ(cloud_observer_status, pof.cloud_observer_status);

  ASSERT_TRUE(oc_sec_remove_cred_by_credid(credid, kDeviceID));
  ASSERT_TRUE(oc_sec_remove_cred_by_credid(root_credid, kDeviceID));
#endif /* OC_DYNAMIC_ALLOCATION */

  dps_context_deinit(&ctx);
  plgd_time_set_time(0);
  plgd_time_set_status(PLGD_TIME_STATUS_IN_SYNC);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
