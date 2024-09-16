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

#include "api/oc_runtime_internal.h"
#include "api/oc_server_api_internal.h"
#include "api/cloud/oc_cloud_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_pki_internal.h"
#include "oc_rep.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"

#include "gtest/gtest.h"

#include <chrono>
#include <limits>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID = 0;

class TestPKI : public testing::Test {
public:
  void SetUp() override { oc_runtime_init(); }
  void TearDown() override { oc_runtime_shutdown(); }
};

TEST_F(TestPKI, SendCSR_FailInvalidDeviceID)
{
  plgd_dps_context_t ctx{};
  ctx.device = 42;

  EXPECT_FALSE(dps_pki_send_csr(&ctx, [](oc_client_response_t *) {
    // no-op
  }));
}

TEST_F(TestPKI, ReplaceCertificates_FailInvalidDeviceID)
{
  oc_rep_t emptyRep{};
  oc_endpoint_t emptyEp{};
  EXPECT_FALSE(dps_pki_replace_certificates(42, &emptyRep, &emptyEp));
}

TEST_F(TestPKI, CalculateRenewCertificatesInterval)
{
  dps_pki_configuration_t cfg{
    /*.expiring_limit =*/10,
  };
  oc_clock_time_t valid_to = oc_clock_seconds_v1();
  EXPECT_EQ(0, dps_pki_calculate_renew_certificates_interval(cfg, valid_to));

  // expiring within 1 minute
  valid_to = oc_clock_seconds_v1() + 30;
  EXPECT_EQ(std::chrono::duration_cast<std::chrono::milliseconds>(10s).count(),
            dps_pki_calculate_renew_certificates_interval(cfg, valid_to));

  // expiring within 3 minutes
  valid_to = oc_clock_seconds_v1() + 120;
  EXPECT_EQ(std::chrono::duration_cast<std::chrono::milliseconds>(1min).count(),
            dps_pki_calculate_renew_certificates_interval(cfg, valid_to));

  // expiring within 6 minutes
  valid_to = oc_clock_seconds_v1() + 300;
  EXPECT_EQ(std::chrono::duration_cast<std::chrono::milliseconds>(2min).count(),
            dps_pki_calculate_renew_certificates_interval(cfg, valid_to));

  // longer than 6 minutes
  valid_to = oc_clock_seconds_v1() + 600;
  EXPECT_GT(std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::seconds(600))
              .count(),
            dps_pki_calculate_renew_certificates_interval(cfg, valid_to));
}

class TestPKIWithDevice : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void TearDown() override
  {
    oc::TestDevice::Reset();
    oc::TestDevice::CloseSessions(kDeviceID);
    // wait for asynchronous closing of sessions to finish
    oc::TestDevice::PoolEventsMsV1(10ms);
    oc::TestDevice::ClearSystemTime();
  }
};

TEST_F(TestPKIWithDevice, ReplaceCertificates_FailInvalidRep)
{
  oc_endpoint_t emptyEp{};
  std::string uuid = "00000000-0000-0000-0000-000000000001";

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, rowneruuid, uuid.c_str(), uuid.length());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_FALSE(dps_pki_replace_certificates(kDeviceID, rep.get(), &emptyEp));
}

TEST_F(TestPKIWithDevice, TryRenewCertificates)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  plgd_dps_context_t ctx{};
  ctx.endpoint = &ep;
  ctx.device = kDeviceID;
  EXPECT_TRUE(dps_pki_try_renew_certificates(&ctx));

  auto timeout = 10ms;
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  plgd_dps_manager_stop(&ctx);
}

TEST_F(TestPKIWithDevice, RenewCertificates)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  plgd_dps_context_t ctx{};
  ctx.endpoint = &ep;
  ctx.device = kDeviceID;
  ctx.status = PLGD_DPS_PROVISIONED_MASK | PLGD_DPS_CLOUD_STARTED;

  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, cloud_ctx);
  cloud_ctx->cloud_manager = true;

  oc_reset_delayed_callback(&ctx, dps_pki_renew_certificates_async, 0);

  auto timeout = 10ms;
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  plgd_dps_manager_stop(&ctx);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
