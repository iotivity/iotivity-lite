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

#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_provision_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_provision_owner_internal.h"
#include "oc_api.h"
#include "oc_rep.h"
#include "security/oc_pstat_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"

#include "gtest/gtest.h"

using namespace std::chrono_literals;

static constexpr size_t kDeviceID = 0;

class TestProvisionOwnerWithDevice : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void SetUp() override
  {
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    ASSERT_NE(nullptr, pstat);
    pstat->s = OC_DOS_RFNOP;
  }

  void TearDown() override
  {
    oc::TestDevice::Reset();
    oc::TestDevice::CloseSessions(kDeviceID);
    // wait for asynchronous closing of sessions to finish
    oc::TestDevice::PoolEventsMsV1(10ms);
    oc::TestDevice::ClearSystemTime();
  }
};

TEST_F(TestProvisionOwnerWithDevice, GetOwner_FailInvalidDOSState)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  plgd_dps_context_t ctx{};
  ctx.device = kDeviceID;
  EXPECT_FALSE(dps_get_owner(&ctx));

  pstat->s = OC_DOS_RFNOP;
}

TEST_F(TestProvisionOwnerWithDevice, GetOwner_OwnerAlreadySet)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  plgd_dps_context_t ctx{};
  ctx.endpoint = &ep;
  ctx.status = PLGD_DPS_HAS_OWNER;
  EXPECT_TRUE(dps_get_owner(&ctx));

  auto timeout = 10ms;
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  oc_has_delayed_callback(nullptr, dps_provision_next_step_async, true);
}

TEST_F(TestProvisionOwnerWithDevice, GetOwner_InvalidStatus)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  plgd_dps_context_t ctx{};
  ctx.endpoint = &ep;
  ctx.status = PLGD_DPS_INITIALIZED;
  EXPECT_TRUE(dps_get_owner(&ctx));

  auto timeout = 10ms;
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_EQ(PLGD_DPS_INITIALIZED | PLGD_DPS_GET_OWNER | PLGD_DPS_FAILURE,
            ctx.status);
  EXPECT_EQ(PLGD_DPS_ERROR_GET_OWNER, ctx.last_error);
}

TEST_F(TestProvisionOwnerWithDevice, GetOwner_InvalidResponse)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  plgd_dps_context_t ctx{};
  ctx.endpoint = &ep;
  ctx.status = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME;
  EXPECT_TRUE(dps_get_owner(&ctx));

  auto timeout = 10ms;
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_EQ(PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME | PLGD_DPS_GET_OWNER |
              PLGD_DPS_FAILURE,
            ctx.status);
  EXPECT_EQ(PLGD_DPS_ERROR_RESPONSE, ctx.last_error);
}

TEST_F(TestProvisionOwnerWithDevice, HandleGetOwnerResponse_Fail)
{
  oc_client_response_t response{};
  // owner property not set
  EXPECT_EQ(-1, dps_handle_get_owner_response(&response));

  // unexpected property
  std::string uuid = "00000000-0000-0000-0000-000000000001";

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, rowneruuid, uuid.c_str(), uuid.length());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  response.payload = rep.get();
  EXPECT_EQ(-1, dps_handle_get_owner_response(&response));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
