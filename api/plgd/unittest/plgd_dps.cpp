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

#include "plgd_dps_test.h"

#include "api/plgd/device-provisioning-client/plgd_dps_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_security_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_uuid.h"

#include "gtest/gtest.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

static constexpr size_t kDeviceID = 0;

TEST(DPSApiTest, SetSkipVerify)
{
  auto ctx = dps::make_unique_context(kDeviceID);
  plgd_dps_set_skip_verify(ctx.get(), true);

  EXPECT_TRUE(plgd_dps_get_skip_verify(ctx.get()));
}

TEST(DPSApiTest, StatusToLogString)
{
  EXPECT_NE(0, dps_status_to_logstr(0, nullptr, 0));
  std::array<char, 1> tooSmall{};
  EXPECT_NE(0, dps_status_to_logstr(0, &tooSmall[0], tooSmall.size()));

  std::vector<char> buffer;
  buffer.resize(1024);
  EXPECT_EQ(0, dps_status_to_logstr(0, buffer.data(), buffer.capacity()));
  EXPECT_STREQ(kPlgdDpsStatusUninitialized, buffer.data());

  EXPECT_NE(0, dps_status_to_logstr(PLGD_DPS_PROVISIONED_ALL_FLAGS,
                                    &tooSmall[0], tooSmall.size()));

  EXPECT_EQ(0, dps_status_to_logstr(PLGD_DPS_PROVISIONED_ALL_FLAGS,
                                    buffer.data(), buffer.capacity()));
  std::unordered_set<std::string> flags{
    kPlgdDpsStatusInitialized,      kPlgdDpsStatusGetTime,
    kPlgdDpsStatusHasTime,          kPlgdDpsStatusGetOwner,
    kPlgdDpsStatusHasOwner,         kPlgdDpsStatusGetCredentials,
    kPlgdDpsStatusHasCredentials,   kPlgdDpsStatusGetAcls,
    kPlgdDpsStatusHasAcls,          kPlgdDpsStatusGetCloud,
    kPlgdDpsStatusHasCloud,         kPlgdDpsStatusProvisioned,
    kPlgdDpsStatusRenewCredentials, kPlgdDpsStatusTransientFailure,
    kPlgdDpsStatusFailure,
  };

  std::stringstream ss{ buffer.data() };
  std::string s;
  while (std::getline(ss, s, '|')) {
    EXPECT_EQ(1, flags.erase(s));
  }
  if (!flags.empty()) {
    std::cout << "missing flags: ";
    for (const auto &f : flags) {
      std::cout << f << " ";
    }
    std::cout << std::endl;
  }
  EXPECT_TRUE(flags.empty());
}

class TestDPSWithDevice : public testing::Test {
private:
  static int AppInit()
  {
    if (oc_init_platform("Samsung", nullptr, nullptr) != 0) {
      return -1;
    }
    if (oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                      "ocf.res.1.0.0", nullptr, nullptr) != 0) {
      return -1;
    }
    return 0;
  }

  static void SignalEventLoop()
  {
    // no-op for tests
  }

public:
  void SetUp() override
  {
    static oc_handler_t handler{};
    handler.init = AppInit;
    handler.signal_event_loop = SignalEventLoop;
    ASSERT_EQ(0, oc_main_init(&handler));
    ASSERT_EQ(kDeviceID, oc_core_get_num_devices() - 1);
    ASSERT_EQ(0, plgd_dps_init());
  }
  void TearDown() override
  {
    plgd_dps_shutdown();
    oc_main_shutdown();
  }
};

TEST_F(TestDPSWithDevice, GetContext)
{
  EXPECT_NE(nullptr, plgd_dps_get_context(kDeviceID));

  size_t invalidDeviceID = 42;
  EXPECT_EQ(nullptr, plgd_dps_get_context(invalidDeviceID));
}

TEST_F(TestDPSWithDevice, SetSelfOwned)
{
  auto ctx = dps::make_unique_context(kDeviceID);
  EXPECT_FALSE(dps_is_self_owned(ctx.get()));

  EXPECT_TRUE(dps_set_self_owned(ctx.get()));
  EXPECT_TRUE(dps_is_self_owned(ctx.get()));
  EXPECT_FALSE(dps_has_owner(ctx.get()));
}

TEST_F(TestDPSWithDevice, SetOwned)
{
  auto ctx = dps::make_unique_context(kDeviceID);
  EXPECT_FALSE(dps_has_owner(ctx.get()));

  oc_uuid_t owner;
  oc_gen_uuid(&owner);
  EXPECT_TRUE(dps_set_owner(ctx.get(), &owner));
  EXPECT_FALSE(dps_is_self_owned(ctx.get()));
  EXPECT_TRUE(dps_has_owner(ctx.get()));
}

TEST_F(TestDPSWithDevice, SetDpsResource)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  auto hasDpsResource = [](size_t device) {
    return oc_ri_get_app_resource_by_uri(PLGD_DPS_URI, sizeof(PLGD_DPS_URI) - 1,
                                         device) != nullptr;
  };
  EXPECT_FALSE(hasDpsResource(kDeviceID));

  plgd_dps_set_configuration_resource(ctx.get(), false);
  EXPECT_EQ(nullptr, ctx->conf);
  EXPECT_FALSE(hasDpsResource(kDeviceID));

  plgd_dps_set_configuration_resource(ctx.get(), true);
  EXPECT_NE(nullptr, ctx->conf);
  EXPECT_TRUE(hasDpsResource(kDeviceID));

  plgd_dps_set_configuration_resource(ctx.get(), false);
  EXPECT_EQ(nullptr, ctx->conf);
  EXPECT_FALSE(hasDpsResource(kDeviceID));
}

TEST_F(TestDPSWithDevice, SetIdentityChain)
{
  // invalid deviceID
  EXPECT_FALSE(dps_try_set_identity_chain(42));
}

TEST_F(TestDPSWithDevice, CloudAPI)
{
  EXPECT_FALSE(dps_cloud_is_started(kDeviceID));
  EXPECT_FALSE(dps_cloud_is_registered(kDeviceID));
  EXPECT_FALSE(dps_cloud_is_logged_in(kDeviceID));

  size_t invalidDeviceID = 42;
  EXPECT_FALSE(dps_cloud_is_started(invalidDeviceID));
  EXPECT_FALSE(dps_cloud_is_registered(invalidDeviceID));
  EXPECT_FALSE(dps_cloud_is_logged_in(invalidDeviceID));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
