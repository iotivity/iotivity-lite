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

#include "api/plgd/device-provisioning-client/plgd_dps_manager_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_cloud_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "api/cloud/oc_cloud_context_internal.h"
#include "oc_cloud.h"
#include "oc_uuid.h"
#include "port/oc_random.h"
#include "tests/gtest/Device.h"

#include "gtest/gtest.h"

#include <string>

static constexpr size_t kDeviceID = 0;

class DPSCloudTest : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }
  static void TearDownTestCase() { oc_random_destroy(); }
};

TEST_F(DPSCloudTest, CloudObserverOnServerChange)
{
  oc_uuid_t nilUUID{};
  plgd_cloud_status_observer_t obs{};
  obs.last_endpoint_uuid = nilUUID;
  EXPECT_FALSE(dps_cloud_observer_copy_endpoint_uuid(&obs, nullptr));
  EXPECT_TRUE(oc_uuid_is_empty(obs.last_endpoint_uuid));
  EXPECT_FALSE(dps_cloud_observer_copy_endpoint_uuid(&obs, &nilUUID));
  EXPECT_TRUE(oc_uuid_is_empty(obs.last_endpoint_uuid));

  oc_uuid_t uuid;
  oc_gen_uuid(&uuid);
  EXPECT_TRUE(dps_cloud_observer_copy_endpoint_uuid(&obs, &uuid));
  EXPECT_TRUE(oc_uuid_is_equal(obs.last_endpoint_uuid, uuid));
}

class DPSCloudWithServerTest : public testing::Test {
public:
  static void SetUpTestCase()
  {
    EXPECT_TRUE(oc::TestDevice::StartServer());
    plgd_dps_init();
  }

  static void TearDownTestCase()
  {
    plgd_dps_shutdown();
    oc::TestDevice::StopServer();
  }
};

TEST_F(DPSCloudWithServerTest, CloudObserverOnServerChange)
{
  plgd_dps_context_t ctx{};
  dps_cloud_observer_init(&ctx.cloud_observer);

  auto cloud_ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, cloud_ctx);

  // no remaining changes
  ctx.device = cloud_ctx->device;
  ASSERT_TRUE(dps_cloud_observer_load(&ctx.cloud_observer, cloud_ctx));
  ASSERT_EQ(0, ctx.cloud_observer.remaining_endpoint_changes);
  dps_cloud_observer_on_server_change(&ctx);

  std::string_view uri{ "/uri/1" };
  oc_uuid_t uuid{
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
  };
  auto *ep1 =
    oc_cloud_add_server_address(cloud_ctx, uri.data(), uri.length(), uuid);
  ASSERT_NE(nullptr, ep1);
  ASSERT_TRUE(dps_cloud_observer_load(&ctx.cloud_observer, cloud_ctx));
  ASSERT_EQ(1, ctx.cloud_observer.remaining_endpoint_changes);
  // invalid device
  ctx.device = 42;
  dps_cloud_observer_on_server_change(&ctx);
  EXPECT_EQ(1, ctx.cloud_observer.remaining_endpoint_changes);

  // no selected endpoint
  ctx.device = cloud_ctx->device;
  oc_endpoint_addresses_clear(&cloud_ctx->store.ci_servers);
  dps_cloud_observer_on_server_change(&ctx);
  EXPECT_EQ(1, ctx.cloud_observer.remaining_endpoint_changes);
  oc_cloud_context_clear(cloud_ctx, false);

  // rotate back to initial endpoint
  ep1 = oc_cloud_add_server_address(cloud_ctx, uri.data(), uri.length(), uuid);
  ASSERT_NE(nullptr, ep1);
  ASSERT_TRUE(dps_cloud_observer_load(&ctx.cloud_observer, cloud_ctx));
  ASSERT_EQ(1, ctx.cloud_observer.remaining_endpoint_changes);
  const auto *selected = oc_cloud_selected_server_address(cloud_ctx);
  ASSERT_TRUE(oc_string_is_equal(&ctx.cloud_observer.initial_endpoint_uri,
                                 oc_endpoint_address_uri(selected)));
  dps_cloud_observer_on_server_change(&ctx);
  EXPECT_EQ(0, ctx.cloud_observer.remaining_endpoint_changes);

  // select the second endpoint with different uuid
  ASSERT_TRUE(dps_cloud_observer_load(&ctx.cloud_observer, cloud_ctx));
  ASSERT_EQ(1, ctx.cloud_observer.remaining_endpoint_changes);
  ASSERT_TRUE(oc_cloud_select_server_address(cloud_ctx, ep1));
  selected = oc_cloud_selected_server_address(cloud_ctx);
  ASSERT_FALSE(oc_string_is_equal(&ctx.cloud_observer.initial_endpoint_uri,
                                  oc_endpoint_address_uri(selected)));
  ASSERT_FALSE(oc_uuid_is_equal(ctx.cloud_observer.last_endpoint_uuid,
                                *oc_endpoint_address_uuid(selected)));
  dps_cloud_observer_on_server_change(&ctx);
  EXPECT_EQ(0, ctx.cloud_observer.remaining_endpoint_changes);
  oc_cloud_context_clear(cloud_ctx, false);

  // tselect the second endpoint with the same (empty) uuid
  ep1 = oc_cloud_add_server_address(cloud_ctx, uri.data(), uri.length(), {});
  ASSERT_TRUE(dps_cloud_observer_load(&ctx.cloud_observer, cloud_ctx));
  ASSERT_EQ(1, ctx.cloud_observer.remaining_endpoint_changes);
  ASSERT_TRUE(oc_cloud_select_server_address(cloud_ctx, ep1));
  selected = oc_cloud_selected_server_address(cloud_ctx);
  ASSERT_FALSE(oc_string_is_equal(&ctx.cloud_observer.initial_endpoint_uri,
                                  oc_endpoint_address_uri(selected)));
  ASSERT_TRUE(oc_uuid_is_equal(ctx.cloud_observer.last_endpoint_uuid,
                               *oc_endpoint_address_uuid(selected)));
  dps_cloud_observer_on_server_change(&ctx);
  EXPECT_EQ(0, ctx.cloud_observer.remaining_endpoint_changes);

  dps_manager_stop(&ctx);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
