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
#include "api/plgd/device-provisioning-client/plgd_dps_retry_internal.h"

#include "gtest/gtest.h"

#include "oc_api.h"

class TestDPSRetry : public testing::Test {
private:
  static void SignalEventLoop()
  {
    // no-op for tests
  }

  static int AppInit()
  {
    // no-op for tests
    return 0;
  }

public:
  void SetUp() override
  {
    static oc_handler_t handler{};
    handler.init = AppInit;
    handler.signal_event_loop = SignalEventLoop;
    EXPECT_EQ(0, oc_main_init(&handler));
  }

  void TearDown() override { oc_main_shutdown(); }
};

TEST_F(TestDPSRetry, IncrementRetry)
{
  plgd_dps_context_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  dps_retry_init(&ctx.retry);

  size_t size = dps_retry_size(&ctx.retry);
  EXPECT_LE(2, size);
  for (size_t i = 0; i < size - 1; i++) {
    dps_retry_increment(&ctx, PLGD_DPS_GET_CREDENTIALS);
    EXPECT_LT(0, ctx.retry.count);
  }
  dps_retry_increment(&ctx, PLGD_DPS_GET_CREDENTIALS);
  EXPECT_EQ(0, ctx.retry.count);
}

TEST_F(TestDPSRetry, ResetRetry)
{
  plgd_dps_context_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  dps_retry_init(&ctx.retry);
  EXPECT_EQ(0, ctx.retry.count);

  dps_retry_increment(&ctx, PLGD_DPS_GET_CREDENTIALS);
  EXPECT_LT(0, ctx.retry.count);

  dps_retry_reset(&ctx, PLGD_DPS_GET_CREDENTIALS);
  EXPECT_EQ(0, ctx.retry.count);

  // change default_cfg size 0 to invoke reset internally
  ctx.retry.default_cfg[0] = 0;
  dps_retry_increment(&ctx, PLGD_DPS_GET_CREDENTIALS);
  EXPECT_EQ(0, ctx.retry.count);
  EXPECT_EQ(DEFAULT_RESET_TIMEOUT, ctx.retry.schedule_action.timeout);
  EXPECT_LT(0, ctx.retry.schedule_action.delay);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
