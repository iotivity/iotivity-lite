/******************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "gtest/gtest.h"

#ifdef OC_SOFTWARE_UPDATE

#include "api/oc_swupdate_internal.h"
#include "oc_api.h"

class TestSWUpdate : public testing::Test {
protected:
  void SetUp() override { oc_swupdate_init(); }
  void TearDown() override { oc_swupdate_free(); }

  static void SetUpTestCase()
  {
    s_handler.init = &TestSWUpdate::appInit;
    s_handler.signal_event_loop = &TestSWUpdate::signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);
  }

  static void TearDownTestCase() { oc_main_shutdown(); }

private:
  static oc_handler_t s_handler;
  static oc_endpoint_t s_endpoint;

  static void onPostResponse(oc_client_response_t *) {}

  static int appInit(void)
  {
    if (oc_init_platform("SWUpdateTest", nullptr, nullptr) != 0) {
      return -1;
    }
    if (oc_add_device("/oic/d", "oic.d.test", "SWU Test", "ocf.1.0.0",
                      "ocf.res.1.0.0", nullptr, nullptr) != 0) {
      return -1;
    }
    return 0;
  }

  static void signalEventLoop(void)
  {
    // no-op for tests
  }
};
oc_handler_t TestSWUpdate::s_handler;

TEST_F(TestSWUpdate, Init)
{
  EXPECT_NE(nullptr, oc_swupdate_get_context(0));
}

TEST(SWUpdate, ConvertAction)
{
  EXPECT_EQ(nullptr, oc_swupdate_action_to_str((oc_swupdate_action_t)-1));
  EXPECT_EQ(-1, oc_swupdate_action_from_str("invalid value"));

  EXPECT_EQ(OC_SWUPDATE_IDLE, oc_swupdate_action_from_str(
                                oc_swupdate_action_to_str(OC_SWUPDATE_IDLE)));
  EXPECT_EQ(OC_SWUPDATE_ISAC, oc_swupdate_action_from_str(
                                oc_swupdate_action_to_str(OC_SWUPDATE_ISAC)));
  EXPECT_EQ(OC_SWUPDATE_ISVV, oc_swupdate_action_from_str(
                                oc_swupdate_action_to_str(OC_SWUPDATE_ISVV)));
  EXPECT_EQ(OC_SWUPDATE_UPGRADE,
            oc_swupdate_action_from_str(
              oc_swupdate_action_to_str(OC_SWUPDATE_UPGRADE)));
}

TEST(SWUpdate, ConvertState)
{
  EXPECT_EQ(nullptr, oc_swupdate_state_to_str((oc_swupdate_state_t)-1));
  EXPECT_EQ(-1, oc_swupdate_state_from_str("invalid value"));

  EXPECT_EQ(OC_SWUPDATE_STATE_IDLE,
            oc_swupdate_state_from_str(
              oc_swupdate_state_to_str(OC_SWUPDATE_STATE_IDLE)));
  EXPECT_EQ(OC_SWUPDATE_STATE_NSA,
            oc_swupdate_state_from_str(
              oc_swupdate_state_to_str(OC_SWUPDATE_STATE_NSA)));
  EXPECT_EQ(OC_SWUPDATE_STATE_SVV,
            oc_swupdate_state_from_str(
              oc_swupdate_state_to_str(OC_SWUPDATE_STATE_SVV)));
  EXPECT_EQ(OC_SWUPDATE_STATE_SVA,
            oc_swupdate_state_from_str(
              oc_swupdate_state_to_str(OC_SWUPDATE_STATE_SVA)));
  EXPECT_EQ(OC_SWUPDATE_STATE_UPGRADING,
            oc_swupdate_state_from_str(
              oc_swupdate_state_to_str(OC_SWUPDATE_STATE_UPGRADING)));
}

#endif /* OC_SOFTWARE_UPDATE */
