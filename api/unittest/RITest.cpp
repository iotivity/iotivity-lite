/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
 *           2021 CASCODA LTD        All Rights Reserved.
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

#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "port/oc_network_event_handler_internal.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

class TestOcRi : public testing::Test {
protected:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
  }
  void TearDown() override
  {
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
};

TEST_F(TestOcRi, GetInterfaceMask_P)
{
  EXPECT_EQ(0, oc_ri_get_interface_mask("", 0));

  std::vector<oc_interface_mask_t> all_interfaces{
    OC_IF_BASELINE,
    OC_IF_LL,
    OC_IF_B,
    OC_IF_R,
    OC_IF_RW,
    OC_IF_A,
    OC_IF_S,
    OC_IF_CREATE,
    OC_IF_W,
    OC_IF_STARTUP,
    OC_IF_STARTUP_REVERT,
  };
  std::vector<std::string> all_interface_strs{
    OC_IF_BASELINE_STR,
    OC_IF_LL_STR,
    OC_IF_B_STR,
    OC_IF_R_STR,
    OC_IF_RW_STR,
    OC_IF_A_STR,
    OC_IF_S_STR,
    OC_IF_CREATE_STR,
    OC_IF_W_STR,
    OC_IF_STARTUP_STR,
    OC_IF_STARTUP_REVERT_STR,
  };
  ASSERT_EQ(all_interfaces.size(), all_interface_strs.size());

  for (size_t i = 0; i < all_interface_strs.size(); ++i) {
    oc_interface_mask_t ifm = oc_ri_get_interface_mask(
      all_interface_strs[i].c_str(), all_interface_strs[i].length());
    EXPECT_EQ(all_interfaces[i], ifm);
  }
}

static oc_event_callback_retval_t
test_timed_callback(void *data)
{
  (void)data;
  return OC_EVENT_DONE;
}

TEST_F(TestOcRi, RiTimedCallbacks_P)
{
  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
  int data;
  oc_ri_add_timed_event_callback_seconds(&data, test_timed_callback, 0);

  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, false));
  EXPECT_TRUE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
  EXPECT_TRUE(
    oc_ri_has_timed_event_callback(&data, test_timed_callback, false));

  oc_ri_remove_timed_event_callback(&data, test_timed_callback);
  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
}

TEST_F(TestOcRi, RiTimedCallbacksFilter_P)
{
  struct thing_t
  {
    int value;
  };
  thing_t a{ 1 };
  thing_t b = a;
  oc_ri_add_timed_event_callback_seconds(&a, test_timed_callback, 0);
  oc_ri_remove_timed_event_callback(&b, test_timed_callback);
  // comparison by pointer address will fail to match the data, so the callback
  // won't be removed
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&a, test_timed_callback, false));

  auto match_by_value_filter = [](const void *cb_data,
                                  const void *filter_data) {
    const auto *first = static_cast<const thing_t *>(cb_data);
    const auto *second = static_cast<const thing_t *>(filter_data);
    return first->value == second->value;
  };
  oc_ri_remove_timed_event_callback_by_filter(
    test_timed_callback, match_by_value_filter, &b, false, nullptr);
  // matching by value removes the callback
  EXPECT_FALSE(oc_ri_has_timed_event_callback(&a, test_timed_callback, false));
}

TEST_F(TestOcRi, RiTimedCallbacksFilterMatchAll_P)
{
  struct thing_t
  {
    int value;
  };
  thing_t a{ 1 };
  thing_t b = a;
  thing_t c = a;
  oc_ri_add_timed_event_callback_seconds(&a, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(&b, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(&c, test_timed_callback, 0);

  auto match_by_value_filter = [](const void *cb_data,
                                  const void *filter_data) {
    const auto *first = static_cast<const thing_t *>(cb_data);
    const auto *second = static_cast<const thing_t *>(filter_data);
    return first->value == second->value;
  };
  oc_ri_remove_timed_event_callback_by_filter(
    test_timed_callback, match_by_value_filter, &a, true, nullptr);

  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
}

TEST_F(TestOcRi, RiTimedCallbacksFilterDealloc_P)
{
  struct thing_t
  {
    int value;
  };
  thing_t m{ 1 };
  auto *a = new thing_t{ m };
  auto *b = new thing_t{ m };
  auto *c = new thing_t{ m };

  oc_ri_add_timed_event_callback_seconds(a, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(b, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(c, test_timed_callback, 0);

  auto match_by_value_filter = [](const void *cb_data,
                                  const void *filter_data) {
    const auto *first = static_cast<const thing_t *>(cb_data);
    const auto *second = static_cast<const thing_t *>(filter_data);
    return first->value == second->value;
  };

  auto free_thing = [](void *data) {
    auto *t = static_cast<thing_t *>(data);
    delete t;
  };

  oc_ri_remove_timed_event_callback_by_filter(
    test_timed_callback, match_by_value_filter, &m, true, free_thing);

  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
}
