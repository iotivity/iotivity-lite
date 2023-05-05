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
#include "port/oc_network_event_handler_internal.h"

#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

class TestOcRi : public testing::Test {
protected:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_ri_init();
  }
  void TearDown() override
  {
    oc_ri_shutdown();
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

TEST_F(TestOcRi, RIGetQueryValueEmpty_N)
{
  const char *value;
  int ret = oc_ri_get_query_value(nullptr, 0, "key", &value);
  EXPECT_EQ(-1, ret) << "N input NULL "
                     << "key";

  ret = oc_ri_get_query_value("", 0, "key", &value);
  EXPECT_EQ(-1, ret) << "N input \"\" "
                     << "key";
}

TEST_F(TestOcRi, RIGetQueryValue_P)
{
  std::map<std::string, std::string> inputs = {
    { "key", "" },
    { "key=1337", "1337" },
    { "data=1&key=22", "22" },
    { "key=333&data=3", "333" },
    { "x&key=42&data=3", "42" },
    { "y&x&key=5225&data=3", "5225" },
    { "y&x&key=6", "6" },
    { "y&x&key=777&y", "777" },
  };

  const char *v;
  for (const auto &input : inputs) {
    int ret = oc_ri_get_query_value(input.first.c_str(), input.first.length(),
                                    "key", &v);
    EXPECT_EQ(input.second.length(), ret) << "P input " << input.first << " "
                                          << "key";
    if (ret > 0) {
      std::string value(v, ret);
      EXPECT_STREQ(input.second.c_str(), value.c_str())
        << "P input " << input.first << " "
        << "value " << input.second << " vs " << value;
    }
  }

  for (const auto &input : inputs) {
    int ret = oc_ri_get_query_value(input.first.c_str(), input.first.length(),
                                    "key2", nullptr);
    EXPECT_EQ(-1, ret) << "N input " << input.first << " "
                       << "key2";
  }
}

TEST_F(TestOcRi, RIQueryExists_P)
{
  std::vector<std::string> inputs = { "key=1",
                                      "key",
                                      "data=1&key=2",
                                      "data=2&key",
                                      "key&data=3",
                                      "key=2&data=3",
                                      "x=1&key=2&data=3",
                                      "y=&key=2&data=3",
                                      "y=1&x&key=2&data=3",
                                      "y=1&x&key" };
  int ret;
  for (const auto &input : inputs) {
    ret = oc_ri_query_exists(input.c_str(), input.length(), "key");
    EXPECT_EQ(1, ret) << "P input " << input << " "
                      << "key";
  }

  inputs.emplace_back("");
  for (const auto &input : inputs) {
    ret = oc_ri_query_exists(input.c_str(), input.length(), "key2");
    EXPECT_EQ(-1, ret) << "N input " << input << " "
                       << "key2";
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
