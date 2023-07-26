/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "api/oc_query_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_api.h"
#include "oc_ri.h"

#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

class TestQuery : public testing::Test {};

TEST_F(TestQuery, RIGetQueryValueEmpty_N)
{
  const char *value;
  int ret = oc_ri_get_query_value(nullptr, 0, "key", &value);
  EXPECT_EQ(-1, ret) << "N input NULL "
                     << "key";

  ret = oc_ri_get_query_value("", 0, "key", &value);
  EXPECT_EQ(-1, ret) << "N input \"\" "
                     << "key";
}

TEST_F(TestQuery, RIGetQueryValue_P)
{
  using string_pair = std::pair<std::string, std::string>;
  std::vector<string_pair> inputs = {
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
  for (const auto &[query, exp] : inputs) {
    int ret = oc_ri_get_query_value(query.c_str(), query.length(), "key", &v);
    EXPECT_EQ(exp.length(), ret) << "P input " << query << " "
                                 << "key";
    if (ret > 0) {
      std::string value(v, ret);
      EXPECT_STREQ(exp.c_str(), value.c_str())
        << "P input " << query << " "
        << "value " << exp << " vs " << value;
    }
  }

  for (const auto &[query, _] : inputs) {
    int ret =
      oc_ri_get_query_value(query.c_str(), query.length(), "key2", nullptr);
    EXPECT_EQ(-1, ret) << "N input " << query << " "
                       << "key2";
  }
}

TEST_F(TestQuery, RIQueryExists_P)
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

TEST_F(TestQuery, GetValue_F)
{
  EXPECT_EQ(-1, oc_get_query_value(nullptr, "", nullptr));
}

TEST_F(TestQuery, GetValueEmpty_N)
{
  const char *value;
  oc_request_t request;
  request.query = nullptr;
  request.query_len = 0;
  int ret = oc_get_query_value(&request, "key", &value);
  EXPECT_EQ(-1, ret) << "N input NULL "
                     << "key";

  request.query = "";
  ret = oc_get_query_value(&request, "key", &value);
  EXPECT_EQ(-1, ret) << "N input \"\" "
                     << "key";
}

TEST_F(TestQuery, Exists_F)
{
  EXPECT_EQ(-1, oc_query_value_exists(nullptr, ""));
}

TEST_F(TestQuery, Exists_P)
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
    oc_request_t request;
    request.query = input.c_str();
    request.query_len = input.length();
    ret = oc_query_value_exists(&request, "key");
    EXPECT_EQ(1, ret) << "P input " << input << " "
                      << "key";
  }

  inputs.emplace_back("");
  for (const auto &input : inputs) {
    oc_request_t request;
    request.query = input.c_str();
    request.query_len = input.length();
    ret = oc_query_value_exists(&request, "key2");
    EXPECT_EQ(-1, ret) << "N input " << input << " "
                       << "key2";
  }
}

#ifdef OC_SERVER

TEST_F(TestQuery, EncodeInterface_F)
{
  auto iview = oc_query_encode_interface(static_cast<oc_interface_mask_t>(-1));
  EXPECT_EQ(nullptr, iview.data);
}

TEST_F(TestQuery, EncodeInterface_P)
{
  std::vector<oc_interface_mask_t> ifaces = {
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

  std::vector<std::string> iface_strs = {
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

  for (size_t i = 0; i < ifaces.size(); ++i) {
    auto iview = oc_query_encode_interface(ifaces[i]);
    ASSERT_NE(nullptr, iview.data);
    std::string exp = "if=" + iface_strs[i];
    EXPECT_STREQ(exp.c_str(), iview.data);
  }
}

#endif /* OC_SERVER */
