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
#include "messaging/coap/options_internal.h"
#include "oc_api.h"
#include "oc_ri.h"

#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

class TestQuery : public testing::Test {};

TEST_F(TestQuery, RIGetQueryNthKeyValue_F)
{
  const char *k = nullptr;
  size_t klen = 0;
  EXPECT_EQ(-1, oc_ri_get_query_nth_key_value(nullptr, 0, &k, &klen, nullptr,
                                              nullptr, 1));
  EXPECT_EQ(nullptr, k);
  EXPECT_EQ(0, klen);

  EXPECT_EQ(
    -1, oc_ri_get_query_nth_key_value("", 0, &k, &klen, nullptr, nullptr, 1));
  EXPECT_EQ(nullptr, k);
  EXPECT_EQ(0, klen);

  std::string key = "key=";
  EXPECT_EQ(-1, oc_ri_get_query_nth_key_value(key.c_str(), key.length(), &k,
                                              &klen, nullptr, nullptr, 2));
  EXPECT_EQ(nullptr, k);
  EXPECT_EQ(0, klen);
}

TEST_F(TestQuery, RIGetQueryNthKeyValue_P)
{
  std::string key1 = "key1";
  std::string value1 = "value1";
  std::string query = key1 + "=" + value1;
  const char *k = nullptr;
  size_t klen = 0;
  EXPECT_EQ(query.length() + 1,
            oc_ri_get_query_nth_key_value(query.c_str(), query.length(), &k,
                                          &klen, nullptr, nullptr, 1));
  EXPECT_EQ(key1.length(), klen);
  EXPECT_EQ(0, memcmp(key1.c_str(), k, klen));

  for (int i = 1; i <= 3; ++i) {
    query = "";
    std::vector<std::string> keys{};
    std::vector<std::string> values{};
    for (int j = 0; j < i; ++j) {
      std::string key = "key" + std::to_string(j);
      std::string value = "value" + std::to_string(j);
      query += key + "=" + value;
      keys.emplace_back(key);
      values.emplace_back(value);
      if (j < i - 1) {
        query += "&";
      }
    }
    for (int j = 0; j < i; ++j) {
      k = nullptr;
      klen = 0;
      const char *v = nullptr;
      size_t vlen = 0;
      EXPECT_NE(-1, oc_ri_get_query_nth_key_value(query.c_str(), query.length(),
                                                  &k, &klen, &v, &vlen, j + 1));
      EXPECT_EQ(keys[j].length(), klen);
      EXPECT_EQ(0, memcmp(keys[j].c_str(), k, klen));
      EXPECT_EQ(values[j].length(), vlen);
      EXPECT_EQ(0, memcmp(values[j].c_str(), v, vlen));
    }
  }
}

TEST_F(TestQuery, RIGetQueryValue_F)
{
  const char *value = nullptr;
  int ret = oc_ri_get_query_value(nullptr, 0, "key", &value);
  EXPECT_EQ(-1, ret) << "N input NULL";
  EXPECT_EQ(nullptr, value);

  ret = oc_ri_get_query_value("", 0, "key", &value);
  EXPECT_EQ(-1, ret) << "N input \"\"";
  EXPECT_EQ(nullptr, value);

  std::string query = "key1=1";
  auto key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  ret =
    oc_ri_get_query_value(query.c_str(), query.length(), key.c_str(), &value);
  EXPECT_EQ(-1, ret) << "N input " << query << " " << key;
  EXPECT_EQ(nullptr, value);
}

TEST_F(TestQuery, RIGetQueryValueV1_F)
{
  std::string key1 = "key1";
  const char *value = nullptr;
  int ret =
    oc_ri_get_query_value_v1(nullptr, 0, key1.c_str(), key1.length(), &value);
  EXPECT_EQ(-1, ret) << "N input NULL " << key1;
  EXPECT_EQ(nullptr, value);

  ret = oc_ri_get_query_value_v1("", 0, key1.c_str(), key1.length(), &value);
  EXPECT_EQ(-1, ret) << "N input \"\" " << key1;
  EXPECT_EQ(nullptr, value);

  std::string query = "key1=1";
  std::string key2 = "key2";
  ret = oc_ri_get_query_value_v1(query.c_str(), query.length(), key2.c_str(),
                                 key2.length(), &value);
  EXPECT_EQ(-1, ret) << "N input " << query << " " << key2;
  EXPECT_EQ(nullptr, value);

  auto key3 = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  ret = oc_ri_get_query_value_v1(query.c_str(), query.length(), key3.c_str(),
                                 key3.length(), &value);
  EXPECT_EQ(-1, ret) << "N input " << query << " " << key3;
  EXPECT_EQ(nullptr, value);
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

TEST_F(TestQuery, RIGetQueryValueV1_P)
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
  std::string key = "key";
  const char *v;
  for (const auto &[query, exp] : inputs) {
    int ret = oc_ri_get_query_value_v1(query.c_str(), query.length(),
                                       key.c_str(), key.length(), &v);
    EXPECT_EQ(exp.length(), ret) << "P input " << query << " " << key;
    if (ret > 0) {
      std::string value(v, ret);
      EXPECT_STREQ(exp.c_str(), value.c_str())
        << "P input " << query << " "
        << "value " << exp << " vs " << value;
    }
  }

  std::string key2 = "key2";
  for (const auto &[query, _] : inputs) {
    int ret = oc_ri_get_query_value_v1(query.c_str(), query.length(),
                                       key2.c_str(), key2.length(), nullptr);
    EXPECT_EQ(-1, ret) << "N input " << query << " " << key2;
  }
}

TEST_F(TestQuery, RIQueryNthKeyExists_F)
{
  const char *k = nullptr;
  size_t klen = 0;
  EXPECT_EQ(-1, oc_ri_query_nth_key_exists(nullptr, 0, &k, &klen, 1));
  EXPECT_EQ(nullptr, k);
  EXPECT_EQ(0, klen);

  EXPECT_EQ(-1, oc_ri_query_nth_key_exists("", 0, &k, &klen, 1));
  EXPECT_EQ(nullptr, k);
  EXPECT_EQ(0, klen);

  EXPECT_EQ(-1, oc_ri_query_nth_key_exists("&&&", 0, &k, &klen, 1));
  EXPECT_EQ(nullptr, k);
  EXPECT_EQ(0, klen);
}

TEST_F(TestQuery, RIQueryNthKeyExists_P)
{
  for (int i = 1; i <= 3; ++i) {
    std::string query = "";
    std::vector<std::string> keys{};
    for (int j = 0; j < i; ++j) {
      std::string key = "key" + std::to_string(j);
      query += key + "=" + std::to_string(j);
      keys.emplace_back(key);
      if (j < i - 1) {
        query += "&";
      }
    }
    for (int j = 0; j < i; ++j) {
      const char *k = nullptr;
      size_t klen = 0;
      int vlen = oc_ri_query_nth_key_exists(query.c_str(), query.length(), &k,
                                            &klen, j + 1);
      EXPECT_NE(-1, vlen);
      if (j == i - 1) {
        EXPECT_EQ(query.length(), vlen);
      }
      EXPECT_EQ(keys[j].length(), klen);
      EXPECT_EQ(0, memcmp(keys[j].c_str(), k, klen));
    }
  }
}

TEST_F(TestQuery, RIQueryExists_F)
{
  EXPECT_EQ(-1, oc_ri_query_exists(nullptr, 0, ""));

  std::string query = "key1=1";
  std::string key = "key";
  EXPECT_EQ(-1, oc_ri_query_exists(query.c_str(), query.length(), key.c_str()));
  key = "key11";
  EXPECT_EQ(-1, oc_ri_query_exists(query.c_str(), query.length(), key.c_str()));
  key = "1";
  EXPECT_EQ(-1, oc_ri_query_exists(query.c_str(), query.length(), key.c_str()));
  key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  EXPECT_EQ(-1, oc_ri_query_exists(query.c_str(), query.length(), key.c_str()));
}

TEST_F(TestQuery, RIQueryExistsV1_F)
{
  EXPECT_FALSE(oc_ri_query_exists_v1(nullptr, 0, "", 0));

  std::string query = "key1=1";
  std::string key = "key";
  EXPECT_FALSE(oc_ri_query_exists_v1(query.c_str(), query.length(), key.c_str(),
                                     key.length()));
  key = "key11";
  EXPECT_FALSE(oc_ri_query_exists_v1(query.c_str(), query.length(), key.c_str(),
                                     key.length()));
  key = "1";
  EXPECT_FALSE(oc_ri_query_exists_v1(query.c_str(), query.length(), key.c_str(),
                                     key.length()));
  key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  EXPECT_FALSE(oc_ri_query_exists_v1(query.c_str(), query.length(), key.c_str(),
                                     key.length()));
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
  for (const auto &input : inputs) {
    int ret = oc_ri_query_exists(input.c_str(), input.length(), "key");
    EXPECT_EQ(1, ret) << "P input " << input << " "
                      << "key";
  }

  inputs.emplace_back("");
  for (const auto &input : inputs) {
    int ret = oc_ri_query_exists(input.c_str(), input.length(), "key2");
    EXPECT_EQ(-1, ret) << "N input " << input << " "
                       << "key2";
  }
}

TEST_F(TestQuery, RIQueryExistsV1_P)
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
  std::string key = "key";
  for (const auto &input : inputs) {
    bool ret = oc_ri_query_exists_v1(input.c_str(), input.length(), key.c_str(),
                                     key.length());
    EXPECT_TRUE(ret) << "P input " << input << " " << key;
  }

  inputs.emplace_back("");
  std::string key2 = "key2";
  for (const auto &input : inputs) {
    bool ret = oc_ri_query_exists_v1(input.c_str(), input.length(),
                                     key2.c_str(), key2.length());
    EXPECT_FALSE(ret) << "N input " << input << " " << key2;
  }
}

TEST_F(TestQuery, GetValue_F)
{
  EXPECT_EQ(-1, oc_get_query_value(nullptr, "", nullptr));

  oc_request_t request{};
  std::string query = "key1=1&key2=2";
  request.query = query.c_str();
  request.query_len = query.length();
  oc_init_query_iterator();
  auto key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  const char *value = nullptr;
  EXPECT_EQ(-1, oc_get_query_value(&request, key.c_str(), &value));
  EXPECT_EQ(nullptr, value);
}

TEST_F(TestQuery, GetValueV1_F)
{
  EXPECT_EQ(-1, oc_get_query_value_v1(nullptr, "", 0, nullptr));

  oc_request_t request{};
  std::string query = "key1=1&key2=2";
  request.query = query.c_str();
  request.query_len = query.length();
  oc_init_query_iterator();
  auto key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  const char *value = nullptr;
  EXPECT_EQ(-1,
            oc_get_query_value_v1(&request, key.c_str(), key.length(), &value));
  EXPECT_EQ(nullptr, value);
}

TEST_F(TestQuery, GetValueEmpty_N)
{
  const char *value = nullptr;
  oc_request_t request{};
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

TEST_F(TestQuery, GetValueV1Empty_N)
{
  const char *value = nullptr;
  oc_request_t request{};
  request.query = nullptr;
  request.query_len = 0;
  std::string key = "key";
  int ret = oc_get_query_value_v1(&request, key.c_str(), key.length(), &value);
  EXPECT_EQ(-1, ret) << "N input NULL " << key;

  request.query = "";
  ret = oc_get_query_value_v1(&request, key.c_str(), key.length(), &value);
  EXPECT_EQ(-1, ret) << "N input \"\" " << key;
}

TEST_F(TestQuery, IterateValues_F)
{
  oc_init_query_iterator();
  oc_request_t request{};
  const char *v = nullptr;
  int vlen = 0;
  EXPECT_FALSE(oc_iterate_query_get_values(&request, "", &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);

  oc_init_query_iterator();
  std::string query = "key1=1&key2=2";
  request.query = query.c_str();
  request.query_len = query.length();
  EXPECT_FALSE(oc_iterate_query_get_values(&request, "", &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  EXPECT_FALSE(oc_iterate_query_get_values(&request, "key", &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  EXPECT_FALSE(oc_iterate_query_get_values(&request, "key12", &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  EXPECT_FALSE(oc_iterate_query_get_values(&request, "keyF", &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  auto key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  EXPECT_FALSE(oc_iterate_query_get_values(&request, key.c_str(), &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
}

TEST_F(TestQuery, IterateValuesV1_F)
{
  oc_init_query_iterator();
  oc_request_t request{};
  const char *v = nullptr;
  int vlen = 0;
  EXPECT_FALSE(oc_iterate_query_get_values_v1(&request, "", 0, &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);

  oc_init_query_iterator();
  std::string query = "key1=1&key2=2";
  request.query = query.c_str();
  request.query_len = query.length();
  EXPECT_FALSE(oc_iterate_query_get_values_v1(&request, "", 0, &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  std::string key = "key";
  EXPECT_FALSE(oc_iterate_query_get_values_v1(&request, key.c_str(),
                                              key.length(), &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  key = "key12";
  EXPECT_FALSE(oc_iterate_query_get_values_v1(&request, key.c_str(),
                                              key.length(), &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  key = "keyF";
  EXPECT_FALSE(oc_iterate_query_get_values_v1(&request, key.c_str(),
                                              key.length(), &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
  key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  EXPECT_FALSE(oc_iterate_query_get_values_v1(&request, key.c_str(),
                                              key.length(), &v, &vlen));
  EXPECT_EQ(nullptr, v);
  EXPECT_EQ(0, vlen);
}

TEST_F(TestQuery, IterateValuesV1_P)
{
  std::string query = "key1=1&key2=2&key3=3";
  oc_request_t request{};
  request.query = query.c_str();
  request.query_len = query.length();
  const char *v = nullptr;
  int vlen = 0;

  std::string key = "key1";
  oc_init_query_iterator();
  EXPECT_TRUE(oc_iterate_query_get_values_v1(&request, key.c_str(),
                                             key.length(), &v, &vlen));
  EXPECT_EQ(1, vlen);
  EXPECT_EQ(0, memcmp("1", v, static_cast<size_t>(vlen)));

  key = "key2";
  oc_init_query_iterator();
  EXPECT_TRUE(oc_iterate_query_get_values_v1(&request, key.c_str(),
                                             key.length(), &v, &vlen));
  EXPECT_EQ(1, vlen);
  EXPECT_EQ(0, memcmp("2", v, static_cast<size_t>(vlen)));

  key = "key3";
  oc_init_query_iterator();
  EXPECT_FALSE(oc_iterate_query_get_values_v1(&request, key.c_str(),
                                              key.length(), &v, &vlen));
  EXPECT_EQ(1, vlen);
  EXPECT_EQ(0, memcmp("3", v, static_cast<size_t>(vlen)));

  query = "key=1&key=2&key=3";
  request.query = query.c_str();
  request.query_len = query.length();
  oc_init_query_iterator();
  key = "key";
  bool more = true;
  int i = 1;
  do {
    more = oc_iterate_query_get_values_v1(&request, key.c_str(), key.length(),
                                          &v, &vlen);
    EXPECT_EQ(1, vlen);
    EXPECT_EQ(0,
              memcmp(std::to_string(i).c_str(), v, static_cast<size_t>(vlen)));
    ++i;
  } while (more);
}

TEST_F(TestQuery, Exists_F)
{
  EXPECT_EQ(-1, oc_query_value_exists(nullptr, ""));

  oc_request_t request{};
  std::string query = "key1=1&key2=2";
  request.query = query.c_str();
  request.query_len = query.length();
  oc_init_query_iterator();
  auto key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  EXPECT_EQ(-1, oc_query_value_exists(&request, key.c_str()));
}

TEST_F(TestQuery, ExistsV1_F)
{
  EXPECT_FALSE(oc_query_value_exists_v1(nullptr, "", 0));

  oc_request_t request{};
  std::string query = "key1=1&key2=2";
  request.query = query.c_str();
  request.query_len = query.length();
  oc_init_query_iterator();
  auto key = std::string(COAP_OPTION_QUERY_MAX_SIZE + 1, 'a');
  EXPECT_FALSE(oc_query_value_exists_v1(&request, key.c_str(), key.length()));
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
  for (const auto &input : inputs) {
    oc_request_t request{};
    request.query = input.c_str();
    request.query_len = input.length();
    int ret = oc_query_value_exists(&request, "key");
    EXPECT_EQ(1, ret) << "P input " << input << " "
                      << "key";
  }

  inputs.emplace_back("");
  for (const auto &input : inputs) {
    oc_request_t request{};
    request.query = input.c_str();
    request.query_len = input.length();
    int ret = oc_query_value_exists(&request, "key2");
    EXPECT_EQ(-1, ret) << "N input " << input << " "
                       << "key2";
  }
}

TEST_F(TestQuery, ExistsV1_P)
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
  std::string key = "key";
  for (const auto &input : inputs) {
    oc_request_t request{};
    request.query = input.c_str();
    request.query_len = input.length();
    bool ret = oc_query_value_exists_v1(&request, key.c_str(), key.length());
    EXPECT_TRUE(ret) << "P input " << input << " " << key;
  }

  inputs.emplace_back("");
  std::string key2 = "key2";
  for (const auto &input : inputs) {
    oc_request_t request{};
    request.query = input.c_str();
    request.query_len = input.length();
    bool ret = oc_query_value_exists_v1(&request, key2.c_str(), key2.length());
    EXPECT_FALSE(ret) << "N input " << input << " " << key2;
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
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
    PLGD_IF_ETAG,
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
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
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
    PLGD_IF_ETAG_STR,
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  };

  for (size_t i = 0; i < ifaces.size(); ++i) {
    auto iview = oc_query_encode_interface(ifaces[i]);
    ASSERT_NE(nullptr, iview.data);
    std::string exp = "if=" + iface_strs[i];
    EXPECT_STREQ(exp.c_str(), iview.data);
  }
}

#endif /* OC_SERVER */
