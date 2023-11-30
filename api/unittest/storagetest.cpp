/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifdef _WIN32
// don't define max() macro
#define NOMINMAX
#endif /* _WIN32 */

#include "oc_config.h"

#ifdef OC_STORAGE

#include "api/oc_rep_internal.h"
#include "api/oc_storage_internal.h"
#include "oc_api.h"
#include "port/oc_connectivity.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "util/oc_macros_internal.h"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <limits>
#include <string>

static const std::string testStorage{ "storage_test" };

class TestCommonStorage : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));

    auto encode = [](size_t, void *) {
      oc_rep_start_root_object();
      oc_rep_set_boolean(root, ok, true);
      oc_rep_end_root_object();
      EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
      return 0;
    };
    EXPECT_LT(0, oc_storage_data_save("test", 0, encode, nullptr));
  }

  static void TearDownTestCase()
  {
    ASSERT_EQ(0, oc_storage_reset());
    for (const auto &entry : std::filesystem::directory_iterator(testStorage)) {
      std::filesystem::remove_all(entry.path());
    }

    ASSERT_EQ(0, oc_storage_reset());
  }
};

TEST_F(TestCommonStorage, GenSvrTagFail)
{
  std::array<char, 3> too_small{};
  EXPECT_EQ(
    -1, oc_storage_gen_svr_tag("test", 0, too_small.data(), too_small.size()));
}

TEST_F(TestCommonStorage, GenSvrTag)
{
  std::string exp{ "t_123" };
  std::array<char, 6> b1{};
  EXPECT_EQ(exp.length(),
            oc_storage_gen_svr_tag("test", 123, b1.data(), b1.size()));
  EXPECT_STREQ(exp.c_str(), b1.data());

  exp = "test_123";
  std::array<char, 9> b2{};
  EXPECT_EQ(exp.length(),
            oc_storage_gen_svr_tag("test", 123, b2.data(), b2.size()));
  EXPECT_STREQ(exp.c_str(), b2.data());

  exp = "test_12345";
  std::array<char, OC_STORAGE_SVR_TAG_MAX> b3{};
  EXPECT_EQ(exp.length(),
            oc_storage_gen_svr_tag("test", 12345, b3.data(), b3.size()));
  EXPECT_STREQ(exp.c_str(), b3.data());

  exp = "test_" + std::to_string(std::numeric_limits<size_t>::max());
  std::array<char, OC_STORAGE_SVR_TAG_MAX> b4{};
  EXPECT_EQ(exp.length(),
            oc_storage_gen_svr_tag("test", std::numeric_limits<size_t>::max(),
                                   b4.data(), b4.size()));
  EXPECT_STREQ(exp.c_str(), b4.data());
}

TEST_F(TestCommonStorage, GenSvrTagTruncateToMax)
{
  std::array<char, 128> b{};
  std::string long_name =
    "superLongNameThatIsLongerThan_OC_STORAGE_SVR_TAG_MAX";
  std::string device = std::to_string(std::numeric_limits<size_t>::max());
  std::string exp = long_name;

  // longer than OC_STORAGE_SVR_TAG_MAX will be truncated to
  // OC_STORAGE_SVR_TAG_MAX
  ASSERT_LT(OC_STORAGE_SVR_TAG_MAX, long_name.length() + device.length() + 2);

  exp.resize(OC_STORAGE_SVR_TAG_MAX - device.length() - 2);
  exp += "_" + device;
  EXPECT_EQ(exp.length(),
            oc_storage_gen_svr_tag(long_name.c_str(),
                                   std::numeric_limits<size_t>::max(), b.data(),
                                   b.size()));
  EXPECT_STREQ(exp.c_str(), b.data());
}

TEST_F(TestCommonStorage, LoadResourceFail)
{
  auto decode = [](const oc_rep_t *, size_t, void *) { return 0; };
  // not-existing file
  EXPECT_EQ(-1, oc_storage_data_load("fail", 0, decode, nullptr));

  auto decodeFail = [](const oc_rep_t *, size_t, void *) { return -1; };
  // failing to decode
  EXPECT_EQ(-1, oc_storage_data_load("test", 0, decodeFail, nullptr));
}

TEST_F(TestCommonStorage, SaveResourceFail)
{
  auto encodeFail = [](size_t, void *) { return -1; };
  EXPECT_EQ(-1, oc_storage_data_save("fail", 0, encodeFail, nullptr));

  auto encodeTooLarge = [](size_t, void *) {
    std::string str(OC_MAX_APP_DATA_SIZE, 'a');
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, too_long, str.c_str());
    oc_rep_end_root_object();
    EXPECT_NE(CborNoError, oc_rep_get_cbor_errno());
    return 0;
  };
  EXPECT_EQ(-1, oc_storage_data_save("fail", 0, encodeTooLarge, nullptr));
}

TEST_F(TestCommonStorage, SaveAndLoad)
{
  struct TestData
  {
    std::string str;
    int num;
  };

  TestData td{};
  td.str = "Hello world";
  td.num = 42;

  auto encode = [](size_t, void *data) {
    const auto *d = static_cast<TestData *>(data);
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, str, d->str.c_str());
    oc_rep_set_int(root, num, d->num);
    oc_rep_end_root_object();
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
    return 0;
  };
  EXPECT_LT(0, oc_storage_data_save("test", 123, encode, &td));

  TestData outTd{};
  auto decode = [](const oc_rep_t *rep, size_t, void *data) {
    auto *d = static_cast<TestData *>(data);
    for (; rep != nullptr; rep = rep->next) {
      if (rep->type == OC_REP_INT &&
          oc_rep_is_property(rep, "num", OC_CHAR_ARRAY_LEN("num"))) {
        d->num = static_cast<int>(rep->value.integer);
        continue;
      }
      if (rep->type == OC_REP_STRING &&
          oc_rep_is_property(rep, "str", OC_CHAR_ARRAY_LEN("str"))) {
        d->str = oc_string(rep->value.string);
        continue;
      }
    }
    return 0;
  };
  EXPECT_LT(0, oc_storage_data_load("test", 123, decode, &outTd));
  EXPECT_STREQ(td.str.c_str(), outTd.str.c_str());
  EXPECT_EQ(td.num, outTd.num);
}

#endif /* OC_STORAGE */
