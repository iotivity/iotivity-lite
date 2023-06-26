/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "oc_config.h"

#ifdef OC_STORAGE

#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#if defined(__linux__) && !defined(__ANDROID__) && !defined(ESP_PLATFORM)
#include "port/linux/storage.h"
#endif /* __linux__ */

#ifdef __ANDROID__
#include "port/android/storage.h"
#endif /* __ANDROID__ */

#ifdef _WIN32
#include "port/windows/storage.h"
#endif /* _WIN32 */

static const std::string testStorage{ "storage_test" };

#ifdef _WIN32
constexpr char kPathSeparator = '\\';
#else
constexpr char kPathSeparator = '/';
#endif

class TestStorage : public testing::Test {
public:
  void TearDown() override { ASSERT_EQ(0, oc_storage_reset()); }
};

TEST_F(TestStorage, oc_storage_config_fail)
{
  EXPECT_NE(0, oc_storage_config(nullptr));
  EXPECT_NE(0, oc_storage_config(""));
}

TEST_F(TestStorage, oc_storage_config_fail_append_slash)
{
  auto path = std::string(OC_STORE_PATH_SIZE - 1, 'a');
  EXPECT_NE(0, oc_storage_config(path.c_str()));
}

TEST_F(TestStorage, oc_storage_config_fail_with_length_over)
{
  EXPECT_NE(
    0, oc_storage_config("./"
                         "storage_test_long_size_fail_storage_test_long_size_"
                         "fail_storage_test_long_size_fail_storage_test_long_"
                         "size_fail_storage_test_long_size_fail"));
  EXPECT_FALSE(oc_storage_path(nullptr, 0));
}

TEST_F(TestStorage, oc_storage_config)
{
  EXPECT_EQ(0, oc_storage_config(testStorage.c_str()));

  EXPECT_TRUE(oc_storage_path(nullptr, 0));
  std::array<char, 256> path{};
  EXPECT_TRUE(oc_storage_path(path.data(), path.size()));
  EXPECT_STREQ((testStorage + kPathSeparator).c_str(), path.data());

  EXPECT_EQ(0, oc_storage_reset());
  EXPECT_FALSE(oc_storage_path(nullptr, 0));
}

TEST_F(TestStorage, oc_storage_config_strip_trailing_slashes)
{
  EXPECT_EQ(0, oc_storage_config(
                 (testStorage + std::string(5, kPathSeparator)).c_str()));

  std::array<char, 256> path{};
  EXPECT_TRUE(oc_storage_path(path.data(), path.size()));
  EXPECT_STREQ((testStorage + kPathSeparator).c_str(), path.data());

  EXPECT_EQ(0, oc_storage_reset());
  EXPECT_FALSE(oc_storage_path(nullptr, 0));
}

TEST_F(TestStorage, oc_storage_path_fail)
{
  ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));

  std::array<char, 1> too_small{};
  EXPECT_FALSE(oc_storage_path(too_small.data(), too_small.size()));
}

TEST_F(TestStorage, oc_storage_read_fail)
{
  // not configured
  std::array<uint8_t, 100> buf{};
  EXPECT_NE(0, oc_storage_read("storage_fail", buf.data(), buf.size()));

  // configured
  ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));
  // storage name empty
  EXPECT_NE(0, oc_storage_read("", buf.data(), buf.size()));
  // storage name too long
  auto store = std::string(OC_STORE_PATH_SIZE, 'a');
  EXPECT_NE(0, oc_storage_read(store.c_str(), buf.data(), buf.size()));
}

TEST_F(TestStorage, oc_storage_write_fail)
{
  // not configured
  std::array<uint8_t, 100> buf{};
  EXPECT_NE(0, oc_storage_write("storage_fail", buf.data(), buf.size()));

  // configured
  ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));
  // storage name empty
  EXPECT_NE(0, oc_storage_write("", buf.data(), buf.size()));
  // storage name too long
  auto store = std::string(OC_STORE_PATH_SIZE, 'a');
  EXPECT_NE(0, oc_storage_write(store.c_str(), buf.data(), buf.size()));
}

TEST_F(TestStorage, oc_storage_write)
{
  EXPECT_EQ(0, oc_storage_config(testStorage.c_str()));

  std::string file_name = "st_file";
  std::string str = "storage_folder";
  std::vector<uint8_t> in{};
  std::copy(str.begin(), str.end(), std::back_inserter(in));
  auto ret = oc_storage_write(file_name.c_str(), in.data(), in.size());
  EXPECT_LE(0, ret);

  std::array<uint8_t, 100> buf{};
  ret = oc_storage_read(file_name.c_str(), buf.data(), buf.size());
  EXPECT_LE(0, ret);
  std::string out{};
  std::copy_n(buf.begin(), static_cast<size_t>(ret), std::back_inserter(out));
  EXPECT_STREQ(str.c_str(), out.c_str());
}

#endif /* OC_STORAGE */
