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

#include "port/oc_storage.h"

#ifdef OC_SECURITY

#include <algorithm>
#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <vector>

TEST(TestStorage, oc_storage_config_fail_with_length_over)
{
  int ret = oc_storage_config("./"
                              "storage_test_long_size_fail_storage_test_long_"
                              "size_fail_storage_test_long_size_fail");
  EXPECT_NE(0, ret);
}

TEST(TestStorage, oc_storage_read_fail)
{
  std::array<uint8_t, 100> buf{};
  auto ret = oc_storage_read("storage_store", buf.data(), buf.size());
  EXPECT_NE(0, ret);
}

TEST(TestStorage, oc_storage_write_fail)
{
  std::array<uint8_t, 100> buf{};
  auto ret = oc_storage_write("storage_store", buf.data(), buf.size());
  EXPECT_NE(0, ret);
}

TEST(TestStorage, oc_storage_config)
{
  auto ret = oc_storage_config("./storage_test");
  EXPECT_EQ(0, ret);
}

TEST(TestStorage, oc_storage_write)
{
  std::string file_name = "storage_store";
  std::string str = "storage";
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
#endif /* OC_SECURITY */
