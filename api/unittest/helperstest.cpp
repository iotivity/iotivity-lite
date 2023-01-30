/******************************************************************
 *
 * Copyright 2022 Daniel Adam All Rights Reserved.
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

#include "api/oc_helpers_internal.h"
#include "oc_helpers.h"
#include "port/oc_random.h"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>

TEST(Helpers, ConcatStrings)
{
  oc_string_t str;
  oc_concat_strings(&str, "", "");
  EXPECT_STREQ("", oc_string(str));
  oc_free_string(&str);

  memset(&str, 0, sizeof(str));
  oc_concat_strings(&str, "abc", "");
  EXPECT_STREQ("abc", oc_string(str));
  oc_free_string(&str);

  memset(&str, 0, sizeof(str));
  oc_concat_strings(&str, "", "def");
  EXPECT_STREQ("def", oc_string(str));
  oc_free_string(&str);

  memset(&str, 0, sizeof(str));
  oc_concat_strings(&str, "abc", "def");
  EXPECT_STREQ("abcdef", oc_string(str));
  oc_free_string(&str);
}

TEST(Helpers, RandomBuffer)
{
  oc_random_init();

  uint8_t c{ 0 };
  oc_random_buffer(&c, 1);
  std::cout << "token: " << std::hex << (int)c << std::endl;

  std::array<uint8_t, 2> small_array{ 0 };
  oc_random_buffer(small_array.data(), small_array.size());
  std::cout << "token: ";
  for (const auto &a : small_array) {
    std::cout << std::hex << (int)a << " ";
  }
  std::cout << std::endl;

  std::array<uint8_t, 8> medium_array{ 0 };
  oc_random_buffer(medium_array.data(), medium_array.size());
  std::cout << "token: ";
  for (const auto &a : medium_array) {
    std::cout << std::hex << (int)a << " ";
  }
  std::cout << std::endl;

  std::array<uint8_t, 42> best_array{ 0 };
  oc_random_buffer(best_array.data(), best_array.size());
  std::cout << "token: ";
  for (const auto &a : best_array) {
    std::cout << std::hex << (int)a << " ";
  }
  std::cout << std::endl;

  oc_random_destroy();
}
