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

#include "gtest/gtest.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <numeric>
#include <vector>

TEST(Helpers, StringLen)
{
  oc_string_t oc_str{};
  EXPECT_EQ(0, oc_string_len(oc_str));
  // cannot use oc_string_len_unsafe because oc_str.ptr is NULL

  std::string str{ "test" };
  oc_new_string(&oc_str, str.c_str(), str.length());
  EXPECT_EQ(str.length(), oc_string_len(oc_str));
  EXPECT_EQ(str.length(), oc_string_len_unsafe(oc_str));

  oc_free_string(&oc_str);
}

TEST(Helpers, SetStrings)
{
  oc_string_t oc_str{};
  std::string str1{ "test1" };
  oc_set_string(&oc_str, str1.c_str(), str1.length());
  EXPECT_STREQ(str1.c_str(), oc_string(oc_str));

  std::string str2{ "test2" };
  oc_set_string(&oc_str, str2.c_str(), str2.length());
  EXPECT_STREQ(str2.c_str(), oc_string(oc_str));

  oc_set_string(&oc_str, nullptr, 1);
  EXPECT_EQ(nullptr, oc_string(oc_str));
}

TEST(Helpers, CopyStrings)
{
  std::string str1{ "test1" };
  oc_string_t oc_str1{};
  oc_new_string(&oc_str1, str1.c_str(), str1.length());

  oc_copy_string(&oc_str1, &oc_str1);

  oc_string_t oc_str2{};
  oc_copy_string(&oc_str2, &oc_str1);
  EXPECT_STREQ(str1.c_str(), oc_string(oc_str2));

  oc_copy_string(&oc_str2, nullptr);
  EXPECT_EQ(nullptr, oc_string(oc_str2));

  oc_copy_string(&oc_str1, &oc_str2);
  EXPECT_EQ(nullptr, oc_string(oc_str1));

  oc_free_string(&oc_str2);
  oc_free_string(&oc_str1);
}

TEST(Helpers, SetMultipleStrings)
{
  std::string str1{ "test1" };
  oc_string_t oc_str1{};
  oc_new_string(&oc_str1, str1.c_str(), str1.length());

  std::string str2{ "test2" };
  oc_string_t oc_str2{};
  oc_new_string(&oc_str2, str2.c_str(), str2.length());

  std::string str3{ "test3" };
  oc_string_t oc_str3{};
  oc_new_string(&oc_str3, str3.c_str(), str3.length());

  // with DYNAMIC_ALLOCATION disabled -> oc_set_string will free oc_str1, which
  // was allocated first, so oc_str2 and oc_str3 will get reallocated
  oc_set_string(&oc_str1, oc_string(oc_str2), oc_string_len(oc_str2));

  EXPECT_STREQ(str2.c_str(), oc_string(oc_str1));
  EXPECT_STREQ(str2.c_str(), oc_string(oc_str2));
  EXPECT_STREQ(str3.c_str(), oc_string(oc_str3));

  oc_free_string(&oc_str3);
  oc_free_string(&oc_str2);
  oc_free_string(&oc_str1);
}

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

TEST(Helpers, ByteStringArray)
{
  std::vector<std::string> strs{
    "first",
    "second",
    "the best",
  };
  oc_byte_string_array_t barray{};
  oc_new_byte_string_array(&barray, strs.size());

  // adding item longer than STRING_ARRAY_ITEM_MAX_LEN fails
  std::string fail(STRING_ARRAY_ITEM_MAX_LEN, 'z');
  EXPECT_FALSE(
    oc_byte_string_array_add_item(barray, fail.c_str(), fail.length()));

  for (const auto &str : strs) {
    EXPECT_TRUE(
      oc_byte_string_array_add_item(barray, str.c_str(), str.length()));
  }

  for (size_t i = 0; i < oc_byte_string_array_get_allocated_size(barray); ++i) {
    const char *bs = oc_byte_string_array_get_item(barray, i);
    size_t bs_size = oc_byte_string_array_get_item_size(barray, i);
    std::string str(bs, bs_size);
    EXPECT_STREQ(strs[i].c_str(), str.c_str());
  }

  // adding item past the allocated size fails
  fail = "fail";
  EXPECT_FALSE(
    oc_byte_string_array_add_item(barray, fail.c_str(), fail.length()));

  oc_free_byte_string_array(&barray);
}

TEST(Helpers, StringArray)
{
  std::vector<std::string> strs{
    "first",
    "second",
    "the best",
  };

  oc_string_array_t sarray{};
  oc_new_string_array(&sarray, strs.size());

  // adding item longer than STRING_ARRAY_ITEM_MAX_LEN fails
  std::string fail(STRING_ARRAY_ITEM_MAX_LEN, 'z');
  EXPECT_FALSE(oc_string_array_add_item(sarray, fail.c_str()));

  for (const auto &str : strs) {
    EXPECT_TRUE(oc_string_array_add_item(sarray, str.c_str()));
  }

  for (size_t i = 0; i < oc_string_array_get_allocated_size(sarray); ++i) {
    EXPECT_STREQ(strs[i].c_str(), oc_string_array_get_item(sarray, i));
  }

  // adding item past the allocated size should fail
  fail = "fail";
  EXPECT_FALSE(oc_string_array_add_item(sarray, fail.c_str()));

  oc_free_string_array(&sarray);
}

TEST(Helpers, JoinStringArray)
{
  std::vector<std::string> strs{
    "first",
    "second",
    "the best",
  };

  oc_string_array_t sarray{};
  oc_new_string_array(&sarray, strs.size());
  for (const auto &str : strs) {
    EXPECT_TRUE(oc_string_array_add_item(sarray, str.c_str()));
  }

  oc_string_t oc_joined{};
  oc_join_string_array(&sarray, &oc_joined);

  std::string exp_joined =
    std::accumulate(strs.begin(), strs.end(), std::string(),
                    [](const std::string &lhs, const std::string &rhs) {
                      return lhs + (lhs.length() > 0 ? " " : "") + rhs;
                    });
  EXPECT_STREQ(exp_joined.c_str(), oc_string(oc_joined));

  oc_free_string(&oc_joined);
  oc_free_string_array(&sarray);
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

// Test error when provided hex string buffer is too small
TEST(Helpers, HexStringTooSmallError)
{
  std::array<uint8_t, 4> array{ 0x1f, 0xa0, 0x5b, 0xff };
  std::array<char, 5> hex_str; // Too small to fit the full hex representation
                               // (8 chars + null terminator)
  size_t hex_str_len = hex_str.size();
  int result = oc_conv_byte_array_to_hex_string(array.data(), array.size(),
                                                &hex_str[0], &hex_str_len);
  ASSERT_EQ(result, -1);
}

// Test successful conversion of a byte array to hex string
TEST(Helpers, ConvertByteArrayToHexStringSuccess)
{
  std::array<uint8_t, 4> array{ 0x1f, 0xa0, 0x5b, 0xff };
  std::array<char, 9>
    hex_str; // Must hold 8 characters (2 per byte) + null terminator
  size_t hex_str_len = hex_str.size();
  int result = oc_conv_byte_array_to_hex_string(array.data(), array.size(),
                                                &hex_str[0], &hex_str_len);
  ASSERT_EQ(result, 0);
  EXPECT_STREQ(hex_str.data(), "1fa05bff");
  EXPECT_EQ(hex_str_len, 8);
}

// Test empty hex string input
TEST(Helpers, EmptyHexStringError)
{
  std::string hex_str = "";
  std::array<uint8_t, 4> array;
  size_t array_len = array.size();

  int result = oc_conv_hex_string_to_byte_array(
    hex_str.c_str(), hex_str.length(), &array[0], &array_len);
  ASSERT_EQ(result, -1);
}

// Test when array buffer is too small
TEST(Helpers, ArrayBufferTooSmallError)
{
  std::string hex_str = "1fa05bff";
  std::array<uint8_t, 2>
    array; // Too small to hold the expected byte array (needs 4 bytes)
  size_t array_len = array.size();

  int result = oc_conv_hex_string_to_byte_array(
    hex_str.c_str(), hex_str.length(), &array[0], &array_len);
  ASSERT_EQ(result, -1);
}

// Test successful conversion of an even-length hex string to byte array
TEST(Helpers, EvenLengthHexStringSuccess)
{
  std::string hex_str = "1fa05bff";
  std::array<uint8_t, 4> array;
  size_t array_len = array.size();

  int result = oc_conv_hex_string_to_byte_array(
    hex_str.c_str(), hex_str.length(), &array[0], &array_len);

  ASSERT_EQ(result, 0);
  EXPECT_EQ(array_len, 4);
  std::array<uint8_t, 4> expected_array = { 0x1f, 0xa0, 0x5b, 0xff };
  EXPECT_EQ(expected_array, array);
}

// Test successful conversion of an odd-length hex string to byte array
TEST(Helpers, OddLengthHexStringSuccess)
{
  std::string hex_str = "fa05bf";
  std::array<uint8_t, 3> array;
  size_t array_len = array.size();

  int result = oc_conv_hex_string_to_byte_array(
    hex_str.c_str(), hex_str.length(), &array[0], &array_len);

  ASSERT_EQ(result, 0);
  std::array<uint8_t, 3> expected_array = { 0xfa, 0x05, 0xbf };
  EXPECT_EQ(array_len, expected_array.size());
  EXPECT_EQ(expected_array, array);
}
