/******************************************************************
 *
 * Copyright 2018 Intel Corporation All Rights Reserved.
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

#include "oc_base64.h"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <stddef.h>
#include <string>
#include <vector>

template<typename To>
std::vector<To>
fromString(const std::string &str, bool includeTerminator = false)
{
  std::vector<To> arr;
  arr.resize(str.length());
  for (size_t i = 0; i < str.length(); ++i) {
    arr[i] = static_cast<To>(str[i]);
  }
  if (includeTerminator) {
    arr.push_back(static_cast<To>('\0'));
  }
  return arr;
}

template<typename From>
std::string
toString(From *arr, size_t arrSize)
{
  std::string str{};
  str.resize(arrSize);
  for (size_t i = 0; i < arrSize; ++i) {
    str[i] = static_cast<char>(arr[i]);
  }
  // base64 encoder does not null terminate its output
  str.push_back('\0');
  return str;
}

TEST(B64Test, RFC4648_EncodeFail)
{
  std::vector<std::string> inputs = {
    "foo",
    "foobar",
  };

  std::for_each(inputs.begin(), inputs.end(), [](const std::string &str) {
    auto toEncode = fromString<uint8_t>(str);
    EXPECT_EQ(-1,
              oc_base64_encode(toEncode.data(), toEncode.size(), nullptr, 0));
  });
}

/*
 * Expected input and output comes from section 10 of RFC4648
 */
TEST(B64Test, RFC4648_EncodeTestVectors)
{
  // clang-format off
  std::vector<std::string> input =
  {
    "",
    "f",
    "fo",
    "foo",
    "foob",
    "fooba",
    "foobar",
  };

  std::vector<std::string> output =
  {
    "",
    "Zg==",
    "Zm8=",
    "Zm9v",
    "Zm9vYg==",
    "Zm9vYmE=",
    "Zm9vYmFy",
  };

  std::vector<size_t> expectedOutputLenth =
  {
    0,
    4,
    4,
    4,
    8,
    8,
    8,
  };
  // clang-format on

  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";
  ASSERT_EQ(input.size(), expectedOutputLenth.size())
    << "Input test data and output test data missmatch.";

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    auto toEncode = fromString<uint8_t>(input[i]);
    int outputLength = oc_base64_encode(toEncode.data(), toEncode.size(),
                                        buf.data(), buf.size() - 1);
    ASSERT_NE(-1, outputLength) << "Failed to Base64 encode \"" << input[i]
                                << "\" to \"" << output[i] << "\"";
    ASSERT_EQ(0u, outputLength % 4) << "The return size for all b64Encode "
                                       "operations should be a multiple of 4. ";
    auto str = toString(buf.data(), outputLength);
    EXPECT_STREQ(output[i].c_str(), str.c_str())
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i]
      << "\"";
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
  }
}

TEST(B64Test, RFC4648_DecodeTestVectors)
{
  // clang-format off
  std::vector<std::string> input =
  {
    "",
    "Zg==",
    "Zm8=",
    "Zm9v",
    "Zm9vYg==",
    "Zm9vYmE=",
    "Zm9vYmFy"
  };

  std::vector<std::string> output =
  {
    "",
    "f",
    "fo",
    "foo",
    "foob",
    "fooba",
    "foobar"
  };

  std::vector<size_t> expectedOutputLenth =
  {
    0,
    1,
    2,
    3,
    4,
    5,
    6
  };
  // clang-format on

  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";
  ASSERT_EQ(input.size(), expectedOutputLenth.size())
    << "Input test data and output test data missmatch.";

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    std::copy(input[i].begin(), input[i].end(), buf.data());
    size_t bufLen = input[i].length();
    buf[bufLen] = '\0';
    int outputLength = oc_base64_decode(buf.data(), bufLen);
    EXPECT_NE(-1, outputLength) << "Failed to Base64 decode \"" << input[i]
                                << "\" to \"" << output[i] << "\"";
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
    auto str = toString(buf.data(), outputLength);
    EXPECT_STREQ(output[i].c_str(), str.c_str())
      << "Failed to Base64 decode \"" << input[i] << "\" to \"" << output[i]
      << "\"";
  }
}

TEST(B64Test, DecodeInputMissingPadding)
{
  // clang-format off
  std::vector<std::string> input =
  {
    "Zg",
    "Zg="
  };
  // clang-format on

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    std::copy(input[i].begin(), input[i].end(), buf.data());
    size_t bufLen = input[i].length();
    buf[bufLen] = '\0';
    int outputLength = oc_base64_decode(buf.data(), bufLen);
    EXPECT_EQ(-1, outputLength)
      << "Base64 decode for \"" << input[i] << "\" did not fail as expected.";
  }
}

TEST(B64Test, DecodeInputInvalidCharacters)
{
  // Characters '-' and '_' chosen because the are part of other encoding
  // standards, other characters chosen at random just to increase test
  // coverage
  // clang-format off
  std::vector<std::string> input =
  {
    "-a==",
    "_a==",
    "&a==",
    "<>=="
  };
  // clang-format on

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    std::copy(input[i].begin(), input[i].end(), buf.data());
    size_t bufLen = input[i].length();
    buf[bufLen] = '\0';
    int outputLength = oc_base64_decode(buf.data(), bufLen);
    EXPECT_EQ(-1, outputLength)
      << "Base64 decode for \"" << input[i] << "\" did not fail as expected.";
  }
}

TEST(B64Test, DecodeInputInvalidPadding)
{
  // clang-format off
  std::vector<std::string> input =
  {
    "Zg==Zg==", // Invalid padding in middle of encoded string
    "Zm8=Zm8=", // Invalid padding in middle of encoded string
    "Z===", // Invalid padding max padding for Base64 string is two '=='
    "====", // Invalid padding max padding for Base64 string is two '=='
    "Zm=v" // Invalid padding no characters should follow padding
  };
  // clang-format on

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    std::copy(input[i].begin(), input[i].end(), buf.data());
    size_t bufLen = input[i].length();
    buf[bufLen] = '\0';
    int outputLength = oc_base64_decode(buf.data(), bufLen);
    EXPECT_EQ(-1, outputLength)
      << "Base64 decode for \"" << input[i] << "\" did not fail as expected.";
  }
}

/*
 * Expected input and output comes from section 10 of RFC4648
 *
 * This test is differs from the above tests, This tests main concern is the
 * placement of the NUL ('\0') terminating character after encoding.
 *
 * If a zero initialized buffer is used you can get away with out adding the
 * NUL character to the end. However if that buffer is reused for multiple
 * encoder calls there will not be a NUL character added to indicate the end
 * of the string.
 *
 * The first for loop verifies the expected behavior of having the incorrect
 * string when NUL is not added to the end of the string.
 *
 * The second for loop verifies that adding '\0' to outputLength position in
 * the array will work with the string.
 *
 * For this test to work the first encoded value must be larger than the second.
 * This test is also coded to only expect two values.
 */
TEST(B64Test, encoder_does_not_null_terminate)
{
  // clang-format off
  std::vector<std::string> input =
  {
    "foobar",
    "foo"
  };

  std::vector<std::string> output =
  {
    "Zm9vYmFy",
    "Zm9v"
  };

  std::vector<size_t> expectedOutputLenth =
  {
    8,
    4
  };
  // clang-format on

  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";
  ASSERT_EQ(input.size(), expectedOutputLenth.size())
    << "Input test data and output test data missmatch.";

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    auto toEncode = fromString<uint8_t>(input[i]);
    int outputLength = oc_base64_encode(toEncode.data(), toEncode.size(),
                                        buf.data(), buf.size() - 1);
    ASSERT_NE(-1, outputLength) << "Failed to Base64 encode \"" << input[i]
                                << "\" to \"" << output[i] << "\"";
    ASSERT_EQ(0u, outputLength % 4) << "The return size for all b64Encode "
                                       "operations should be a multiple of 4.";

    std::array<char, buf.size()> strBuf;
    std::copy(buf.begin(), buf.end(), strBuf.data());
    if (i == 0) {
      /* expect to pass on first encode due to zero initialized buf */
      EXPECT_STREQ(output[i].c_str(), strBuf.data())
        << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i]
        << "\"";
    } else {
      /* expect to fail on second encode due to lack of NUL character */
      EXPECT_STRNE(output[i].c_str(), strBuf.data())
        << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i]
        << "\"";
    }
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
  }

  for (size_t i = 0; i < input.size(); ++i) {
    auto toEncode = fromString<uint8_t>(input[i]);
    int outputLength = oc_base64_encode(toEncode.data(), toEncode.size(),
                                        buf.data(), buf.size() - 1);
    ASSERT_NE(-1, outputLength) << "Failed to Base64 encode \"" << input[i]
                                << "\" to \"" << output[i] << "\"";
    ASSERT_EQ(0u, outputLength % 4) << "The return size for all b64Encode "
                                       "operations should be a multiple of 4. ";
    auto str = toString(buf.data(), outputLength);
    EXPECT_STREQ(output[i].c_str(), str.c_str())
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i]
      << "\"";
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
  }
}

// verify round trip encoding
TEST(B64Test, EncodeThenDecode)
{
  std::string input = "This is a string that will be passed into  the Base64 "
                      "encoder.  After it is encoded the encoded result will "
                      "be passed into the Base64 decoded and the result will "
                      "be checked with the original input to make sure the "
                      "round trip results are as expected.";
  size_t input_size = input.size() + 1; // include null terminator
  size_t b64BufSize = (input_size / 3) * 4;
  if (sizeof(input) % 3 != 0) {
    b64BufSize += 4;
  }
  b64BufSize++;
  std::vector<uint8_t> b64Buf(b64BufSize, '\0');

  auto toEncode = fromString<uint8_t>(input, true);
  int outputLength = oc_base64_encode(toEncode.data(), toEncode.size(),
                                      b64Buf.data(), b64BufSize - 1);
  ASSERT_NE(-1, outputLength)
    << "Failed to Base64 encode \"" << input << "\" to buffer";
  ASSERT_EQ(0u, outputLength % 4) << "The return size for all b64Encode "
                                     "operations should be a multiple of 4.";
  outputLength = oc_base64_decode(b64Buf.data(), outputLength);
  ASSERT_NE(-1, outputLength)
    << "Failed to Base64 decode \"" << input << "\" to buffer";
  EXPECT_EQ(toEncode.size(), outputLength);
  auto str = toString(b64Buf.data(), outputLength);
  EXPECT_STREQ(input.c_str(), str.c_str());
}
