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
#include "oc_helpers.h"

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

TEST(B64Test, RFC4648_EncodeV1Fail)
{
  std::vector<std::string> inputs = {
    "foo",
    "foobar",
  };

  std::for_each(inputs.begin(), inputs.end(), [](const std::string &str) {
    auto toEncode = fromString<uint8_t>(str);
    EXPECT_EQ(-1,
              oc_base64_encode_v1(OC_BASE64_ENCODING_STD, true, toEncode.data(),
                                  toEncode.size(), nullptr, 0));
    EXPECT_EQ(-1, oc_base64_encode_v1(OC_BASE64_ENCODING_STD, false,
                                      toEncode.data(), toEncode.size(), nullptr,
                                      0));
    EXPECT_EQ(-1,
              oc_base64_encode_v1(OC_BASE64_ENCODING_URL, true, toEncode.data(),
                                  toEncode.size(), nullptr, 0));
    EXPECT_EQ(-1, oc_base64_encode_v1(OC_BASE64_ENCODING_URL, false,
                                      toEncode.data(), toEncode.size(), nullptr,
                                      0));
  });
}

/*
 * Expected input and output comes from section 10 of RFC4648
 */
TEST(B64Test, RFC4648_EncodeTestVectors)
{
  std::vector<std::string> input = {
    "", "f", "fo", "foo", "foob", "fooba", "foobar",
  };

  std::vector<std::string> output = {
    "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
  };

  ASSERT_EQ(input.size(), output.size())
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
    EXPECT_EQ(output[i].length(), outputLength);
  }
}

static std::vector<uint8_t>
hexConvert(const std::string &input)
{
  std::vector<uint8_t> buf{};
  buf.resize(input.length());
  size_t bufLen = buf.size();
  if (oc_conv_hex_string_to_byte_array(input.c_str(), input.length(),
                                       buf.data(), &bufLen) != 0) {
    throw std::string("Failed to convert hex string to byte array");
  }
  buf.resize(bufLen);
  return buf;
}

TEST(B64Test, RFC4648_EncodeV1TestVectors)
{
  std::vector<std::vector<uint8_t>> input = {
    {},
    hexConvert("D"),
    hexConvert("FF"),
    hexConvert("123"),
    hexConvert("F8F9"),
    hexConvert("BCDEFF"),
    hexConvert("FEFDCDEFF"),
  };

  std::vector<std::string> output = {
    "", "DQ==", "/w==", "ASM=", "+Pk=", "vN7/", "D+/c3v8=",
  };

  std::vector<std::string> urlOutput = {
    "", "DQ==", "_w==", "ASM=", "-Pk=", "vN7_", "D-_c3v8=",
  };

  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";
  ASSERT_EQ(input.size(), urlOutput.size())
    << "Input test data and URL output test data missmatch.";

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    auto toEncode = input[i];
    int outputLength =
      oc_base64_encode_v1(OC_BASE64_ENCODING_STD, true, toEncode.data(),
                          toEncode.size(), buf.data(), buf.size() - 1);
    ASSERT_NE(-1, outputLength);
    EXPECT_EQ(output[i].length(), outputLength);
    auto str = toString(buf.data(), outputLength);
    EXPECT_STREQ(output[i].c_str(), str.c_str());

    outputLength =
      oc_base64_encode_v1(OC_BASE64_ENCODING_STD, false, toEncode.data(),
                          toEncode.size(), buf.data(), buf.size() - 1);
    ASSERT_NE(-1, outputLength);
    std::string expOutput = output[i];
    // remove padding
    expOutput.erase(std::remove(expOutput.begin(), expOutput.end(), '='),
                    expOutput.end());
    EXPECT_EQ(expOutput.length(), outputLength);
    str = toString(buf.data(), outputLength);
    EXPECT_STREQ(expOutput.c_str(), str.c_str());

    outputLength =
      oc_base64_encode_v1(OC_BASE64_ENCODING_URL, true, toEncode.data(),
                          toEncode.size(), buf.data(), buf.size() - 1);
    ASSERT_NE(-1, outputLength);
    EXPECT_EQ(urlOutput[i].length(), outputLength);
    str = toString(buf.data(), outputLength);
    EXPECT_STREQ(urlOutput[i].c_str(), str.c_str());
  }
}

TEST(B64Test, RFC4648_EncodeCalculateSize)
{
  std::vector<std::string> input = {
    "", "f", "fo", "foo", "foob", "fooba", "foobar",
  };
  std::vector<std::string> output = {
    "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
  };
  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";

  for (size_t i = 0; i < input.size(); ++i) {
    auto toEncode = fromString<uint8_t>(input[i]);
    size_t outputLength = oc_base64_encoded_output_size(toEncode.size(), true);
    EXPECT_EQ(output[i].length(), outputLength);
    outputLength = oc_base64_encoded_output_size(toEncode.size(), false);
    std::string expOutput = output[i];
    // remove padding
    expOutput.erase(std::remove(expOutput.begin(), expOutput.end(), '='),
                    expOutput.end());
    EXPECT_EQ(expOutput.length(), outputLength);
  }
}

TEST(B64Test, RFC4648_DecodeTestVectors)
{
  std::vector<std::string> input = {
    "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
  };
  std::vector<std::string> output = {
    "", "f", "fo", "foo", "foob", "fooba", "foobar",
  };
  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    std::copy(input[i].begin(), input[i].end(), buf.data());
    size_t bufLen = input[i].length();
    buf[bufLen] = '\0';
    int outputLength = oc_base64_decode(buf.data(), bufLen);
    EXPECT_NE(-1, outputLength) << "Failed to Base64 decode \"" << input[i]
                                << "\" to \"" << output[i] << "\"";
    EXPECT_EQ(output[i].length(), outputLength);
    auto str = toString(buf.data(), outputLength);
    EXPECT_STREQ(output[i].c_str(), str.c_str())
      << "Failed to Base64 decode \"" << input[i] << "\" to \"" << output[i]
      << "\"";
  }
}

TEST(B64Test, RFC4648_DecodeV1TestStdVectors)
{
  std::vector<std::string> input = {
    "", "DQ==", "/w==", "ASM=", "+Pk=", "vN7/", "D+/c3v8=",
  };

  std::vector<std::vector<uint8_t>> output = {
    {},
    hexConvert("D"),
    hexConvert("FF"),
    hexConvert("123"),
    hexConvert("F8F9"),
    hexConvert("BCDEFF"),
    hexConvert("FEFDCDEFF"),
  };

  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    auto toDecode = fromString<uint8_t>(input[i]);
    int outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_STD, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_NE(-1, outputLength);
    EXPECT_EQ(output[i].size(), outputLength);
    EXPECT_EQ(output[i].size(), oc_base64_decoded_output_size(
                                  toDecode.data(), toDecode.size(), true));
    auto str1 = toString(buf.data(), outputLength);
    auto str2 = toString(output[i].data(), output[i].size());
    EXPECT_STREQ(str2.c_str(), str1.c_str());
  }
}

TEST(B64Test, RFC4648_DecodeV1TestUrlVectors)
{
  std::vector<std::string> input = {
    "", "DQ==", "_w==", "ASM=", "-Pk=", "vN7_", "D-_c3v8=",
  };

  std::vector<std::vector<uint8_t>> output = {
    {},
    hexConvert("D"),
    hexConvert("FF"),
    hexConvert("123"),
    hexConvert("F8F9"),
    hexConvert("BCDEFF"),
    hexConvert("FEFDCDEFF"),
  };

  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";

  std::array<uint8_t, 64> buf{};
  for (size_t i = 0; i < input.size(); ++i) {
    auto toDecode = fromString<uint8_t>(input[i]);
    int outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_URL, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_NE(-1, outputLength);
    EXPECT_EQ(output[i].size(), outputLength);
    EXPECT_EQ(output[i].size(), oc_base64_decoded_output_size(
                                  toDecode.data(), toDecode.size(), true));
    auto str1 = toString(buf.data(), outputLength);
    auto str2 = toString(output[i].data(), output[i].size());
    EXPECT_STREQ(str2.c_str(), str1.c_str());
  }
}

TEST(B64Test, DecodeV1BufferTooSmall)
{
  std::vector<std::string> input = {
    "cA==",     "cGw=",     "cGxn",         "cGxnZA==",
    "cGxnZC4=", "cGxnZC5k", "cGxnZC5kZQ==", "cGxnZC5kZXY=",
  };
  std::vector<std::string> output = {
    "p", "pl", "plg", "plgd", "plgd.", "plgd.d", "plgd.de", "plgd.dev",
  };
  ASSERT_EQ(input.size(), output.size())
    << "Input test data and output test data missmatch.";

  for (size_t i = 0; i < input.size(); ++i) {
    auto toDecode = fromString<uint8_t>(input[i]);
    ASSERT_EQ(output[i].length(), oc_base64_decoded_output_size(
                                    toDecode.data(), toDecode.size(), true));

    std::vector<uint8_t> buf{};
    buf.resize(output[i].length() - 1);
    int outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_STD, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);
    outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_URL, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);

    // remove padding
    toDecode.erase(std::remove(toDecode.begin(), toDecode.end(), '='),
                   toDecode.end());
    ASSERT_EQ(output[i].length(), oc_base64_decoded_output_size(
                                    toDecode.data(), toDecode.size(), false));
    outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_STD, false, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);
    outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_URL, false, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);
  }
}

TEST(B64Test, DecodeV1InvalidNonPaddedString)
{
  std::vector<std::string> inputs = {
    "A",
    "AAAAA",
    "AAAAAAAAA",
    "AAAAAAAAAAAAA",
  };

  std::for_each(inputs.begin(), inputs.end(), [&](const std::string &in) {
    std::array<uint8_t, 64> buf{};
    auto toDecode = fromString<uint8_t>(in);
    EXPECT_EQ(-1, oc_base64_decoded_output_size(toDecode.data(),
                                                toDecode.size(), true));
    EXPECT_EQ(-1, oc_base64_decode_v1(OC_BASE64_ENCODING_STD, false,
                                      toDecode.data(), toDecode.size(),
                                      buf.data(), buf.size()));
    EXPECT_EQ(-1, oc_base64_decode_v1(OC_BASE64_ENCODING_URL, false,
                                      toDecode.data(), toDecode.size(),
                                      buf.data(), buf.size()));
  });
}

TEST(B64Test, DecodeInputMissingPadding)
{
  std::vector<std::string> input = {
    "Zg", "Zg=", "Zm9vYg", "Zm9vYg=", "Zm9vYmE",
  };

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

TEST(B64Test, DecodeInputV1MissingPadding)
{
  std::vector<std::string> inputs = {
    "Zg", "Zg=", "Zm9vYg", "Zm9vYg=", "Zm9vYmE",
  };

  // when padding is expected in the output the decoding should fail
  std::for_each(inputs.begin(), inputs.end(), [&](const std::string &in) {
    auto toDecode = fromString<uint8_t>(in);
    std::array<uint8_t, 64> buf{};
    int outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_STD, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);

    outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_URL, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);
  });

  // when padding is not expected in the output the decoding should succeed
  inputs = {
    "Zg",
    "Zm9vYg",
    "Zm9vYmE",
  };
  std::vector<std::string> outputs = {
    "f",
    "foob",
    "fooba",
  };
  ASSERT_EQ(inputs.size(), outputs.size())
    << "Input test data and output test data missmatch.";

  for (size_t i = 0; i < inputs.size(); ++i) {
    auto toDecode = fromString<uint8_t>(inputs[i]);
    std::array<uint8_t, 64> buf{};
    int outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_STD, false, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_NE(-1, outputLength);

    outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_URL, false, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_NE(-1, outputLength);
    EXPECT_EQ(outputs[i].length(), outputLength);
    auto str1 = toString(buf.data(), outputLength);
    auto str2 = toString(outputs[i].data(), outputs[i].size());
    EXPECT_STREQ(str2.c_str(), str1.c_str());
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
    "<>==",
    "{a==",
    "}a==",
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

TEST(B64Test, DecodeV1InputInvalidStdCharacters)
{
  std::vector<std::string> input = {
    "-a==", "_a==", "&a==", "<>==", "{a==", "}a==",
  };

  std::for_each(input.begin(), input.end(), [&](const std::string &in) {
    auto toDecode = fromString<uint8_t>(in);
    std::array<uint8_t, 64> buf{};
    int outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_STD, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);

    // remove padding
    toDecode.erase(std::remove(toDecode.begin(), toDecode.end(), '='),
                   toDecode.end());
    outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_STD, false, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);
  });
}

TEST(B64Test, DecodeV1InputInvalidUrlCharacters)
{
  std::vector<std::string> input = {
    "+a==", "/a==", "&a==", "<>==", "{a==", "}a==",
  };

  std::for_each(input.begin(), input.end(), [&](const std::string &in) {
    auto toDecode = fromString<uint8_t>(in);
    std::array<uint8_t, 64> buf{};
    int outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_URL, true, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);

    // remove padding
    toDecode.erase(std::remove(toDecode.begin(), toDecode.end(), '='),
                   toDecode.end());
    outputLength =
      oc_base64_decode_v1(OC_BASE64_ENCODING_URL, false, toDecode.data(),
                          toDecode.size(), buf.data(), buf.size());
    EXPECT_EQ(-1, outputLength);
  });
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
    "Zm=v", // Invalid padding no characters should follow padding
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

TEST(B64Test, DecodeV1InputInvalidPadding)
{
  // clang-format off
  std::vector<std::string> input =
  {
    "Zg==Zg==", // Invalid padding in middle of encoded string
    "Zm8=Zm8=", // Invalid padding in middle of encoded string
    "Z===", // Invalid padding max padding for Base64 string is two '=='
    "====", // Invalid padding max padding for Base64 string is two '=='
    "Zm=v", // Invalid padding no characters should follow padding
  };
  // clang-format on

  std::for_each(input.begin(), input.end(), [&](const std::string &in) {
    auto toDecode = fromString<uint8_t>(in);
    std::array<uint8_t, 64> buf{};
    EXPECT_EQ(-1,
              oc_base64_decode_v1(OC_BASE64_ENCODING_STD, true, toDecode.data(),
                                  toDecode.size(), buf.data(), buf.size()));
    EXPECT_EQ(-1, oc_base64_decode_v1(OC_BASE64_ENCODING_STD, false,
                                      toDecode.data(), toDecode.size(),
                                      buf.data(), buf.size()));
    EXPECT_EQ(-1,
              oc_base64_decode_v1(OC_BASE64_ENCODING_URL, true, toDecode.data(),
                                  toDecode.size(), buf.data(), buf.size()));
    EXPECT_EQ(-1, oc_base64_decode_v1(OC_BASE64_ENCODING_URL, false,
                                      toDecode.data(), toDecode.size(),
                                      buf.data(), buf.size()));
  });
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
 * For this test to work the first encoded value must be larger than the
 * second. This test is also coded to only expect two values.
 */
TEST(B64Test, EncoderDoesNotNullTerminate)
{
  std::vector<std::string> input = { "foobar", "foo" };

  std::vector<std::string> output = { "Zm9vYmFy", "Zm9v" };

  ASSERT_EQ(input.size(), output.size())
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
    EXPECT_EQ(output[i].length(), outputLength);
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
  }

  for (size_t i = 0; i < input.size(); ++i) {
    auto toEncode = fromString<uint8_t>(input[i]);
    int outputLength = oc_base64_encode(toEncode.data(), toEncode.size(),
                                        buf.data(), buf.size() - 1);
    ASSERT_NE(-1, outputLength) << "Failed to Base64 encode \"" << input[i]
                                << "\" to \"" << output[i] << "\"";
    ASSERT_EQ(0u, outputLength % 4) << "The return size for all b64Encode "
                                       "operations should be a multiple of 4. ";
    EXPECT_EQ(output[i].length(), outputLength);
    auto str = toString(buf.data(), outputLength);
    EXPECT_STREQ(output[i].c_str(), str.c_str())
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i]
      << "\"";
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

TEST(B64Test, EncodeV1ThenDecodeV1)
{
  auto test = [](oc_base64_encoding_t enc, bool padding) {
    std::string input = "This is a string that will be passed into  the Base64 "
                        "encoder.  After it is encoded the encoded result will "
                        "be passed into the Base64 decoded and the result will "
                        "be checked with the original input to make sure the "
                        "round trip results are as expected.";
    auto toEncode = fromString<uint8_t>(input, true);
    size_t b64BufSize = oc_base64_encoded_output_size(toEncode.size(), padding);
    std::vector<uint8_t> b64Buf(b64BufSize, '\0');

    int outputLength =
      oc_base64_encode_v1(enc, padding, toEncode.data(), toEncode.size(),
                          b64Buf.data(), b64Buf.size());
    ASSERT_NE(-1, outputLength);
    outputLength = oc_base64_decode_v1(
      enc, padding, b64Buf.data(), outputLength, b64Buf.data(), b64Buf.size());
    ASSERT_NE(-1, outputLength);
    EXPECT_EQ(toEncode.size(), outputLength);
    auto str = toString(b64Buf.data(), outputLength);
    EXPECT_STREQ(input.c_str(), str.c_str());
  };

  test(OC_BASE64_ENCODING_STD, true);
  test(OC_BASE64_ENCODING_STD, false);
  test(OC_BASE64_ENCODING_URL, true);
  test(OC_BASE64_ENCODING_URL, false);
}
