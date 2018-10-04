/******************************************************************
 *
 * Copyright 2018 Intel Corporation All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include <gtest/gtest.h>
#include <string.h>
extern "C" {
#include "oc_base64.h"
}
/*
 * Expected input and output comes from section 10 of RFC4648
 */
TEST(B64Test, RFC4648_EncodeTestVectors)
{
  char buf[128];
  int outputLength = 0;
  const char *input[] =
  {
    "",
    "f",
    "fo",
    "foo",
    "foob",
    "fooba",
    "foobar"
  };

  const char *output[] =
  {
    "",
    "Zg==",
    "Zm8=",
    "Zm9v",
    "Zm9vYg==",
    "Zm9vYmE=",
    "Zm9vYmFy"
  };

  const size_t expectedOutputLenth[] =
  {
    0,
    4,
    4,
    4,
    8,
    8,
    8
  };

  size_t bufSize = (sizeof(buf)/sizeof(buf[0]));
  size_t inputArraySize = (sizeof(input) / sizeof(input[0]));
  size_t outputArraySize = (sizeof(output) / sizeof(output[0]));
  size_t expectedOutputLenthArraySize = (sizeof(expectedOutputLenth) / sizeof(
      expectedOutputLenth[0]));

  ASSERT_EQ(inputArraySize, outputArraySize)
  << "Input test data and output test data missmatch.";
  ASSERT_EQ(inputArraySize, expectedOutputLenthArraySize)
  << "Input test data and output test data missmatch.";
  for (size_t i = 0; i < inputArraySize; ++i)
  {
    outputLength = oc_base64_encode((const uint8_t *)input[i], strlen(input[i]), (uint8_t *)buf, bufSize);
    EXPECT_NE(-1, outputLength)
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i] << "\"";
    EXPECT_EQ(0u, outputLength % 4)
      << "The return size for all b64Encode operations should be a multiple of 4.";
    // base64 encoder does not null terminate its output
    buf[outputLength] = '\0';
    EXPECT_STREQ(output[i], buf)
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i] << "\"";
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
  }
}

TEST(B64Test, RFC4648_DecodeTestVectors)
{
  uint8_t buf[128] = {0,};
  size_t outputLength = 0;

  const char *input[] =
  {
    "",
    "Zg==",
    "Zm8=",
    "Zm9v",
    "Zm9vYg==",
    "Zm9vYmE=",
    "Zm9vYmFy"
  };

  const char *output[] =
  {
    "",
    "f",
    "fo",
    "foo",
    "foob",
    "fooba",
    "foobar"
  };

  const size_t expectedOutputLenth[] =
  {
    0,
    1,
    2,
    3,
    4,
    5,
    6
  };

  size_t bufSize = (sizeof(buf)/sizeof(buf[0]));
  size_t inputArraySize = (sizeof(input) / sizeof(input[0]));
  size_t outputArraySize = (sizeof(output) / sizeof(output[0]));
  size_t expectedOutputLenthArraySize = (sizeof(expectedOutputLenth) / sizeof(
      expectedOutputLenth[0]));

  ASSERT_EQ(inputArraySize, outputArraySize)
  << "Input test data and output test data missmatch.";
  ASSERT_EQ(inputArraySize, expectedOutputLenthArraySize)
  << "Input test data and output test data missmatch.";

  for (size_t i = 0; i < inputArraySize; ++i)
  {
    strncpy((char*)buf, input[i], bufSize);
    buf[bufSize] = '\0';
    outputLength = oc_base64_decode(buf, strlen((const char*)buf));
    EXPECT_NE(-1, outputLength)
    << "Failed to Base64 decode \"" << input[i] << "\" to \"" << output[i] << "\"";
    EXPECT_STREQ(output[i], (char *)buf)
    << "Failed to Base64 decode \"" << input[i] << "\" to \"" << output[i] << "\"";
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
  }
}

TEST(B64Test, DecodeInputMissingPadding)
{
  uint8_t buf[128] = {0,};
  size_t outputLength = 0;

  const char *input[] =
  {
    "Zg",
    "Zg="
  };

  size_t bufSize = (sizeof(buf)/sizeof(buf[0]));
  size_t inputArraySize = (sizeof(input) / sizeof(input[0]));

  for (size_t i = 0; i < inputArraySize; ++i)
  {
    strncpy((char*)buf, input[i], bufSize);
    buf[bufSize] = '\0';
    outputLength = oc_base64_decode(buf, strlen((const char*)buf));
    EXPECT_EQ(-1, outputLength)
    << "Base64 decode for \"" << input[i] << "\" did not fail as expected.";
  }
}

TEST(B64Test, DecodeInputInvalidCharacters)
{
  uint8_t buf[128] = {0,};
  size_t outputLength = 0;

  // Characters '-' and '_' chosen because the are part of other encoding
  // standards, other characters chosen at random just to increase test
  // coverage
  const char *input[] =
  {
    "-a==",
    "_a==",
    "&a==",
    "<>=="
  };

  size_t bufSize = (sizeof(buf)/sizeof(buf[0]));
  size_t inputArraySize = (sizeof(input) / sizeof(input[0]));

  for (size_t i = 0; i < inputArraySize; ++i)
  {
    strncpy((char*)buf, input[i], bufSize);
    buf[bufSize] = '\0';
    outputLength = oc_base64_decode(buf, strlen((const char*)buf));
    EXPECT_EQ(-1, outputLength)
      << "Base64 decode for \"" << input[i] << "\" did not fail as expected.";
  }
}

TEST(B64Test, DecodeInputInvalidPadding)
{
  uint8_t buf[128] = {0,};
  size_t outputLength = 0;
  const char *input[] =
  {
      "Zg==Zg==", // Invalid padding in middle of encoded string
      "Zm8=Zm8=", // Invalid padding in middle of encoded string
      "Z===", // Invalid padding max padding for Base64 string is two '=='
      "====", // Invalid padding max padding for Base64 string is two '=='
      "Zm=v" // Invalid padding no characters should follow padding
  };

  size_t bufSize = (sizeof(buf)/sizeof(buf[0]));
  size_t inputArraySize = (sizeof(input) / sizeof(input[0]));

  for (size_t i = 0; i < inputArraySize; ++i)
  {
    strncpy((char*)buf, input[i], bufSize);
    buf[bufSize] = '\0';
    outputLength = oc_base64_decode(buf, strlen((const char*)buf));
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
  char buf[128] = {0};
  int outputLength = 0;
  const char *input[] =
  {
    "foobar",
    "foo"
  };

  const char *output[] =
  {
    "Zm9vYmFy",
    "Zm9v"
  };

  const size_t expectedOutputLenth[] =
  {
    8,
    4
  };

  size_t bufSize = (sizeof(buf)/sizeof(buf[0]));
  size_t inputArraySize = (sizeof(input) / sizeof(input[0]));
  size_t outputArraySize = (sizeof(output) / sizeof(output[0]));
  size_t expectedOutputLenthArraySize = (sizeof(expectedOutputLenth) / sizeof(
      expectedOutputLenth[0]));

  ASSERT_EQ(inputArraySize, outputArraySize)
    << "Input test data and output test data missmatch.";
  ASSERT_EQ(inputArraySize, expectedOutputLenthArraySize)
    << "Input test data and output test data missmatch.";

  for (size_t i = 0; i < inputArraySize; ++i)
  {
    outputLength = oc_base64_encode((const uint8_t *)input[i], strlen(input[i]), (uint8_t *)buf, bufSize);
    EXPECT_NE(-1, outputLength)
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i] << "\"";
    EXPECT_EQ(0u, outputLength % 4)
      << "The return size for all b64Encode operations should be a multiple of 4.";
    if(i == 0 ){ /* expect to pass on first encode due to zero initialized buf */
      EXPECT_STREQ(output[i], buf)
        << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i] << "\"";
    } else { /* expect to fail on second encode due to lack of NUL character */
      EXPECT_STRNE(output[i], buf)
        << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i] << "\"";
    }
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
  }

  for (size_t i = 0; i < inputArraySize; ++i)
  {
    outputLength = oc_base64_encode((const uint8_t *)input[i], strlen(input[i]), (uint8_t *)buf, bufSize);
    EXPECT_NE(-1, outputLength)
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i] << "\"";
    // base64 encoder does not null terminate its output
    buf[outputLength] = '\0';
    EXPECT_EQ(0u, outputLength % 4)
      << "The return size for all b64Encode operations should be a multiple of 4.";
    EXPECT_STREQ(output[i], buf)
      << "Failed to Base64 encode \"" << input[i] << "\" to \"" << output[i] << "\"";
    EXPECT_EQ(expectedOutputLenth[i], outputLength);
  }
}

// verify round trip encoding
TEST(B64Test, EncodeThenDecode)
{

  const char input[] = "This is a string that will be passed into  the Base64 "
                       "encoder.  After it is encoded the encoded result will "
                       "be passed into the Base64 decoded and the result will "
                       "be checked with the original input to make sure the "
                       "round trip results are as expected.";
  int outputLength = 0;
  // Use sizeof instead of strlen to encode the null character at the end of the string.
  size_t b64BufSize = (sizeof(input) / 3) * 4;
  if (sizeof(input) % 3 != 0) {
    b64BufSize += 4;
  }
  b64BufSize++;
  char *b64Buf = (char *)calloc(1, b64BufSize);
  ASSERT_NE(nullptr, b64Buf) << "memory allocation error.";
  outputLength = oc_base64_encode((const uint8_t *)input, sizeof(input), (uint8_t *)b64Buf, b64BufSize);
  EXPECT_NE(-1, outputLength)
    << "Failed to Base64 encode \"" << input << "\" to \"" << (char*)b64Buf << "\"";
  EXPECT_EQ(0u, outputLength % 4) <<
      "The return size for all b64Encode operations should be a multiple of 4.";
  // base64 encoder does not null terminate its output
  b64Buf[outputLength] = '\0';

  outputLength = oc_base64_decode((uint8_t *)b64Buf, strlen(b64Buf));
  EXPECT_NE(-1, outputLength)
    << "Failed to Base64 decode \"" << input << "\" to \"" << b64Buf << "\"";
  EXPECT_EQ(sizeof(input), outputLength);
  EXPECT_STREQ(input, (char *)b64Buf);
  free(b64Buf);
}

