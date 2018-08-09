/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 *
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

#include <cstdlib>
#include "gtest/gtest.h"

extern "C" {
#include "oc_base64.h"
}

#define MAX_OUTPUT_BUFFER_LENGTH 1024

/*
 * @API             : int oc_base64_encode(const uint8_t *input, int input_len,
                     uint8_t *output_buffer, int output_buffer_len);
 * @Description     : test oc_base64_encode api positively
 * @PassCondition   : oc_base64_encode should not return -1
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestBase64, EncodingTest_P)
{
    uint8_t inputData[] = "123456";
    uint8_t outputData[MAX_OUTPUT_BUFFER_LENGTH];
    int outputLength, inputLength = 6;
    outputLength = MAX_OUTPUT_BUFFER_LENGTH;
    int ret = oc_base64_encode(inputData, inputLength, outputData, outputLength);
    ASSERT_NE(ret, -1);
    EXPECT_EQ(ret, inputLength * 4 / 3);
}

/*
 * @API             : int oc_base64_encode(const uint8_t *input, int input_len,
                     uint8_t *output_buffer, int output_buffer_len);
 * @Description     : test oc_base64_encode api negatively
 * @PassCondition   : oc_base64_encode should return -1
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestBase64, EmptyEncodingTest_N)
{
    uint8_t inputData[] = "123456";
    uint8_t outputData[MAX_OUTPUT_BUFFER_LENGTH];
    int outputLength, inputLength = 6;
    outputLength = 0;
    int ret = oc_base64_encode(inputData, inputLength, outputData, outputLength);
    ASSERT_EQ(ret, -1);
}

/*
 * @API             : int oc_base64_encode(const uint8_t *input, int input_len,
                     uint8_t *output_buffer, int output_buffer_len);
 * @Description     : test oc_base64_encode api positively
 * @PassCondition   : oc_base64_encode return verdict checking
 * @PreCondition    : with padding
 * @PostCondition   : N/A
*/
TEST(TestBase64, EncodingWithPaddingTest_P)
{
    uint8_t inputData[] = "1234567";
    uint8_t outputData[MAX_OUTPUT_BUFFER_LENGTH];
    int outputLength, inputLength = 7;
    outputLength = MAX_OUTPUT_BUFFER_LENGTH;
    int ret = oc_base64_encode(inputData, inputLength, outputData, outputLength);
    ASSERT_NE(ret, -1);
    EXPECT_EQ(ret, (inputLength / 3 ) * 4 + 4 * ((inputLength % 3) > 0));
}

/*
 * @API             : int oc_base64_decode(uint8_t *str, int len);
 * @Description     : oc_base64_decode api positively
 * @PassCondition   : oc_base64_decode should not return -1
 * @PreCondition    : with padding
 * @PostCondition   : N/A
*/
TEST(TestBase64, DecodingTest_P)
{
    uint8_t inputData[] = "12345678";
    int inputLength = 8;
    int ret = oc_base64_decode(inputData, inputLength);
    ASSERT_NE(ret, -1);
    EXPECT_EQ(ret, inputLength * 3 / 4);
}

/*
 * @API             : int oc_base64_decode(uint8_t *str, int len);
 * @Description     : oc_base64_decode api positively
 * @PassCondition   : oc_base64_decode should not return -1
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestBase64, PaddedDecodingTest_P)
{
    uint8_t inputData[] = "12345+/=";
    int inputLength = 8;
    int ret = oc_base64_decode(inputData, inputLength);
    ASSERT_NE(ret, -1);
    EXPECT_EQ(ret, (inputLength * 3 - 3) / 4);
}

/*
 * @API             : int oc_base64_decode(uint8_t *str, int len);
 * @Description     : oc_base64_decode api negatively
 * @PassCondition   : oc_base64_decode should return -1
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestBase64, InvalidDecodingTest_N)
{
    uint8_t inputData[] = "12345@#$";
    int inputLength = 8;
    int ret = oc_base64_decode(inputData, inputLength);
    ASSERT_EQ(ret, -1);
}
