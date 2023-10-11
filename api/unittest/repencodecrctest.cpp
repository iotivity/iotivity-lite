/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_CRC_ENCODER

#include "encoder/TestEncoderBuffer.h"

#include "api/oc_rep_encode_crc_internal.h"
#include "oc_rep.h"
#include "tests/gtest/Utility.h"
#include "util/oc_crc_internal.h"

#include <array>
#include <cbor.h>
#include <cfloat>
#include <gtest/gtest.h>
#include <memory>
#include <optional>

class TestCrcRepEncodeWithRealloc : public testing::Test {
public:
  static void SetUpTestCase()
  {
    TestEncoderBuffer::StoreDefaults();
    TestCrcRepEncodeWithRealloc::encoder =
      std::make_unique<TestEncoderBuffer>(OC_REP_CRC_ENCODER);
    ASSERT_EQ(OC_REP_CRC_ENCODER, oc_rep_encoder_get_type());
  }

  static void TearDownTestCase()
  {
    TestCrcRepEncodeWithRealloc::encoder.reset();
    TestEncoderBuffer::RestoreDefaults();
  }

  static void SetRepBuffer(size_t size = 1024, size_t max_size = 1024)
  {
    TestCrcRepEncodeWithRealloc::encoder->SetRepBuffer(size, max_size);
  }

  static void Shrink() { TestCrcRepEncodeWithRealloc::encoder->Shrink(); }

  static std::optional<uint64_t> geyPayloadCRC()
  {
    const uint8_t *payload = oc_rep_get_encoder_buf();
    int payload_len = oc_rep_get_encoded_payload_size();
    uint64_t crc;
    if (payload_len != sizeof(crc)) {
      return {};
    }
    memcpy(&crc, payload, sizeof(crc));
    return crc;
  }

  static std::unique_ptr<TestEncoderBuffer> encoder;
};

std::unique_ptr<TestEncoderBuffer> TestCrcRepEncodeWithRealloc::encoder{
  nullptr
};

static uint64_t
calculateCrc(uint64_t crc, CborType type, const uint8_t *buffer, size_t size)
{
  if (CborInvalidType != type) {
    auto dt = static_cast<uint8_t>(type);
    crc = oc_crc64(crc, &dt, 1);
  }
  return oc_crc64(crc, buffer, size);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeNull)
{
  SetRepBuffer(1, 0);
  EXPECT_EQ(CborErrorOutOfMemory, oc_rep_encode_null(oc_rep_get_encoder()));

  SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError, oc_rep_encode_null(oc_rep_get_encoder()));

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  uint64_t expCrc = calculateCrc(0, CborNullType, nullptr, 0);
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeBool)
{
  SetRepBuffer(1, 1);
  EXPECT_EQ(CborErrorOutOfMemory,
            oc_rep_encode_boolean(oc_rep_get_encoder(), true));

  SetRepBuffer(1, 8);
  std::vector<uint8_t> crcData{};
  uint64_t expCrc = 0;
  for (size_t i = 0; i < 8; ++i) {
    bool value = i % 2 == 0;
    ASSERT_EQ(CborNoError, oc_rep_encode_boolean(oc_rep_get_encoder(), value));
    crcData.push_back(value ? OC_CRC_REP_TRUE : OC_CRC_REP_FALSE);
    expCrc = calculateCrc(expCrc, CborBooleanType, &crcData[i], 1);
  }

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeInt)
{
  SetRepBuffer(1, 2);
  int64_t value = INT64_MAX;
  EXPECT_EQ(CborErrorOutOfMemory,
            oc_rep_encode_int(oc_rep_get_encoder(), value));

  SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError, oc_rep_encode_int(oc_rep_get_encoder(), value));

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  std::array<uint8_t, sizeof(value)> crcData{};
  memcpy(&crcData[0], &value, sizeof(value));
  uint64_t expCrc =
    calculateCrc(0, CborIntegerType, crcData.data(), crcData.size());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeUint)
{
  SetRepBuffer(1, 3);
  uint64_t value = UINT64_MAX;
  EXPECT_EQ(CborErrorOutOfMemory,
            oc_rep_encode_uint(oc_rep_get_encoder(), value));

  SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError, oc_rep_encode_uint(oc_rep_get_encoder(), value));

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  std::array<uint8_t, sizeof(value)> crcData{};
  memcpy(&crcData[0], &value, sizeof(value));
  uint64_t expCrc =
    calculateCrc(0, CborIntegerType, crcData.data(), crcData.size());
  EXPECT_EQ(expCrc, *crc);
}

template<typename FloatType>
static void
encodeFloat()
{
  TestCrcRepEncodeWithRealloc::SetRepBuffer(1, 4);
  FloatType value = std::numeric_limits<FloatType>::max();

  CborType fp = CborInvalidType;
  if (sizeof(FloatType) == sizeof(uint16_t)) {
    fp = CborHalfFloatType;
  } else if (sizeof(FloatType) == sizeof(float)) {
    fp = CborFloatType;
  } else if (sizeof(FloatType) == sizeof(double)) {
    fp = CborDoubleType;
  }
  if (fp == CborInvalidType) {
    return;
  }

  EXPECT_EQ(CborErrorOutOfMemory,
            oc_rep_encode_floating_point(oc_rep_get_encoder(), fp, &value));
  TestCrcRepEncodeWithRealloc::SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError,
            oc_rep_encode_floating_point(oc_rep_get_encoder(), fp, &value));

  auto crc = TestCrcRepEncodeWithRealloc::geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  std::array<uint8_t, sizeof(FloatType)> crcData{};
  memcpy(&crcData[0], &value, sizeof(value));
  uint64_t expCrc = calculateCrc(0, fp, crcData.data(), crcData.size());
  EXPECT_EQ(expCrc, *crc);
}

#ifdef HAVE_FLOAT16

TEST_F(TestCrcRepEncodeWithRealloc, EncodeFloat16)
{
  encodeFloat<_Float16>();
}

#endif /* HAVE_FLOAT16 */

TEST_F(TestCrcRepEncodeWithRealloc, EncodeFloat)
{
  encodeFloat<float>();
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeDoubleFloat)
{
  encodeFloat<double>();
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeFloat_Fail)
{
  SetRepBuffer(1, 8);
  bool value = true;
  EXPECT_NE(CborNoError, oc_rep_encode_floating_point(oc_rep_get_encoder(),
                                                      CborBooleanType, &value));
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeDouble)
{
  SetRepBuffer(1, 5);
  double value = std::numeric_limits<double>::max();
  EXPECT_EQ(CborErrorOutOfMemory,
            oc_rep_encode_double(oc_rep_get_encoder(), value));
  SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError, oc_rep_encode_double(oc_rep_get_encoder(), value));

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  std::array<uint8_t, sizeof(value)> crcData{};
  memcpy(&crcData[0], &value, sizeof(value));
  uint64_t expCrc =
    calculateCrc(0, CborDoubleType, crcData.data(), crcData.size());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeByteString)
{
  SetRepBuffer(1, 6);
  std::vector<uint8_t> bstr = { 0x42, 0x0,  0x42, 0x0,  0x42, 0x0,  0x42, 0x42,
                                0x0,  0x42, 0x0,  0x42, 0x0,  0x42, 0x42, 0x0 };
  EXPECT_EQ(
    CborErrorOutOfMemory,
    oc_rep_encode_byte_string(oc_rep_get_encoder(), bstr.data(), bstr.size()));

  SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError, oc_rep_encode_byte_string(oc_rep_get_encoder(),
                                                   bstr.data(), bstr.size()));

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  uint64_t expCrc =
    calculateCrc(0, CborByteStringType, bstr.data(), bstr.size());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeTextString)
{
  SetRepBuffer(1, 7);
  std::string str = "test";
  EXPECT_EQ(
    CborErrorOutOfMemory,
    oc_rep_encode_text_string(oc_rep_get_encoder(), str.c_str(), str.length()));

  SetRepBuffer(1, 8);
  str = "this is 16 chars";
  ASSERT_EQ(CborNoError, oc_rep_encode_text_string(oc_rep_get_encoder(),
                                                   str.c_str(), str.length()));
  ASSERT_EQ(8, oc_rep_get_encoded_payload_size());

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  auto data = oc::GetVector<uint8_t>(str);
  uint64_t expCrc =
    calculateCrc(0, CborTextStringType, data.data(), data.size());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeArray)
{
  SetRepBuffer(1, 1);
  CborEncoder array{};
  ASSERT_EQ(CborErrorOutOfMemory,
            oc_rep_encoder_create_array(oc_rep_get_encoder(), &array,
                                        CborIndefiniteLength));

  SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError, oc_rep_encoder_create_array(
                           oc_rep_get_encoder(), &array, CborIndefiniteLength));
  uint8_t openByte = OC_CRC_OPEN_CONTAINER;
  uint8_t closeByte = OC_CRC_CLOSE_CONTAINER;
  uint64_t expCrc = calculateCrc(0, CborArrayType, &openByte, 1);

  ASSERT_EQ(CborNoError,
            oc_rep_encoder_close_container(oc_rep_get_encoder(), &array));
  expCrc = calculateCrc(expCrc, CborArrayType, &closeByte, 1);

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeArrayOfArrays)
{
  SetRepBuffer(1, 8);

  CborEncoder array{};
  ASSERT_EQ(CborNoError, oc_rep_encoder_create_array(
                           oc_rep_get_encoder(), &array, CborIndefiniteLength));
  const uint8_t openByte = OC_CRC_OPEN_CONTAINER;
  const uint8_t closeByte = OC_CRC_CLOSE_CONTAINER;
  uint64_t expCrc = calculateCrc(0, CborArrayType, &openByte, 1);

  // bool array
  CborEncoder boolArray{};
  ASSERT_EQ(CborNoError, oc_rep_encoder_create_array(&array, &boolArray,
                                                     CborIndefiniteLength));
  expCrc = calculateCrc(expCrc, CborArrayType, &openByte, 1);

  uint8_t boolValue = OC_CRC_REP_TRUE;
  ASSERT_EQ(CborNoError, oc_rep_encode_boolean(&boolArray, true));
  expCrc = calculateCrc(expCrc, CborBooleanType, &boolValue, 1);

  boolValue = OC_CRC_REP_FALSE;
  ASSERT_EQ(CborNoError, oc_rep_encode_boolean(&boolArray, false));
  expCrc = calculateCrc(expCrc, CborBooleanType, &boolValue, 1);

  ASSERT_EQ(CborNoError, oc_rep_encoder_close_container(&array, &boolArray));
  expCrc = calculateCrc(expCrc, CborArrayType, &closeByte, 1);

  // integer Array
  CborEncoder intArray{};
  ASSERT_EQ(CborNoError, oc_rep_encoder_create_array(&array, &intArray,
                                                     CborIndefiniteLength));
  expCrc = calculateCrc(expCrc, CborArrayType, &openByte, 1);

  int64_t intValue = 0;
  ASSERT_EQ(CborNoError, oc_rep_encode_int(&intArray, intValue));
  std::array<uint8_t, sizeof(intValue)> crcData{};
  memcpy(&crcData[0], &intValue, sizeof(intValue));
  expCrc =
    calculateCrc(expCrc, CborIntegerType, crcData.data(), crcData.size());

  intValue = 42;
  ASSERT_EQ(CborNoError, oc_rep_encode_int(&intArray, intValue));
  memcpy(&crcData[0], &intValue, sizeof(intValue));
  expCrc =
    calculateCrc(expCrc, CborIntegerType, crcData.data(), crcData.size());

  ASSERT_EQ(CborNoError, oc_rep_encoder_close_container(&array, &intArray));
  expCrc = calculateCrc(expCrc, CborArrayType, &closeByte, 1);

  ASSERT_EQ(CborNoError,
            oc_rep_encoder_close_container(oc_rep_get_encoder(), &array));
  expCrc = calculateCrc(expCrc, CborArrayType, &closeByte, 1);

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodeMap)
{
  SetRepBuffer(1, 1);
  CborEncoder map{};
  ASSERT_EQ(CborErrorOutOfMemory,
            oc_rep_encoder_create_map(oc_rep_get_encoder(), &map,
                                      CborIndefiniteLength));

  SetRepBuffer(1, 8);
  ASSERT_EQ(CborNoError, oc_rep_encoder_create_map(oc_rep_get_encoder(), &map,
                                                   CborIndefiniteLength));
  const uint8_t openByte = OC_CRC_OPEN_CONTAINER;
  const uint8_t closeByte = OC_CRC_CLOSE_CONTAINER;
  uint64_t expCrc = calculateCrc(0, CborMapType, &openByte, 1);

  ASSERT_EQ(CborNoError,
            oc_rep_encoder_close_container(oc_rep_get_encoder(), &map));
  expCrc = calculateCrc(expCrc, CborMapType, &closeByte, 1);

  auto crc = geyPayloadCRC();
  ASSERT_TRUE(crc.has_value());
  EXPECT_EQ(expCrc, *crc);
}

TEST_F(TestCrcRepEncodeWithRealloc, EncodedPayloadRealloc)
{
  SetRepBuffer(1, 1024);

  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, hello, "world");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_double(root, double, 3.14);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(root, bool, true);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, int, -1);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_uint(root, uint, -1);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<uint8_t> byte_string = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
  oc_rep_set_byte_string(root, byte_string_key, byte_string.data(),
                         byte_string.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<int> fib = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
  oc_rep_set_key(oc_rep_object(root), "fibonacci");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_begin_array(oc_rep_object(root), fibonacci);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (const auto &val : fib) {
    oc_rep_add_int(fibonacci, val);
    ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_end_array(oc_rep_object(root), fibonacci);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<double> math_constants = { 3.14159, 2.71828, 1.414121, 1.61803 };
  oc_rep_set_double_array(root, math_constants, math_constants.data(),
                          math_constants.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  size_t payload_size = oc_rep_get_encoded_payload_size();
  EXPECT_EQ(8, payload_size);
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_GT(oc_rep_get_encoder_buffer_size(), payload_size);
#endif /* OC_DYNAMIC_ALLOCATION */
  Shrink();
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(oc_rep_get_encoder_buffer_size(), payload_size);
#endif /* OC_DYNAMIC_ALLOCATION */
}

#endif /* OC_HAS_FEATURE_CRC_ENCODER */
