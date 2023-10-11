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

#include "encoder/TestEncoderBuffer.h"

#include "api/oc_rep_encode_internal.h"
#include "oc_buffer_settings.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"
#include "tests/gtest/RepPool.h"

#include <gtest/gtest.h>
#include <map>
#include <vector>

class TestRepEncode : public testing::Test {
public:
  static void SetUpTestCase() { TestEncoderBuffer::StoreDefaults(); }

  void TearDown() override { TestEncoderBuffer::RestoreDefaults(); }
};

TEST_F(TestRepEncode, SetEncoderByAccept)
{
  ASSERT_TRUE(oc_rep_encoder_set_type_by_accept(APPLICATION_NOT_DEFINED));
  EXPECT_EQ(OC_REP_CBOR_ENCODER, oc_rep_encoder_get_type());

  std::map<oc_content_format_t, oc_rep_encoder_type_t> encoders{
    { APPLICATION_CBOR, OC_REP_CBOR_ENCODER },
    { APPLICATION_VND_OCF_CBOR, OC_REP_CBOR_ENCODER },
#ifdef OC_JSON_ENCODER
    { APPLICATION_JSON, OC_REP_JSON_ENCODER },
    { APPLICATION_TD_JSON, OC_REP_JSON_ENCODER },
#endif /* OC_JSON_ENCODER */
    { APPLICATION_NOT_DEFINED, OC_REP_CBOR_ENCODER },
  };

  oc_rep_encoder_type_t et = oc_rep_encoder_get_type();
  for (int cf = 0; cf < APPLICATION_NOT_DEFINED; ++cf) {
    if (encoders.find(static_cast<oc_content_format_t>(cf)) != encoders.end()) {
      EXPECT_TRUE(oc_rep_encoder_set_type_by_accept(
        static_cast<oc_content_format_t>(cf)));
      et = oc_rep_encoder_get_type();
      EXPECT_EQ(encoders[static_cast<oc_content_format_t>(cf)], et);
      continue;
    }
    EXPECT_FALSE(
      oc_rep_encoder_set_type_by_accept(static_cast<oc_content_format_t>(cf)));
    EXPECT_EQ(et, oc_rep_encoder_get_type());
  }
}

TEST_F(TestRepEncode, GetContentFormat)
{
  oc_content_format_t cf{};
  oc_rep_encoder_set_type(OC_REP_CBOR_ENCODER);
  ASSERT_TRUE(oc_rep_encoder_get_content_format(&cf));
  EXPECT_EQ(APPLICATION_VND_OCF_CBOR, cf);
#ifdef OC_JSON_ENCODER
  oc_rep_encoder_set_type(OC_REP_JSON_ENCODER);
  ASSERT_TRUE(oc_rep_encoder_get_content_format(&cf));
  EXPECT_EQ(APPLICATION_JSON, cf);
#endif /* OC_JSON_ENCODER */
#ifdef OC_HAS_FEATURE_CRC_ENCODER
  oc_rep_encoder_set_type(OC_REP_CRC_ENCODER);
  ASSERT_FALSE(oc_rep_encoder_get_content_format(&cf));
#endif /* OC_HAS_FEATURE_CRC_ENCODER */
}

TEST_F(TestRepEncode, ShrinkEncoderBuffer)
{
  EXPECT_EQ(nullptr, oc_rep_shrink_encoder_buf(nullptr));

  uint8_t byte;
  EXPECT_EQ(&byte, oc_rep_shrink_encoder_buf(&byte));

#ifdef OC_DYNAMIC_ALLOCATION
  // with enabled realloc
  auto *buf = static_cast<uint8_t *>(malloc(1));
  oc_rep_new_realloc_v1(&buf, 1, 8);
  EXPECT_EQ(buf, oc_rep_shrink_encoder_buf(buf));

  // with disabled realloc
  oc_rep_new_v1(buf, 1);
  EXPECT_EQ(buf, oc_rep_shrink_encoder_buf(buf));

  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  memset(oc_rep_global_encoder(), 0, sizeof(oc_rep_encoder_t));
}

#ifdef OC_DYNAMIC_ALLOCATION

TEST_F(TestRepEncode, ShrinkBuffer_Fail)
{
  oc_rep_encoder_t encoder{};
  // buffer.enable_realloc is false
  EXPECT_FALSE(oc_rep_encoder_shrink_buffer(&encoder));

  encoder.buffer.enable_realloc = true;
  // buffer.pptr is nullptr
  EXPECT_FALSE(oc_rep_encoder_shrink_buffer(&encoder));

  // shrink not needed -> buffer is larger than the payload
  constexpr size_t kBufferSize = 8;
  constexpr size_t kMaxBufferSize = 1024;
  auto *buf = static_cast<uint8_t *>(malloc(kBufferSize));
  oc_rep_encoder_buffer_t eb{};
  eb.ptr = buf;
  eb.pptr = &buf;
  eb.size = kBufferSize;
  eb.max_size = kMaxBufferSize;
  eb.enable_realloc = true;
  encoder = oc_rep_encoder(OC_REP_CBOR_ENCODER, eb);
  EXPECT_FALSE(oc_rep_encoder_shrink_buffer(&encoder));
  free(buf);
}

TEST_F(TestRepEncode, WriteRaw_Fail)
{
  constexpr size_t kBufferSize = 8;
  constexpr size_t kMaxBufferSize = 1024;
  auto *buf = static_cast<uint8_t *>(malloc(kBufferSize));
  oc_rep_encoder_buffer_t eb{};
  eb.ptr = buf;
  eb.pptr = &buf;
  eb.size = kBufferSize;
  eb.max_size = kMaxBufferSize;
  eb.enable_realloc = false;
  oc_rep_encoder_t encoder = oc_rep_encoder(OC_REP_CBOR_ENCODER, eb);

  std::vector<uint8_t> rawData{};
  rawData.resize(kBufferSize + 1);
  // buffer too small and enable_realloc == false
  EXPECT_EQ(CborErrorOutOfMemory,
            oc_rep_encoder_write_raw(&encoder, rawData.data(), rawData.size()));

  // buffer too small, and maximum size is smaller than the payload
  eb.enable_realloc = true;
  encoder = oc_rep_encoder(OC_REP_CBOR_ENCODER, eb);
  ASSERT_EQ(CborNoError,
            oc_rep_encoder_write_raw(&encoder, rawData.data(), rawData.size()));

  encoder = oc_rep_encoder(OC_REP_CBOR_ENCODER, eb);
  rawData.resize(kMaxBufferSize + 1);
  EXPECT_EQ(CborErrorOutOfMemory,
            oc_rep_encoder_write_raw(&encoder, rawData.data(), rawData.size()));
  free(buf);
}

#endif /* OC_DYNAMIC_ALLOCATION */

TEST_F(TestRepEncode, MultipleCBorEncoders)
{
  TestEncoderBuffer cborBuf1{ OC_REP_CBOR_ENCODER };
  cborBuf1.SetRepBuffer(1, 1024);

  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, hello, "world");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cborEncoder1 = oc_rep_global_encoder_reset(nullptr);

  TestEncoderBuffer cborBuf2{ OC_REP_CBOR_ENCODER };
  cborBuf2.SetRepBuffer(1, 1024);
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, int, 42);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cbor2Rep = cborBuf2.ParsePayload();
  ASSERT_NE(nullptr, cbor2Rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(cbor2Rep.get(), true).data());

  oc_rep_global_encoder_reset(&cborEncoder1);
  oc_rep_set_text_string(root, goodbye, "underworld");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cbor1Rep = cborBuf1.ParsePayload();
  ASSERT_NE(nullptr, cbor1Rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(cbor1Rep.get(), true).data());
}

#ifdef OC_JSON_ENCODER

TEST_F(TestRepEncode, JsonAndCborEncoder)
{
  TestEncoderBuffer cborBuf1{ OC_REP_JSON_ENCODER };
  cborBuf1.SetRepBuffer(1, 1024);

  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, hello, "world");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cborEncoder1 = oc_rep_global_encoder_reset(nullptr);

  TestEncoderBuffer cborBuf2{ OC_REP_CBOR_ENCODER };
  cborBuf2.SetRepBuffer(1, 1024);
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, int, 42);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cbor2Rep = cborBuf2.ParsePayload();
  ASSERT_NE(nullptr, cbor2Rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(cbor2Rep.get(), true).data());

  oc_rep_global_encoder_reset(&cborEncoder1);
  oc_rep_set_text_string(root, goodbye, "underworld");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cbor1Rep = cborBuf1.ParsePayload();
  ASSERT_NE(nullptr, cbor1Rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(cbor1Rep.get(), true).data());
}

#endif /* OC_JSON_ENCODER */

#ifdef OC_HAS_FEATURE_CRC_ENCODER

TEST_F(TestRepEncode, CborAndCrcEncoder)
{
  TestEncoderBuffer cborBuf1{ OC_REP_CBOR_ENCODER };
  cborBuf1.SetRepBuffer(1, 1024);

  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, hello, "world");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cborEncoder1 = oc_rep_global_encoder_reset(nullptr);

  TestEncoderBuffer cborBuf2{ OC_REP_CRC_ENCODER };
  cborBuf2.SetRepBuffer(1, 1024);
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, hello, "world");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  int payload_len = oc_rep_get_encoded_payload_size();
  uint64_t crc;
  ASSERT_EQ(sizeof(crc), payload_len);
  const uint8_t *payload = oc_rep_get_encoder_buf();
  memcpy(&crc, payload, sizeof(crc));

  oc_rep_global_encoder_reset(&cborEncoder1);
  oc_rep_set_uint(root, crc, crc);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto cbor1Rep = cborBuf1.ParsePayload();
  ASSERT_NE(nullptr, cbor1Rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(cbor1Rep.get(), true).data());
}

#endif /* OC_HAS_FEATURE_CRC_ENCODER */
