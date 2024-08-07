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

#include "api/oc_rep_decode_cbor_internal.h"
#include "api/oc_rep_encode_cbor_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_config.h"
#include "oc_helpers.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Utility.h"

#include "gtest/gtest.h"

#include <array>
#include <string>

class TestRepDecodeCbor : public testing::Test {
public:
  void SetUp() override
  {
    oc_rep_set_pool(&rep_objects_);
#ifndef OC_DYNAMIC_ALLOCATION
    memset(rep_objects_alloc_, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool_, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
#endif /* !OC_DYNAMIC_ALLOCATION */
  }

private:
#ifdef OC_DYNAMIC_ALLOCATION
  oc_memb rep_objects_{ sizeof(oc_rep_t), 0, nullptr, nullptr, nullptr };
#else  /* !OC_DYNAMIC_ALLOCATION */
  char rep_objects_alloc_[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool_[OC_MAX_NUM_REP_OBJECTS];
  oc_memb rep_objects_{ sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                        rep_objects_alloc_, (void *)rep_objects_pool_,
                        nullptr };
#endif /* OC_DYNAMIC_ALLOCATION */
};

TEST_F(TestRepDecodeCbor, DecodeRootNull)
{
  CborEncoder encoder;
  std::array<uint8_t, 1024> buffer{};
  cbor_encoder_init(&encoder, &buffer[0], buffer.size(), 0);

  ASSERT_EQ(CborNoError, cbor_encode_null(&encoder));
  const uint8_t *payload = &buffer[0];
  size_t size = cbor_encoder_get_buffer_size(&encoder, &buffer[0]);
  oc_rep_parse_result_t result{};
  ASSERT_EQ(CborNoError, oc_rep_parse_cbor(payload, size, &result));
  EXPECT_EQ(OC_REP_PARSE_RESULT_NULL, result.type);
}

TEST_F(TestRepDecodeCbor, DecodeRootEmptyArray)
{
  CborEncoder encoder;
  std::array<uint8_t, 1024> buffer{};
  cbor_encoder_init(&encoder, &buffer[0], buffer.size(), 0);

  CborEncoder array;
  ASSERT_EQ(CborNoError,
            cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength));
  ASSERT_EQ(CborNoError, cbor_encoder_close_container(&encoder, &array));
  const uint8_t *payload = &buffer[0];
  size_t size = cbor_encoder_get_buffer_size(&encoder, &buffer[0]);
  oc_rep_parse_result_t result{};
  ASSERT_EQ(CborNoError, oc_rep_parse_cbor(payload, size, &result));
  EXPECT_EQ(OC_REP_PARSE_RESULT_EMPTY_ARRAY, result.type);
}

TEST_F(TestRepDecodeCbor, DecodeRootEmptyObject)
{
  CborEncoder encoder;
  std::array<uint8_t, 1024> buffer{};
  cbor_encoder_init(&encoder, &buffer[0], buffer.size(), 0);

  CborEncoder object;
  ASSERT_EQ(CborNoError,
            cbor_encoder_create_map(&encoder, &object, CborIndefiniteLength));
  ASSERT_EQ(CborNoError, cbor_encoder_close_container(&encoder, &object));
  const uint8_t *payload = &buffer[0];
  size_t size = cbor_encoder_get_buffer_size(&encoder, &buffer[0]);
  oc_rep_parse_result_t result{};
  ASSERT_EQ(CborNoError, oc_rep_parse_cbor(payload, size, &result));
  EXPECT_EQ(OC_REP_PARSE_RESULT_REP, result.type);
  EXPECT_EQ(nullptr, result.rep);
}
