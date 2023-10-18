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

#include "TestEncoderBuffer.h"

#include "api/oc_rep_internal.h"
#include "port/oc_log_internal.h"

#include <cstdlib>

oc_rep_encoder_type_t TestEncoderBuffer::default_encoder =
  oc_rep_encoder_get_type();
oc_rep_decoder_type_t TestEncoderBuffer::default_decoder =
  oc_rep_decoder_get_type();

TestEncoderBuffer::TestEncoderBuffer(oc_rep_encoder_type_t encoder_type)
  : encoder_type_(encoder_type)
{
  oc_rep_encoder_set_type(encoder_type);

  if (encoder_type_ == OC_REP_CBOR_ENCODER) {
    oc_rep_decoder_set_type(OC_REP_CBOR_DECODER);
  }
#ifdef OC_JSON_ENCODER
  else if (encoder_type_ == OC_REP_JSON_ENCODER) {
    oc_rep_decoder_set_type(OC_REP_JSON_DECODER);
  }
#endif /* OC_JSON_ENCODER */
}

TestEncoderBuffer::~TestEncoderBuffer()
{
#ifdef OC_DYNAMIC_ALLOCATION
  free(buffer_);
#endif /* OC_DYNAMIC_ALLOCATION */
}

std::optional<oc_rep_decoder_type_t>
TestEncoderBuffer::GetDecoderType() const
{
  if (encoder_type_ == OC_REP_CBOR_ENCODER) {
    return OC_REP_CBOR_DECODER;
  }

#ifdef OC_JSON_ENCODER
  if (encoder_type_ == OC_REP_JSON_ENCODER) {
    return OC_REP_JSON_DECODER;
  }
#endif /* OC_JSON_ENCODER */

  return {};
}

bool
TestEncoderBuffer::HasDecoder() const
{
  return GetDecoderType().has_value();
}

void
TestEncoderBuffer::RestoreDefaults()
{
  oc_rep_encoder_set_type(default_encoder);
  oc_rep_decoder_set_type(default_decoder);
}

void
TestEncoderBuffer::StoreDefaults()
{
  TestEncoderBuffer::default_encoder = oc_rep_encoder_get_type();
  TestEncoderBuffer::default_decoder = oc_rep_decoder_get_type();
}

void
TestEncoderBuffer::SetRepBuffer(size_t size, size_t max_size)
{
#ifdef OC_DYNAMIC_ALLOCATION
  free(buffer_);
  buffer_ = nullptr;
  if (size > 0) {
    buffer_ = static_cast<uint8_t *>(malloc(size));
    memset(buffer_, 0, size);
  }
  oc_rep_new_realloc_v1(&buffer_, size, max_size);
#else  /* OC_DYNAMIC_ALLOCATION */
  (void)size;
  buffer_.resize(max_size);
  oc_rep_new_v1(buffer_.data(), buffer_.size());
  memset(&rep_objects_alloc_[0], 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(&rep_objects_pool_[0], 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
TestEncoderBuffer::Shrink()
{
#ifdef OC_DYNAMIC_ALLOCATION
  buffer_ = oc_rep_shrink_encoder_buf(buffer_);
#endif /* OC_DYNAMIC_ALLOCATION */
}

oc::oc_rep_unique_ptr
TestEncoderBuffer::ParsePayload()
{
  auto dt = GetDecoderType();
  if (!dt.has_value()) {
    return oc::oc_rep_unique_ptr(nullptr, &oc_free_rep);
  }

  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(&rep_objects_);
  oc_rep_t *rep = nullptr;
  oc_rep_decoder_t decoder = oc_rep_decoder(*dt);
  EXPECT_EQ(CborNoError, decoder.parse(payload, payload_len, &rep));
  return oc::oc_rep_unique_ptr(rep, &oc_free_rep);
}
