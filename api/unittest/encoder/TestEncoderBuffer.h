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

#pragma once

#include "api/oc_rep_decode_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "oc_config.h"
#include "oc_rep.h"
#include "tests/gtest/RepPool.h"

#include <array>
#include <gtest/gtest.h>
#include <optional>
#include <vector>

class TestEncoderBuffer {
public:
  explicit TestEncoderBuffer(oc_rep_encoder_type_t encoder_type);
  ~TestEncoderBuffer();

  TestEncoderBuffer(TestEncoderBuffer &other) = delete;
  TestEncoderBuffer &operator=(TestEncoderBuffer &other) = delete;
  TestEncoderBuffer(TestEncoderBuffer &&other) = delete;
  TestEncoderBuffer &operator=(TestEncoderBuffer &&other) = delete;

  static void RestoreDefaults();
  static void StoreDefaults();

  std::optional<oc_rep_decoder_type_t> GetDecoderType() const;
  bool HasDecoder() const;

  /* buffer for oc_rep_t */
  void SetRepBuffer(size_t size = 1024, size_t max_size = 1024);

  void Shrink();

  oc::oc_rep_unique_ptr ParsePayload();

private:
  static oc_rep_encoder_type_t default_encoder;
  static oc_rep_decoder_type_t default_decoder;

  oc_rep_encoder_type_t encoder_type_;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer_{ nullptr };
  oc_memb rep_objects_{ sizeof(oc_rep_t), 0, nullptr, nullptr, nullptr };
#else  /* !OC_DYNAMIC_ALLOCATION */
  std::vector<uint8_t> buffer_{};
  std::array<char, OC_MAX_NUM_REP_OBJECTS> rep_objects_alloc_{};
  std::array<oc_rep_t, OC_MAX_NUM_REP_OBJECTS> rep_objects_pool_{};
  oc_memb rep_objects_{ sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                        rep_objects_alloc_.data(), rep_objects_pool_.data(),
                        nullptr };
#endif /* OC_DYNAMIC_ALLOCATION */
};
