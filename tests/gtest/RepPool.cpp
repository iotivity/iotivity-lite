/****************************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "RepPool.h"

#include "gtest/gtest.h"

namespace oc {

RepPool::RepPool(size_t size)
  : size_{ size }
{
#ifdef OC_DYNAMIC_ALLOCATION
  oc_rep_new_realloc(&buffer_, 0, size);
#else
  buffer_.resize(size);
  oc_rep_new(buffer_.data(), buffer_.size());
  memset(rep_objects_alloc_, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool_, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
#endif /* OC_DYNAMIC_ALLOCATION */
}

RepPool::~RepPool()
{
#ifdef OC_DYNAMIC_ALLOCATION
  free(buffer_);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
RepPool::Clear()
{
#ifdef OC_DYNAMIC_ALLOCATION
  oc_rep_new_realloc(&buffer_, 0, size_);
#else
  buffer_.resize(size_);
  oc_rep_new(buffer_.data(), buffer_.size());
#endif /* OC_DYNAMIC_ALLOCATION */
}

oc_rep_unique_ptr
RepPool::ParsePayload()
{
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(&rep_objects_);
  oc_rep_t *rep = nullptr;
  EXPECT_EQ(CborNoError, oc_parse_rep(payload, payload_len, &rep));
  return oc_rep_unique_ptr(rep, &oc_free_rep);
}

} // namespace oc
