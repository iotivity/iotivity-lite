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

#include "api/oc_rep_decode_internal.h"

#include <gtest/gtest.h>

class TestRepDecode : public testing::Test {};

TEST_F(TestRepDecode, SetTypeByContentFormat)
{
  auto is_accepted_format = [](oc_content_format_t cf) {
    return cf == APPLICATION_CBOR || cf == APPLICATION_VND_OCF_CBOR
#ifdef OC_JSON_ENCODER
           || cf == APPLICATION_JSON || cf == APPLICATION_TD_JSON
#endif /* OC_JSON_ENCODER */
      ;
  };

  for (int i = 0; i < APPLICATION_NOT_DEFINED; ++i) {
    auto cf = static_cast<oc_content_format_t>(i);
    if (is_accepted_format(cf)) {
      EXPECT_TRUE(oc_rep_decoder_set_by_content_format(cf));
      oc_rep_decoder_type_t exp_type = OC_REP_CBOR_DECODER;
#ifdef OC_JSON_ENCODER
      if (cf == APPLICATION_JSON || cf == APPLICATION_TD_JSON) {
        exp_type = OC_REP_JSON_DECODER;
      }
#endif /* OC_JSON_ENCODER */
      EXPECT_EQ(exp_type, oc_rep_decoder_get_type());
      continue;
    }
    EXPECT_FALSE(oc_rep_decoder_set_by_content_format(cf))
      << "unexpected valid decoder for cf: " << cf;
  }

  EXPECT_TRUE(oc_rep_decoder_set_by_content_format(APPLICATION_NOT_DEFINED));
  EXPECT_EQ(OC_REP_CBOR_DECODER, oc_rep_decoder_get_type());
}

TEST_F(TestRepDecode, ParseFail)
{
  EXPECT_EQ(-1, oc_parse_rep(nullptr, 0, nullptr));
}
