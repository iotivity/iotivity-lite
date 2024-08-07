/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "api/oc_enums_internal.h"

#include "gtest/gtest.h"
#include <limits>
#include <string>

TEST(TestEnums, OCEnum)
{
  EXPECT_EQ(nullptr, oc_enum_to_str(static_cast<oc_enum_t>(0)));
  if constexpr (static_cast<oc_enum_t>(std::numeric_limits<int>::max()) >
                OC_ENUM_ZIGZAG) {
    EXPECT_EQ(nullptr, oc_enum_to_str(static_cast<oc_enum_t>(
                         std::numeric_limits<int>::max())));
  }

  for (int i = OC_ENUM_ABORTED; i <= OC_ENUM_ZIGZAG; ++i) {
    const char *c_str = oc_enum_to_str(static_cast<oc_enum_t>(i));
    ASSERT_NE(c_str, nullptr);

    std::string str(c_str);
    oc_enum_t enum_val;
    EXPECT_TRUE(oc_enum_from_str(str.c_str(), str.length(), &enum_val));
    EXPECT_EQ(enum_val, static_cast<oc_enum_t>(i));
  }

  oc_enum_t enum_val;
  EXPECT_FALSE(oc_enum_from_str(nullptr, 0, &enum_val));
}

TEST(TestEnums, OCPosDescription)
{
  EXPECT_EQ(nullptr,
            oc_enum_pos_desc_to_str(static_cast<oc_pos_description_t>(0)));
  if constexpr (std::numeric_limits<int>::max() > OC_POS_BOTTOMCENTRE) {
    EXPECT_EQ(nullptr,
              oc_enum_pos_desc_to_str(static_cast<oc_pos_description_t>(
                std::numeric_limits<int>::max())));
  }

  for (int i = OC_POS_UNKNOWN; i <= OC_POS_BOTTOMCENTRE; ++i) {
    const char *c_str =
      oc_enum_pos_desc_to_str(static_cast<oc_pos_description_t>(i));
    ASSERT_NE(c_str, nullptr);

    std::string str(c_str);
    oc_pos_description_t pos_val;
    EXPECT_TRUE(oc_enum_pos_desc_from_str(str.c_str(), str.length(), &pos_val));
    EXPECT_EQ(pos_val, static_cast<oc_pos_description_t>(i));
  }

  oc_pos_description_t pos_val;
  EXPECT_FALSE(oc_enum_pos_desc_from_str(nullptr, 0, &pos_val));
}

TEST(TestEnums, OCLocn)
{
  EXPECT_EQ(nullptr, oc_enum_locn_to_str(static_cast<oc_locn_t>(0)));
  if constexpr (std::numeric_limits<int>::max() > OCF_LOCN_YARD) {
    EXPECT_EQ(nullptr, oc_enum_locn_to_str(static_cast<oc_locn_t>(
                         std::numeric_limits<int>::max())));
  }

  for (int i = OCF_LOCN_UNKNOWN; i <= OCF_LOCN_YARD; ++i) {
    const char *c_str = oc_enum_locn_to_str(static_cast<oc_locn_t>(i));
    ASSERT_NE(c_str, nullptr);

    std::string str(c_str);
    oc_locn_t locn_val;
    EXPECT_TRUE(oc_enum_locn_from_str(str.c_str(), str.length(), &locn_val));
    EXPECT_EQ(locn_val, static_cast<oc_locn_t>(i));

    oc_string_t ocstr;
    ocstr.ptr = &str[0];
    ocstr.size = str.length() + 1;
    bool ok;
    locn_val = oc_str_to_enum_locn(ocstr, &ok);
    ASSERT_TRUE(ok);
    EXPECT_EQ(locn_val, static_cast<oc_locn_t>(i));
  }

  oc_locn_t locn_val;
  EXPECT_FALSE(oc_enum_locn_from_str(nullptr, 0, &locn_val));

  oc_string_t ocstr;
  ocstr.ptr = nullptr;
  ocstr.size = 0;
  bool ok;
  locn_val = oc_str_to_enum_locn(ocstr, &ok);
  ASSERT_FALSE(ok);
}
