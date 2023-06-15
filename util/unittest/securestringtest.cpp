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

#include "util/oc_secure_string_internal.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

TEST(TestSecureString, oc_strnlen)
{
  EXPECT_EQ(0, oc_strnlen_s("", 0));

  std::string nullTerminated = "test";
  EXPECT_EQ(nullTerminated.length(),
            oc_strnlen(nullTerminated.c_str(), nullTerminated.size()));
  // early termination
  EXPECT_EQ(2, oc_strnlen_s(nullTerminated.c_str(), 2));

  std::vector<char> nonNullTerminated = { 't', 'e', 's', 't' };
  EXPECT_EQ(nonNullTerminated.size(),
            oc_strnlen(nonNullTerminated.data(), nonNullTerminated.size()));

  // string with multiple null terminators
  std::vector<char> multipleNullTerminators = {
    't', 'e', '\0', 's', 't', '\0'
  };
  EXPECT_EQ(2, oc_strnlen(multipleNullTerminators.data(),
                          multipleNullTerminators.size()));
}

TEST(TestSecureString, oc_strnlen_s)
{
  EXPECT_EQ(0, oc_strnlen_s(nullptr, 0));
  EXPECT_EQ(0, oc_strnlen_s("", 0));

  std::string nullTerminated = "test";
  EXPECT_EQ(nullTerminated.length(),
            oc_strnlen_s(nullTerminated.c_str(), nullTerminated.size()));
  // early termination
  EXPECT_EQ(2, oc_strnlen_s(nullTerminated.c_str(), 2));

  std::vector<char> nonNullTerminated = { 't', 'e', 's', 't' };
  EXPECT_EQ(nonNullTerminated.size(),
            oc_strnlen_s(nonNullTerminated.data(), nonNullTerminated.size()));

  // string with multiple null terminators
  std::vector<char> multipleNullTerminators = {
    't', 'e', '\0', 's', 't', '\0'
  };
  EXPECT_EQ(2, oc_strnlen_s(multipleNullTerminators.data(),
                            multipleNullTerminators.size()));
}
