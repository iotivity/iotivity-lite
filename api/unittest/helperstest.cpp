/******************************************************************
 *
 * Copyright 2022 Daniel Adam All Rights Reserved.
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

#include "gtest/gtest.h"
#include "oc_helpers.h"
#include <cstdlib>

TEST(Helpers, ConcatStrings)
{
  oc_string_t str;
  oc_concat_strings(&str, "", "");
  EXPECT_STREQ("", oc_string(str));
  oc_free_string(&str);

  memset(&str, 0, sizeof(str));
  oc_concat_strings(&str, "abc", "");
  EXPECT_STREQ("abc", oc_string(str));
  oc_free_string(&str);

  memset(&str, 0, sizeof(str));
  oc_concat_strings(&str, "", "def");
  EXPECT_STREQ("def", oc_string(str));
  oc_free_string(&str);

  memset(&str, 0, sizeof(str));
  oc_concat_strings(&str, "abc", "def");
  EXPECT_STREQ("abcdef", oc_string(str));
  oc_free_string(&str);
}
