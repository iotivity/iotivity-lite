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

#include "util/oc_numeric_internal.h"

#include "gtest/gtest.h"

#include <array>
#include <string.h>

TEST(TestNumeric, DoubleIsZero)
{
  EXPECT_TRUE(oc_double_is_zero(0.0));
  EXPECT_TRUE(oc_double_is_zero(0));
  std::array<double, 1> d;
  memset(&d[0], 0, sizeof(double));
  EXPECT_TRUE(oc_double_is_zero(d[0]));

  EXPECT_FALSE(oc_double_is_zero(0.0001));
  EXPECT_FALSE(oc_double_is_zero(1));
}
