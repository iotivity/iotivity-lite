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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_CRC_ENCODER

#include "util/oc_crc_internal.h"

#include <gtest/gtest.h>

TEST(TestCRC, CRC64)
{
  struct test
  {
    std::string input;
    uint64_t crc;
  };

  std::vector<test> inputs{
    { "", 0x0 },
    { "Hello, World!", 0xA885B0FA12A6B582 },
    { "1234567890", 0x4CCE99FD976EC1A8 },
    { "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
      0x9A076C1F9CFD879C },
    { "IoTivity-Lite is the best IoT C library on the flat plane!",
      0xB54B2DCA2CFA4D9E },
  };

  for (auto &input : inputs) {
    EXPECT_EQ(input.crc,
              oc_crc64(0, (uint8_t *)&input.input[0], input.input.size()));
  }
}

#endif /* OC_HAS_FEATURE_CRC_ENCODER */
