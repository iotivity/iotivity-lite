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

#include "python/oc_python_internal.h"

#include <array>
#include <gtest/gtest.h>
#include <string>

class ResourceDiscoveryPayloadTest : public ::testing::Test {
public:
  static void comparePayloads(const std::string &expected,
                              const std::string &actual)
  {
    ASSERT_STREQ(expected.c_str(), actual.c_str())
      << "Expected: " << expected << "\nActual: " << actual;
  }
};

TEST_F(ResourceDiscoveryPayloadTest, EncodePayload)
{
  std::array<char, 1024> buffer{};

  // Call the function with valid inputs
  ASSERT_TRUE(encode_resource_discovery_payload(
    &buffer[0], buffer.size(), "example_uri", "oic.r.example,oic.r.test",
    static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_R | OC_IF_RW |
                                     OC_IF_CREATE)));

  // Define the expected payload based on the inputs
  std::string expected_payload =
    R"({"uri":"example_uri","types":[oic.r.example,oic.r.test],)"
    R"("if":["oic.if.baseline","oic.if.rw","oic.if.r","oic.if.create"]})";

  // Compare the expected payload with the actual payload
  comparePayloads(expected_payload, buffer.data());
}

TEST_F(ResourceDiscoveryPayloadTest, EncodePayload_NotEnoughSpace)
{
  std::array<char, 10> buffer{};

  // Call the function with a buffer that doesn't have enough space
  ASSERT_FALSE(encode_resource_discovery_payload(
    &buffer[0], buffer.size(), "example_uri", "oic.r.example,oic.r.test",
    static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_RW)));
}
