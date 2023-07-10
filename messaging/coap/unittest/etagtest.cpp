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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include <messaging/coap/coap.h>
#include "tests/gtest/Device.h"

#include <cstring>
#include <gtest/gtest.h>
#include <string>

class TestETag : public testing::Test {};

TEST_F(TestETag, GetETag)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
  const uint8_t *etag;
  EXPECT_EQ(0, coap_get_header_etag(&packet, &etag));
}

TEST_F(TestETag, SetETag)
{
  coap_packet_t packet{};

  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
  std::vector<uint8_t> etag{ 0x01, 0x02, 0x03, 0x04 };
  EXPECT_EQ(etag.size(),
            coap_set_header_etag(&packet, etag.data(), etag.size()));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
  const uint8_t *etag_out;
  size_t etag_out_len = coap_get_header_etag(&packet, &etag_out);
  EXPECT_EQ(etag.size(), etag_out_len);
  EXPECT_TRUE(memcmp(etag.data(), etag_out, etag.size()) == 0);

  // truncate too long value to COAP_ETAG_LEN
  std::vector<uint8_t> etag2(COAP_ETAG_LEN + 1, 0x42);
  size_t etag2_len = coap_set_header_etag(&packet, etag2.data(), etag2.size());
  EXPECT_GT(etag2.size(), etag2_len);
  etag_out_len = coap_get_header_etag(&packet, &etag_out);
  EXPECT_EQ(COAP_ETAG_LEN, etag_out_len);
  EXPECT_TRUE(memcmp(etag2.data(), etag_out, COAP_ETAG_LEN) == 0);

  // unset ETag
  EXPECT_EQ(0, coap_set_header_etag(&packet, nullptr, 0));
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
}

static constexpr size_t kDeviceID{ 0 };

class TestETagWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

TEST_F(TestETagWithServer, GetETag)
{
  // TODO: send GET request to /oic/d with ETag option
}
