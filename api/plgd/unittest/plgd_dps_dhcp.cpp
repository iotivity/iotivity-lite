/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifdef OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING

#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_dhcp_internal.h"

#include "gtest/gtest.h"

#include <array>

TEST(DPSDhcpTest, DpsOptions)
{
  plgd_dps_context_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  plgd_dps_dhcp_init(&ctx.dhcp);

  EXPECT_EQ(
    200, plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_endpoint(&ctx));
  EXPECT_EQ(
    201,
    plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_certificate_fingerprint(
      &ctx));

  plgd_dps_dhcp_set_vendor_encapsulated_option_code_dps_endpoint(&ctx, 202);
  EXPECT_EQ(
    202, plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_endpoint(&ctx));

  plgd_dps_dhcp_set_vendor_encapsulated_option_code_dps_certificate_fingerprint(
    &ctx, 203);
  EXPECT_EQ(
    203,
    plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_certificate_fingerprint(
      &ctx));
}

TEST(DPSDhcpTest, ConvertISCDhcpOptionsToBytes)
{
  std::string data = "c8:2:a:b";
  ssize_t ret =
    plgd_dps_hex_string_to_bytes(data.c_str(), data.length(), nullptr, 0);
  ASSERT_EQ(4, ret);

  std::array<uint8_t, 4> buf;
  ret = plgd_dps_hex_string_to_bytes(data.c_str(), data.length(), &buf[0], ret);
  std::array<uint8_t, 4> expected_data = { (uint8_t)0xc8, (uint8_t)0x2,
                                           (uint8_t)0xA, (uint8_t)0xB };
  EXPECT_EQ(expected_data.size(), ret);
  EXPECT_EQ(0, memcmp(&expected_data[0], &buf[0], ret));
}

TEST(DPSDhcpTest, ParseISCDhcpOptions)
{
  std::string data = "c8:20:63:6f:61:70:73:2b:74:63:70:3a:2f:2f:74:72:79:2e:70:"
                     "6c:67:64:2e:63:6c:6f:75:64:3a:31:35:36:38:34:c9:20:b8:f5:"
                     "ba:d:9f:6d:4d:ef:3f:82:28:d2:5f:53:d9:42:8e:af:b:36:71:"
                     "ed:80:d7:6c:e7:db:af:44:ec:28:d3";
  ssize_t ret =
    plgd_dps_hex_string_to_bytes(data.c_str(), data.length(), nullptr, 0);
  ASSERT_EQ(68, ret);
  std::array<uint8_t, 68> buf;
  ret = plgd_dps_hex_string_to_bytes(data.c_str(), data.length(), &buf[0], ret);
  ASSERT_EQ(68, ret);
  plgd_dps_context_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  plgd_dps_dhcp_init(&ctx.dhcp);
  dhcp_parse_data_t parse_data;
  memset(&parse_data, 0, sizeof(parse_data));
  parse_data.dhcp = &ctx.dhcp;
  EXPECT_TRUE(
    dps_dhcp_parse_vendor_encapsulated_options(&parse_data, &buf[0], ret));
  EXPECT_EQ(0, memcmp("coaps+tcp://try.plgd.cloud:15684", parse_data.endpoint,
                      parse_data.endpoint_size));
  std::array<uint8_t, 32> fingerprint = {
    (uint8_t)0xB8, (uint8_t)0xF5, (uint8_t)0xBA, (uint8_t)0x0D, (uint8_t)0x9F,
    (uint8_t)0x6D, (uint8_t)0x4D, (uint8_t)0xEF, (uint8_t)0x3F, (uint8_t)0x82,
    (uint8_t)0x28, (uint8_t)0xD2, (uint8_t)0x5F, (uint8_t)0x53, (uint8_t)0xD9,
    (uint8_t)0x42, (uint8_t)0x8E, (uint8_t)0xAF, (uint8_t)0x0B, (uint8_t)0x36,
    (uint8_t)0x71, (uint8_t)0xED, (uint8_t)0x80, (uint8_t)0xD7, (uint8_t)0x6C,
    (uint8_t)0xE7, (uint8_t)0xDB, (uint8_t)0xAF, (uint8_t)0x44, (uint8_t)0xEC,
    (uint8_t)0x28, (uint8_t)0xD3
  };
  EXPECT_EQ(fingerprint.size(), parse_data.certificate_fingerprint_size);
  EXPECT_EQ(0, memcmp(&fingerprint[0], parse_data.certificate_fingerprint,
                      parse_data.certificate_fingerprint_size));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
