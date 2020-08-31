/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#if defined(OC_SECURITY) && defined(OC_OSCORE)

#include <cstdlib>
#include "gtest/gtest.h"
#include "oc_helpers.h"
#include "security/oc_oscore_crypto.h"

class TestOSCOREHKDF : public testing::Test {
protected:
  virtual void SetUp() {}

  virtual void TearDown() {}
};

/* Test cases from RFC 5869 */

TEST_F(TestOSCOREHKDF, HKFDTC1_P)
{
  /*
    IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
    salt = 0x000102030405060708090a0b0c (13 octets)
    info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
    L    = 42
   */
  const char *ikm_str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
  const char *salt_str = "000102030405060708090a0b0c";
  const char *info_str = "f0f1f2f3f4f5f6f7f8f9";

  uint8_t salt[512], ikm[512], info[512], okm[512];
  size_t salt_len = 512, info_len = 512, ikm_len = 512;
  size_t L = 42;

  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(ikm_str, strlen(ikm_str), ikm, &ikm_len),
    0);
  EXPECT_EQ(ikm_len, 22);
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(salt_str, strlen(salt_str), salt,
                                             &salt_len),
            0);
  EXPECT_EQ(salt_len, 13);
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(info_str, strlen(info_str), info,
                                             &info_len),
            0);
  EXPECT_EQ(info_len, 10);
  EXPECT_EQ(HKDF_SHA256(salt, salt_len, ikm, ikm_len, info, info_len, okm, L),
            0);

  char hkdf[512];
  size_t hkdf_len = 512;

  /*
    OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
          34007208d5b887185865 (42 octets)
  */
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(okm, L, hkdf, &hkdf_len), 0);
  EXPECT_EQ(hkdf_len, L * 2);
  EXPECT_STREQ(hkdf, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56e"
                     "cc4c5bf34007208d5b887185865");
}

TEST_F(TestOSCOREHKDF, HKFDTC2_P)
{
  /*
    IKM  = 0x000102030405060708090a0b0c0d0e0f
           101112131415161718191a1b1c1d1e1f
           202122232425262728292a2b2c2d2e2f
           303132333435363738393a3b3c3d3e3f
           404142434445464748494a4b4c4d4e4f (80 octets)
    salt = 0x606162636465666768696a6b6c6d6e6f
           707172737475767778797a7b7c7d7e7f
           808182838485868788898a8b8c8d8e8f
           909192939495969798999a9b9c9d9e9f
           a0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
    info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
           c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
           d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
           e0e1e2e3e4e5e6e7e8e9eaebecedeeef
           f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
    L    = 82
   */
  const char *ikm_str = "000102030405060708090a0b0c0d0e0f"
                        "101112131415161718191a1b1c1d1e1f"
                        "202122232425262728292a2b2c2d2e2f"
                        "303132333435363738393a3b3c3d3e3f"
                        "404142434445464748494a4b4c4d4e4f";
  const char *salt_str = "606162636465666768696a6b6c6d6e6f"
                         "707172737475767778797a7b7c7d7e7f"
                         "808182838485868788898a8b8c8d8e8f"
                         "909192939495969798999a9b9c9d9e9f"
                         "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
  const char *info_str = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                         "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                         "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                         "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

  uint8_t salt[512], ikm[512], info[512], okm[512];
  size_t salt_len = 512, info_len = 512, ikm_len = 512;
  size_t L = 82;

  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(ikm_str, strlen(ikm_str), ikm, &ikm_len),
    0);
  EXPECT_EQ(ikm_len, 80);
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(salt_str, strlen(salt_str), salt,
                                             &salt_len),
            0);
  EXPECT_EQ(salt_len, 80);
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(info_str, strlen(info_str), info,
                                             &info_len),
            0);
  EXPECT_EQ(info_len, 80);
  EXPECT_EQ(HKDF_SHA256(salt, salt_len, ikm, ikm_len, info, info_len, okm, L),
            0);

  char hkdf[512];
  size_t hkdf_len = 512;

  /*
    OKM  = 0xb11e398dc80327a1c8e7f78c596a4934
           4f012eda2d4efad8a050cc4c19afa97c
           59045a99cac7827271cb41c65e590e09
           da3275600c2f09b8367793a9aca3db71
           cc30c58179ec3e87c14c01d5c1f3434f
           1d87 (82 octets)
  */
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(okm, L, hkdf, &hkdf_len), 0);
  EXPECT_EQ(hkdf_len, L * 2);
  EXPECT_STREQ(hkdf, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c1"
                     "9afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b836"
                     "7793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
}

TEST_F(TestOSCOREHKDF, HKFDTC3_P)
{
  /*
    IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
    salt = (0 octets)
    info = (0 octets)
    L    = 42
   */
  const char *ikm_str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

  uint8_t ikm[512], okm[512];
  size_t ikm_len = 512, L = 42;

  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(ikm_str, strlen(ikm_str), ikm, &ikm_len),
    0);
  EXPECT_EQ(ikm_len, 22);
  EXPECT_EQ(HKDF_SHA256(NULL, 0, ikm, ikm_len, NULL, 0, okm, L), 0);

  char hkdf[512];
  size_t hkdf_len = 512;

  /*
    OKM  = 0x8da4e775a563c18f715f802a063c5a31
           b8a11f5c5ee1879ec3454e5f3c738d2d
           9d201395faa4b61a96c8 (42 octets)
  */
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(okm, L, hkdf, &hkdf_len), 0);
  EXPECT_EQ(hkdf_len, L * 2);
  EXPECT_STREQ(hkdf, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3"
                     "c738d2d9d201395faa4b61a96c8");
}

#else  /* OC_SECURITY && OC_OSCORE */
typedef int dummy_declaration;
#endif /* !OC_SECURITY && !OC_OSCORE */
