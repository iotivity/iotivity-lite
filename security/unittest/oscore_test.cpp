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
#include "messaging/coap/oscore.h"
#include "messaging/coap/coap.h"
#include "security/oc_oscore_crypto.h"
#include "security/oc_oscore.h"
#include "security/oc_oscore_context.h"

class TestOSCORE : public testing::Test {
protected:
  virtual void SetUp() { oc_ri_init(); }

  virtual void TearDown() { oc_ri_shutdown(); }
};

/* Test cases from RFC 8613 */

/* C.1.  Test Vector 1: Key Derivation with Master Salt */
/* C.1.1.  Client */
TEST_F(TestOSCORE, ClientKDFWithSalt_P)
{
  /*
   Inputs:
   Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
   Master Salt: 0x9e7ca92223786340 (8 bytes)
   Sender ID: 0x (0 byte)
   Recipient ID: 0x01 (1 byte)

   Outputs:
   Sender Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
   Recipient Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
   Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes)
   sender nonce: 0x4622d4dd6d944168eefb54987c (13 bytes)
   recipient nonce: 0x4722d4dd6d944169eefb54987c (13 bytes)
  */

  uint8_t rid[1] = { 0x01 };
  uint8_t secret[512], salt[512];
  size_t secret_len = 512, salt_len = 512;

  uint8_t key[OSCORE_KEY_LEN], iv[OSCORE_COMMON_IV_LEN];

  const char *secret_str = "0102030405060708090a0b0c0d0e0f10";
  const char *salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str, strlen(secret_str),
                                             secret, &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(salt_str, strlen(salt_str), salt,
                                             &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, NULL, 0, "Key", secret,
                                           secret_len, salt, salt_len, key,
                                           OSCORE_KEY_LEN),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "f0910ed7295e6ad4b54fc793154302ff");

  EXPECT_EQ(oc_oscore_context_derive_param(rid, 1, NULL, 0, "Key", secret,
                                           secret_len, salt, salt_len, key,
                                           OSCORE_KEY_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "ffb14e093c94c9cac9471648b4f98710");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, NULL, 0, "IV", secret,
                                           secret_len, salt, salt_len, iv,
                                           OSCORE_COMMON_IV_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv, OSCORE_COMMON_IV_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4622d4dd6d944168eefb54987c");

  uint8_t piv[1] = { 0 };
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];

  oc_oscore_AEAD_nonce(NULL, 0, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4622d4dd6d944168eefb54987c");

  oc_oscore_AEAD_nonce(rid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4722d4dd6d944169eefb54987c");
}

/* C.1.2.  Server */
TEST_F(TestOSCORE, ServerKDFWithSalt_P)
{
  /*
    Inputs:
    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Master Salt: 0x9e7ca92223786340 (8 bytes)
    Sender ID: 0x01 (1 byte)
    Recipient ID: 0x (0 byte)

    Outputs:
    Sender Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
    Recipient Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
    Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes)
    sender nonce: 0x4622d4dd6d944168eefb54987c (13 bytes)
    recipient nonce: 0x4722d4dd6d944169eefb54987c (13 bytes)
  */

  uint8_t sid[1] = { 0x01 };
  uint8_t secret[512], salt[512];
  size_t secret_len = 512, salt_len = 512;

  uint8_t key[OSCORE_KEY_LEN], iv[OSCORE_COMMON_IV_LEN];

  const char *secret_str = "0102030405060708090a0b0c0d0e0f10";
  const char *salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str, strlen(secret_str),
                                             secret, &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(salt_str, strlen(salt_str), salt,
                                             &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(oc_oscore_context_derive_param(sid, 1, NULL, 0, "Key", secret,
                                           secret_len, salt, salt_len, key,
                                           OSCORE_KEY_LEN),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "ffb14e093c94c9cac9471648b4f98710");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, NULL, 0, "Key", secret,
                                           secret_len, salt, salt_len, key,
                                           OSCORE_KEY_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "f0910ed7295e6ad4b54fc793154302ff");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, NULL, 0, "IV", secret,
                                           secret_len, salt, salt_len, iv,
                                           OSCORE_COMMON_IV_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv, OSCORE_COMMON_IV_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4622d4dd6d944168eefb54987c");

  uint8_t piv[1] = { 0 };
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];

  oc_oscore_AEAD_nonce(sid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4722d4dd6d944169eefb54987c");

  oc_oscore_AEAD_nonce(NULL, 0, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4622d4dd6d944168eefb54987c");
}

/* C.2.  Test Vector 2: Key Derivation without Master Salt */
/* C.2.1.  Client */
TEST_F(TestOSCORE, ClientKDFWithoutSalt_P)
{
  /*
    Inputs:
    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Sender ID: 0x00 (1 byte)
    Recipient ID: 0x01 (1 byte)

    Outputs:
    Sender Key: 0x321b26943253c7ffb6003b0b64d74041 (16 bytes)
    Recipient Key: 0xe57b5635815177cd679ab4bcec9d7dda (16 bytes)
    Common IV: 0xbe35ae297d2dace910c52e99f9 (13 bytes)
    sender nonce: 0xbf35ae297d2dace910c52e99f9 (13 bytes)
    recipient nonce: 0xbf35ae297d2dace810c52e99f9 (13 bytes)
  */

  uint8_t sid[1] = { 0 }, rid[1] = { 0x01 };
  uint8_t secret[512];
  size_t secret_len = 512;

  uint8_t key[OSCORE_KEY_LEN], iv[OSCORE_COMMON_IV_LEN];

  const char *secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str, strlen(secret_str),
                                             secret, &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(oc_oscore_context_derive_param(sid, 1, NULL, 0, "Key", secret,
                                           secret_len, NULL, 0, key,
                                           OSCORE_KEY_LEN),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "321b26943253c7ffb6003b0b64d74041");

  EXPECT_EQ(oc_oscore_context_derive_param(rid, 1, NULL, 0, "Key", secret,
                                           secret_len, NULL, 0, key,
                                           OSCORE_KEY_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "e57b5635815177cd679ab4bcec9d7dda");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, NULL, 0, "IV", secret,
                                           secret_len, NULL, 0, iv,
                                           OSCORE_COMMON_IV_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv, OSCORE_COMMON_IV_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "be35ae297d2dace910c52e99f9");

  uint8_t piv[1] = { 0 };
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];

  oc_oscore_AEAD_nonce(sid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "bf35ae297d2dace910c52e99f9");

  oc_oscore_AEAD_nonce(rid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "bf35ae297d2dace810c52e99f9");
}

/* C.2.2.  Server */
TEST_F(TestOSCORE, ServerKDFWithoutSalt_P)
{
  /*
    Inputs:
    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Sender ID: 0x01 (1 byte)
    Recipient ID: 0x00 (1 byte)

    Outputs:
    Sender Key: 0xe57b5635815177cd679ab4bcec9d7dda (16 bytes)
    Recipient Key: 0x321b26943253c7ffb6003b0b64d74041  (16 bytes)
    Common IV: 0xbe35ae297d2dace910c52e99f9 (13 bytes)
    sender nonce: 0xbf35ae297d2dace810c52e99f9 (13 bytes)
    recipient nonce: 0xbf35ae297d2dace910c52e99f9 (13 bytes)
  */

  uint8_t sid[1] = { 0x01 }, rid[1] = { 0 };
  uint8_t secret[512];
  size_t secret_len = 512;

  uint8_t key[OSCORE_KEY_LEN], iv[OSCORE_COMMON_IV_LEN];

  const char *secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str, strlen(secret_str),
                                             secret, &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(oc_oscore_context_derive_param(sid, 1, NULL, 0, "Key", secret,
                                           secret_len, NULL, 0, key,
                                           OSCORE_KEY_LEN),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "e57b5635815177cd679ab4bcec9d7dda");

  EXPECT_EQ(oc_oscore_context_derive_param(rid, 1, NULL, 0, "Key", secret,
                                           secret_len, NULL, 0, key,
                                           OSCORE_KEY_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "321b26943253c7ffb6003b0b64d74041");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, NULL, 0, "IV", secret,
                                           secret_len, NULL, 0, iv,
                                           OSCORE_COMMON_IV_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv, OSCORE_COMMON_IV_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "be35ae297d2dace910c52e99f9");

  uint8_t piv[1] = { 0 };
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];

  oc_oscore_AEAD_nonce(sid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "bf35ae297d2dace810c52e99f9");

  oc_oscore_AEAD_nonce(rid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "bf35ae297d2dace910c52e99f9");
}

/* C.3.  Test Vector 3: Key Derivation with ID Context */
/* C.3.1.  Client */
TEST_F(TestOSCORE, ClientKDFWithIDContext_P)
{
  /*
    Inputs:
    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Master Salt: 0x9e7ca92223786340 (8 bytes)
    Sender ID: 0x (0 byte)
    Recipient ID: 0x01 (1 byte)
    ID Context: 0x37cbf3210017a2d3 (8 bytes)

    Outputs:
    Sender Key: 0xaf2a1300a5e95788b356336eeecd2b92 (16 bytes)
    Recipient Key: 0xe39a0c7c77b43f03b4b39ab9a268699f (16 bytes)
    Common IV: 0x2ca58fb85ff1b81c0b7181b85e (13 bytes)
    sender nonce: 0x2ca58fb85ff1b81c0b7181b85e (13 bytes)
    recipient nonce: 0x2da58fb85ff1b81d0b7181b85e (13 bytes)
  */

  uint8_t rid[1] = { 0x01 };
  uint8_t secret[512], salt[512], idctx[512];
  size_t secret_len = 512, salt_len = 512, idctx_len = 512;

  uint8_t key[OSCORE_KEY_LEN], iv[OSCORE_COMMON_IV_LEN];

  const char *secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str, strlen(secret_str),
                                             secret, &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  const char *salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(salt_str, strlen(salt_str), salt,
                                             &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  const char *idctx_str = "37cbf3210017a2d3";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(idctx_str, strlen(idctx_str),
                                             idctx, &idctx_len),
            0);
  EXPECT_EQ(idctx_len, 8);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, idctx, idctx_len, "Key",
                                           secret, secret_len, salt, salt_len,
                                           key, OSCORE_KEY_LEN),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "af2a1300a5e95788b356336eeecd2b92");

  EXPECT_EQ(oc_oscore_context_derive_param(rid, 1, idctx, idctx_len, "Key",
                                           secret, secret_len, salt, salt_len,
                                           key, OSCORE_KEY_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "e39a0c7c77b43f03b4b39ab9a268699f");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, idctx, idctx_len, "IV",
                                           secret, secret_len, salt, salt_len,
                                           iv, OSCORE_COMMON_IV_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv, OSCORE_COMMON_IV_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "2ca58fb85ff1b81c0b7181b85e");

  uint8_t piv[1] = { 0 };
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];

  oc_oscore_AEAD_nonce(NULL, 0, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "2ca58fb85ff1b81c0b7181b85e");

  oc_oscore_AEAD_nonce(rid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "2da58fb85ff1b81d0b7181b85e");
}

/* C.3.2.  Server */
TEST_F(TestOSCORE, ServerKDFWithIDContext_P)
{
  /*
    Inputs:
    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Master Salt: 0x9e7ca92223786340 (8 bytes)
    Sender ID: 0x01 (1 byte)
    Recipient ID: 0x (0 bytes)
    ID Context: 0x37cbf3210017a2d3 (8 bytes)

    Outputs:
    Sender Key: 0xe39a0c7c77b43f03b4b39ab9a268699f (16 bytes)
    Recipient Key: 0xaf2a1300a5e95788b356336eeecd2b92 (16 bytes)
    Common IV: 0x2ca58fb85ff1b81c0b7181b85e (13 bytes)
    sender nonce: 0x2da58fb85ff1b81d0b7181b85e (13 bytes)
    recipient nonce: 0x2ca58fb85ff1b81c0b7181b85e (13 bytes)
  */

  uint8_t sid[1] = { 0x01 };
  uint8_t secret[512], salt[512], idctx[512];
  size_t secret_len = 512, salt_len = 512, idctx_len = 512;

  uint8_t key[OSCORE_KEY_LEN], iv[OSCORE_COMMON_IV_LEN];

  const char *secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str, strlen(secret_str),
                                             secret, &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  const char *salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(salt_str, strlen(salt_str), salt,
                                             &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  const char *idctx_str = "37cbf3210017a2d3";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(idctx_str, strlen(idctx_str),
                                             idctx, &idctx_len),
            0);
  EXPECT_EQ(idctx_len, 8);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(oc_oscore_context_derive_param(sid, 1, idctx, idctx_len, "Key",
                                           secret, secret_len, salt, salt_len,
                                           key, OSCORE_KEY_LEN),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "e39a0c7c77b43f03b4b39ab9a268699f");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, idctx, idctx_len, "Key",
                                           secret, secret_len, salt, salt_len,
                                           key, OSCORE_KEY_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key, OSCORE_KEY_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "af2a1300a5e95788b356336eeecd2b92");

  EXPECT_EQ(oc_oscore_context_derive_param(NULL, 0, idctx, idctx_len, "IV",
                                           secret, secret_len, salt, salt_len,
                                           iv, OSCORE_COMMON_IV_LEN),
            0);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv, OSCORE_COMMON_IV_LEN, testvec,
                                             &testvec_len),
            0);
  EXPECT_STREQ(testvec, "2ca58fb85ff1b81c0b7181b85e");

  uint8_t piv[1] = { 0 };
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];

  oc_oscore_AEAD_nonce(sid, 1, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "2da58fb85ff1b81d0b7181b85e");

  oc_oscore_AEAD_nonce(NULL, 0, piv, 1, iv, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "2ca58fb85ff1b81c0b7181b85e");
}

/* C.4.  Test Vector 4: OSCORE Request, Client */
TEST_F(TestOSCORE, ClientRequest1_P)
{
  /*
    Unprotected CoAP request:
     0x44015d1f00003974396c6f63616c686f737483747631 (22 bytes)
  */

  const char *request_str = "44015d1f00003974396c6f63616c686f737483747631";
  uint8_t buffer[512];
  size_t buffer_len = 512;

  EXPECT_EQ(oc_conv_hex_string_to_byte_array(request_str, strlen(request_str),
                                             buffer, &buffer_len),
            0);

  coap_packet_t coap_pkt[1];
  coap_status_t code = coap_udp_parse_message(coap_pkt, buffer, buffer_len);

  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes) */

  const char *civ_str = "4622d4dd6d944168eefb54987c";
  uint8_t civ[512];
  size_t civ_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(civ_str, strlen(civ_str), civ, &civ_len),
    0);

  /*
    Sender ID: 0x (0 byte)
    Sender Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
    Sender Sequence Number: 20
  */
  const char *key_str = "f0910ed7295e6ad4b54fc793154302ff";
  uint8_t skey[512];
  size_t skey_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(key_str, strlen(key_str), skey, &skey_len),
    0);

  uint64_t ssn = 20;
  uint8_t piv[OSCORE_PIV_LEN], piv_len = OSCORE_PIV_LEN;
  oscore_store_piv(ssn, piv, &piv_len);

  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */

  uint8_t AAD[OSCORE_AAD_MAX_LEN], AAD_len = OSCORE_AAD_MAX_LEN;

  EXPECT_EQ(oc_oscore_compose_AAD(NULL, 0, piv, piv_len, AAD, &AAD_len), 0);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(AAD, AAD_len, testvec, &testvec_len), 0);
  EXPECT_STREQ(testvec, "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x01b3747631 (5 bytes) */
  size_t plaintext_len = oscore_serialize_plaintext(coap_pkt, buffer + 256);

  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer + 256, plaintext_len,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "01b3747631");

  /* Verify nonce: 0x4622d4dd6d944168eefb549868 (13 bytes) */
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
  oc_oscore_AEAD_nonce(NULL, 0, piv, piv_len, civ, nonce,
                       OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4622d4dd6d944168eefb549868");

  /* Verify ciphertext: 0x612f1092f1776f1c1668b3825e (13 bytes) */
  EXPECT_EQ(oc_oscore_encrypt(buffer + 256, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey, skey_len, nonce, OSCORE_AEAD_NONCE_LEN, AAD,
                              AAD_len, buffer + 256),
            0);
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(
      buffer + 256, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec, &testvec_len),
    0);
  EXPECT_STREQ(testvec, "612f1092f1776f1c1668b3825e");

  coap_pkt->payload = buffer + 256;
  coap_pkt->payload_len = plaintext_len + OSCORE_AEAD_TAG_LEN;

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt->code = oscore_get_outer_code(coap_pkt);

  /* Set the OSCORE option */
  coap_set_header_oscore(coap_pkt, piv, piv_len, NULL, 0, NULL, 0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len = oscore_serialize_message(coap_pkt, buffer);

  /* Verify protected CoAP request (OSCORE message): 0x44025d1f00003974396c6f6
      3616c686f7374620914ff612f1092f1776f1c1668b3825e (35 bytes)
  */
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(buffer, buffer_len, testvec, &testvec_len),
    0);
  EXPECT_STREQ(
    testvec,
    "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e");
}

/* C.5.  Test Vector 5: OSCORE Request, Client */
TEST_F(TestOSCORE, ClientRequest2_P)
{
  /*
    Unprotected CoAP request:
     0x440171c30000b932396c6f63616c686f737483747631 (22 bytes)
  */

  const char *request_str = "440171c30000b932396c6f63616c686f737483747631";
  uint8_t buffer[512];
  size_t buffer_len = 512;

  EXPECT_EQ(oc_conv_hex_string_to_byte_array(request_str, strlen(request_str),
                                             buffer, &buffer_len),
            0);

  coap_packet_t coap_pkt[1];
  coap_status_t code = coap_udp_parse_message(coap_pkt, buffer, buffer_len);

  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0xbe35ae297d2dace910c52e99f9 (13 bytes) */

  const char *civ_str = "be35ae297d2dace910c52e99f9";
  uint8_t civ[512];
  size_t civ_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(civ_str, strlen(civ_str), civ, &civ_len),
    0);

  /*
    Sender ID: 0x00 (1 byte)
    Sender Key: 0x321b26943253c7ffb6003b0b64d74041 (16 bytes)
    Sender Sequence Number: 20
  */
  uint8_t sid[1] = { 0 };
  const char *key_str = "321b26943253c7ffb6003b0b64d74041";
  uint8_t skey[512];
  size_t skey_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(key_str, strlen(key_str), skey, &skey_len),
    0);

  uint64_t ssn = 20;
  uint8_t piv[OSCORE_PIV_LEN], piv_len = OSCORE_PIV_LEN;
  oscore_store_piv(ssn, piv, &piv_len);

  /* Verify AAD: 0x8368456e63727970743040498501810a4100411440 (20 bytes) */

  uint8_t AAD[OSCORE_AAD_MAX_LEN], AAD_len = OSCORE_AAD_MAX_LEN;

  EXPECT_EQ(oc_oscore_compose_AAD(sid, 1, piv, piv_len, AAD, &AAD_len), 0);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(AAD, AAD_len, testvec, &testvec_len), 0);
  EXPECT_STREQ(testvec, "8368456e63727970743040498501810a4100411440");

  /* Verify plaintext: 0x01b3747631 (5 bytes) */
  size_t plaintext_len = oscore_serialize_plaintext(coap_pkt, buffer + 256);

  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer + 256, plaintext_len,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "01b3747631");

  /* Verify nonce: 0xbf35ae297d2dace910c52e99ed (13 bytes) */
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
  oc_oscore_AEAD_nonce(sid, 1, piv, piv_len, civ, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "bf35ae297d2dace910c52e99ed");

  /* Verify ciphertext: 0x4ed339a5a379b0b8bc731fffb0 (13 bytes) */
  EXPECT_EQ(oc_oscore_encrypt(buffer + 256, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey, skey_len, nonce, OSCORE_AEAD_NONCE_LEN, AAD,
                              AAD_len, buffer + 256),
            0);
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(
      buffer + 256, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec, &testvec_len),
    0);
  EXPECT_STREQ(testvec, "4ed339a5a379b0b8bc731fffb0");

  coap_pkt->payload = buffer + 256;
  coap_pkt->payload_len = plaintext_len + OSCORE_AEAD_TAG_LEN;

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt->code = oscore_get_outer_code(coap_pkt);

  /* Set the OSCORE option */
  coap_set_header_oscore(coap_pkt, piv, piv_len, sid, 1, NULL, 0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len = oscore_serialize_message(coap_pkt, buffer);

  /* Protected CoAP request (OSCORE message): 0x440271c30000b932396c6f6
      3616c686f737463091400ff4ed339a5a379b0b8bc731fffb0 (36 bytes)
  */
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(buffer, buffer_len, testvec, &testvec_len),
    0);
  EXPECT_STREQ(
    testvec,
    "440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0");
}

/* C.6.  Test Vector 6: OSCORE Request, Client */
TEST_F(TestOSCORE, ClientRequest3_P)
{
  /*
    Unprotected CoAP request:
     0x44012f8eef9bbf7a396c6f63616c686f737483747631 (22 bytes)
  */

  const char *request_str = "44012f8eef9bbf7a396c6f63616c686f737483747631";
  uint8_t buffer[512];
  size_t buffer_len = 512;

  EXPECT_EQ(oc_conv_hex_string_to_byte_array(request_str, strlen(request_str),
                                             buffer, &buffer_len),
            0);

  coap_packet_t coap_pkt[1];
  coap_status_t code = coap_udp_parse_message(coap_pkt, buffer, buffer_len);

  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x2ca58fb85ff1b81c0b7181b85e (13 bytes) */

  const char *civ_str = "2ca58fb85ff1b81c0b7181b85e";
  uint8_t civ[512];
  size_t civ_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(civ_str, strlen(civ_str), civ, &civ_len),
    0);

  /*
    ID Context: 0x37cbf3210017a2d3 (8 bytes)
    Sender ID: 0x (0 bytes)
    Sender Key: 0xaf2a1300a5e95788b356336eeecd2b92 (16 bytes)
    Sender Sequence Number: 20
  */
  const char *idctx_str = "37cbf3210017a2d3";
  uint8_t idctx[512];
  size_t idctx_len = 512;
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(idctx_str, strlen(idctx_str),
                                             idctx, &idctx_len),
            0);

  const char *key_str = "af2a1300a5e95788b356336eeecd2b92";
  uint8_t skey[512];
  size_t skey_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(key_str, strlen(key_str), skey, &skey_len),
    0);

  uint64_t ssn = 20;
  uint8_t piv[OSCORE_PIV_LEN], piv_len = OSCORE_PIV_LEN;
  oscore_store_piv(ssn, piv, &piv_len);

  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */

  uint8_t AAD[OSCORE_AAD_MAX_LEN], AAD_len = OSCORE_AAD_MAX_LEN;

  EXPECT_EQ(oc_oscore_compose_AAD(NULL, 0, piv, piv_len, AAD, &AAD_len), 0);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(AAD, AAD_len, testvec, &testvec_len), 0);
  EXPECT_STREQ(testvec, "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x01b3747631 (5 bytes) */
  size_t plaintext_len = oscore_serialize_plaintext(coap_pkt, buffer + 256);

  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer + 256, plaintext_len,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "01b3747631");

  /* Verify nonce: 0x2ca58fb85ff1b81c0b7181b84a (13 bytes) */
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
  oc_oscore_AEAD_nonce(NULL, 0, piv, piv_len, civ, nonce,
                       OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "2ca58fb85ff1b81c0b7181b84a");

  /* Verify ciphertext: 0x72cd7273fd331ac45cffbe55c3 (13 bytes) */
  EXPECT_EQ(oc_oscore_encrypt(buffer + 256, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey, skey_len, nonce, OSCORE_AEAD_NONCE_LEN, AAD,
                              AAD_len, buffer + 256),
            0);
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(
      buffer + 256, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec, &testvec_len),
    0);
  EXPECT_STREQ(testvec, "72cd7273fd331ac45cffbe55c3");

  coap_pkt->payload = buffer + 256;
  coap_pkt->payload_len = plaintext_len + OSCORE_AEAD_TAG_LEN;

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt->code = oscore_get_outer_code(coap_pkt);

  /* Set the OSCORE option */
  coap_set_header_oscore(coap_pkt, piv, piv_len, NULL, 0, idctx, idctx_len);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len = oscore_serialize_message(coap_pkt, buffer);

  /* Protected CoAP request (OSCORE message):
      0x44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff
      72cd7273fd331ac45cffbe55c3 (44 bytes)
  */
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(buffer, buffer_len, testvec, &testvec_len),
    0);
  EXPECT_STREQ(testvec, "44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf32100"
                        "17a2d3ff72cd7273fd331ac45cffbe55c3");
}

/* C.7.  Test Vector 7: OSCORE Response, Server */
TEST_F(TestOSCORE, ServerResponse1_P)
{
  /*
    Unprotected CoAP response:
     0x64455d1f00003974ff48656c6c6f20576f726c6421 (21 bytes)
  */

  const char *response_str = "64455d1f00003974ff48656c6c6f20576f726c6421";
  uint8_t buffer[512];
  size_t buffer_len = 512;

  EXPECT_EQ(oc_conv_hex_string_to_byte_array(response_str, strlen(response_str),
                                             buffer, &buffer_len),
            0);

  coap_packet_t coap_pkt[1];
  coap_status_t code = coap_udp_parse_message(coap_pkt, buffer, buffer_len);

  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes) */

  const char *civ_str = "4622d4dd6d944168eefb54987c";
  uint8_t civ[512];
  size_t civ_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(civ_str, strlen(civ_str), civ, &civ_len),
    0);

  /*
    Sender ID: 0x01 (1 byte)
    Sender Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
    Sender Sequence Number: 0
  */
  const char *key_str = "ffb14e093c94c9cac9471648b4f98710";
  uint8_t skey[512];
  size_t skey_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(key_str, strlen(key_str), skey, &skey_len),
    0);

  /* Using request_piv & request_kid from test vector C.4 */
  uint8_t request_piv[1] = { 0x14 };

  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */
  uint8_t AAD[OSCORE_AAD_MAX_LEN], AAD_len = OSCORE_AAD_MAX_LEN;

  EXPECT_EQ(oc_oscore_compose_AAD(NULL, 0, request_piv, 1, AAD, &AAD_len), 0);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(AAD, AAD_len, testvec, &testvec_len), 0);
  EXPECT_STREQ(testvec, "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x45ff48656c6c6f20576f726c6421 (14 bytes) */
  size_t plaintext_len = oscore_serialize_plaintext(coap_pkt, buffer + 256);

  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer + 256, plaintext_len,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "45ff48656c6c6f20576f726c6421");

  /* Verify nonce: 0x4622d4dd6d944168eefb549868 (13 bytes) */
  /* Using nonce from request in test vector C.4 */
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
  oc_oscore_AEAD_nonce(NULL, 0, request_piv, 1, civ, nonce,
                       OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4622d4dd6d944168eefb549868");

  /* Verify ciphertext: 0xdbaad1e9a7e7b2a813d3c31524378303cdafae119106 (22
      bytes) */
  EXPECT_EQ(oc_oscore_encrypt(buffer + 256, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey, skey_len, nonce, OSCORE_AEAD_NONCE_LEN, AAD,
                              AAD_len, buffer + 256),
            0);
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(
      buffer + 256, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec, &testvec_len),
    0);
  EXPECT_STREQ(testvec, "dbaad1e9a7e7b2a813d3c31524378303cdafae119106");

  coap_pkt->payload = buffer + 256;
  coap_pkt->payload_len = plaintext_len + OSCORE_AEAD_TAG_LEN;

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt->code = oscore_get_outer_code(coap_pkt);

  /* Set the OSCORE option */
  coap_set_header_oscore(coap_pkt, NULL, 0, NULL, 0, NULL, 0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len = oscore_serialize_message(coap_pkt, buffer);

  /*
    Protected CoAP response (OSCORE message):
      0x64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106
      (32 bytes)
  */
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(buffer, buffer_len, testvec, &testvec_len),
    0);
  EXPECT_STREQ(
    testvec,
    "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106");
}

/* C.8.  Test Vector 8: OSCORE Response with Partial IV, Server */
TEST_F(TestOSCORE, ServerResponse2_P)
{
  /*
    Unprotected CoAP response:
     0x64455d1f00003974ff48656c6c6f20576f726c6421 (21 bytes)
  */

  const char *response_str = "64455d1f00003974ff48656c6c6f20576f726c6421";
  uint8_t buffer[512];
  size_t buffer_len = 512;

  EXPECT_EQ(oc_conv_hex_string_to_byte_array(response_str, strlen(response_str),
                                             buffer, &buffer_len),
            0);

  coap_packet_t coap_pkt[1];
  coap_status_t code = coap_udp_parse_message(coap_pkt, buffer, buffer_len);

  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes) */

  const char *civ_str = "4622d4dd6d944168eefb54987c";
  uint8_t civ[512];
  size_t civ_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(civ_str, strlen(civ_str), civ, &civ_len),
    0);

  /*
    Sender Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
  */
  const char *key_str = "ffb14e093c94c9cac9471648b4f98710";
  uint8_t skey[512];
  size_t skey_len = 512;
  EXPECT_EQ(
    oc_conv_hex_string_to_byte_array(key_str, strlen(key_str), skey, &skey_len),
    0);

  /* Using request_piv & request_kid from test vetor in C.4 */
  uint8_t request_piv[1] = { 0x14 };
  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */
  uint8_t AAD[OSCORE_AAD_MAX_LEN], AAD_len = OSCORE_AAD_MAX_LEN;
  EXPECT_EQ(oc_oscore_compose_AAD(NULL, 0, request_piv, 1, AAD, &AAD_len), 0);

  char testvec[512];
  size_t testvec_len = 512;

  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(AAD, AAD_len, testvec, &testvec_len), 0);
  EXPECT_STREQ(testvec, "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x45ff48656c6c6f20576f726c6421 (14 bytes) */
  size_t plaintext_len = oscore_serialize_plaintext(coap_pkt, buffer + 256);

  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer + 256, plaintext_len,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "45ff48656c6c6f20576f726c6421");

  /*
    Sender ID: 0x01 (1 byte)
    Sender Sequence Number: 0
  */
  uint8_t sid[1] = { 0x01 };
  uint8_t piv[1] = { 0 };
  /* Verify nonce: 0x4722d4dd6d944169eefb54987c (13 bytes) */
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
  oc_oscore_AEAD_nonce(sid, 1, piv, 1, civ, nonce, OSCORE_AEAD_NONCE_LEN);
  testvec_len = 512;
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce, OSCORE_AEAD_NONCE_LEN,
                                             testvec, &testvec_len),
            0);
  EXPECT_STREQ(testvec, "4722d4dd6d944169eefb54987c");

  /* Verify ciphertext: 0x4d4c13669384b67354b2b6175ff4b8658c666a6cf88e (22
      bytes) */
  EXPECT_EQ(oc_oscore_encrypt(buffer + 256, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey, skey_len, nonce, OSCORE_AEAD_NONCE_LEN, AAD,
                              AAD_len, buffer + 256),
            0);
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(
      buffer + 256, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec, &testvec_len),
    0);
  EXPECT_STREQ(testvec, "4d4c13669384b67354b2b6175ff4b8658c666a6cf88e");

  coap_pkt->payload = buffer + 256;
  coap_pkt->payload_len = plaintext_len + OSCORE_AEAD_TAG_LEN;

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt->code = oscore_get_outer_code(coap_pkt);

  /* Set the OSCORE option */
  coap_set_header_oscore(coap_pkt, piv, 1, NULL, 0, NULL, 0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len = oscore_serialize_message(coap_pkt, buffer);

  /*
    Protected CoAP response (OSCORE message): 0x64445d1f00003974920100
      ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e (34 bytes)
  */
  testvec_len = 512;
  EXPECT_EQ(
    oc_conv_byte_array_to_hex_string(buffer, buffer_len, testvec, &testvec_len),
    0);
  EXPECT_STREQ(
    testvec,
    "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e");
}
#else  /* OC_SECURITY && OC_OSCORE */
typedef int dummy_declaration;
#endif /* !OC_SECURITY && !OC_OSCORE */
