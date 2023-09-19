/****************************************************************************
 *
 * Copyright (c) 2020 Intel Corporation
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
 ******************************************************************/

#include "oc_config.h"

#if defined(OC_SECURITY) && defined(OC_OSCORE)

#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/oscore.h"
#include "oc_helpers.h"
#include "port/oc_network_event_handler_internal.h"
#include "security/oc_oscore.h"
#include "security/oc_oscore_context.h"
#include "security/oc_oscore_crypto.h"

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>

class TestOSCORE : public testing::Test {
protected:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
  }

  void TearDown() override
  {
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
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

  std::array<uint8_t, 512> secret{};
  size_t secret_len = secret.size();
  std::string secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str.c_str(),
                                             secret_str.length(), secret.data(),
                                             &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  std::array<uint8_t, 512> salt{};
  size_t salt_len = salt.size();
  std::string salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(
              salt_str.c_str(), salt_str.length(), salt.data(), &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  std::array<uint8_t, OSCORE_KEY_LEN> key{};
  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, nullptr, 0, "Key", secret.data(), secret_len,
              salt.data(), salt_len, key.data(), key.size()),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "f0910ed7295e6ad4b54fc793154302ff");

  std::array<uint8_t, 1> rid = { 0x01 };
  EXPECT_EQ(oc_oscore_context_derive_param(
              rid.data(), rid.size(), nullptr, 0, "Key", secret.data(),
              secret_len, salt.data(), salt_len, key.data(), key.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "ffb14e093c94c9cac9471648b4f98710");

  std::array<uint8_t, OSCORE_COMMON_IV_LEN> iv{};
  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, nullptr, 0, "IV", secret.data(), secret_len,
              salt.data(), salt_len, iv.data(), iv.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv.data(), iv.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4622d4dd6d944168eefb54987c");

  std::array<uint8_t, 1> piv{};
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(nullptr, 0, piv.data(), piv.size(), iv.data(),
                       nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4622d4dd6d944168eefb54987c");

  oc_oscore_AEAD_nonce(rid.data(), rid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4722d4dd6d944169eefb54987c");
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

  std::array<uint8_t, 512> secret{};
  size_t secret_len = secret.size();
  std::string secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str.c_str(),
                                             secret_str.length(), secret.data(),
                                             &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  std::array<uint8_t, 512> salt{};
  size_t salt_len = secret.size();
  std::string salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(
              salt_str.c_str(), salt_str.length(), salt.data(), &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  std::array<uint8_t, 1> sid = { 0x01 };
  std::array<uint8_t, OSCORE_KEY_LEN> key{};
  std::array<uint8_t, OSCORE_COMMON_IV_LEN> iv{};
  EXPECT_EQ(oc_oscore_context_derive_param(
              sid.data(), sid.size(), nullptr, 0, "Key", secret.data(),
              secret_len, salt.data(), salt_len, key.data(), key.size()),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "ffb14e093c94c9cac9471648b4f98710");

  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, nullptr, 0, "Key", secret.data(), secret_len,
              salt.data(), salt_len, key.data(), key.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "f0910ed7295e6ad4b54fc793154302ff");

  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, nullptr, 0, "IV", secret.data(), secret_len,
              salt.data(), salt_len, iv.data(), iv.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv.data(), iv.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4622d4dd6d944168eefb54987c");

  std::array<uint8_t, 1> piv{};
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(sid.data(), sid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4722d4dd6d944169eefb54987c");

  oc_oscore_AEAD_nonce(nullptr, 0, piv.data(), piv.size(), iv.data(),
                       nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4622d4dd6d944168eefb54987c");
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

  std::array<uint8_t, 512> secret{};
  size_t secret_len = secret.size();
  std::string secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str.c_str(),
                                             secret_str.length(), secret.data(),
                                             &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  std::array<uint8_t, 1> sid{};
  std::array<uint8_t, OSCORE_KEY_LEN> key{};
  EXPECT_EQ(oc_oscore_context_derive_param(sid.data(), sid.size(), nullptr, 0,
                                           "Key", secret.data(), secret_len,
                                           nullptr, 0, key.data(), key.size()),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "321b26943253c7ffb6003b0b64d74041");

  std::array<uint8_t, 1> rid = { 0x01 };
  EXPECT_EQ(oc_oscore_context_derive_param(rid.data(), rid.size(), nullptr, 0,
                                           "Key", secret.data(), secret_len,
                                           nullptr, 0, key.data(), key.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "e57b5635815177cd679ab4bcec9d7dda");

  std::array<uint8_t, OSCORE_COMMON_IV_LEN> iv{};
  EXPECT_EQ(oc_oscore_context_derive_param(nullptr, 0, nullptr, 0, "IV",
                                           secret.data(), secret_len, nullptr,
                                           0, iv.data(), iv.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv.data(), iv.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "be35ae297d2dace910c52e99f9");

  std::array<uint8_t, 1> piv{};
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};

  oc_oscore_AEAD_nonce(sid.data(), sid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "bf35ae297d2dace910c52e99f9");

  oc_oscore_AEAD_nonce(rid.data(), rid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "bf35ae297d2dace810c52e99f9");
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

  std::array<uint8_t, 512> secret{};
  size_t secret_len = secret.size();
  std::string secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str.c_str(),
                                             secret_str.length(), secret.data(),
                                             &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  std::array<uint8_t, 1> sid = { 0x01 };
  std::array<uint8_t, OSCORE_KEY_LEN> key{};
  EXPECT_EQ(oc_oscore_context_derive_param(sid.data(), sid.size(), nullptr, 0,
                                           "Key", secret.data(), secret_len,
                                           nullptr, 0, key.data(), key.size()),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "e57b5635815177cd679ab4bcec9d7dda");

  std::array<uint8_t, 1> rid{};
  EXPECT_EQ(oc_oscore_context_derive_param(rid.data(), rid.size(), nullptr, 0,
                                           "Key", secret.data(), secret_len,
                                           nullptr, 0, key.data(), key.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "321b26943253c7ffb6003b0b64d74041");

  std::array<uint8_t, OSCORE_COMMON_IV_LEN> iv{};
  EXPECT_EQ(oc_oscore_context_derive_param(nullptr, 0, nullptr, 0, "IV",
                                           secret.data(), secret_len, nullptr,
                                           0, iv.data(), iv.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv.data(), iv.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "be35ae297d2dace910c52e99f9");

  std::array<uint8_t, 1> piv{};
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(sid.data(), sid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "bf35ae297d2dace810c52e99f9");

  oc_oscore_AEAD_nonce(rid.data(), rid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "bf35ae297d2dace910c52e99f9");
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

  std::array<uint8_t, 512> secret{};
  size_t secret_len = secret.size();
  std::string secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str.c_str(),
                                             secret_str.length(), secret.data(),
                                             &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  std::array<uint8_t, 512> salt{};
  size_t salt_len = salt.size();
  std::string salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(
              salt_str.c_str(), salt_str.length(), salt.data(), &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  std::array<uint8_t, 512> idctx{};
  size_t idctx_len = idctx.size();
  std::string idctx_str = "37cbf3210017a2d3";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(
              idctx_str.c_str(), idctx_str.length(), idctx.data(), &idctx_len),
            0);
  EXPECT_EQ(idctx_len, 8);

  std::array<uint8_t, OSCORE_KEY_LEN> key{};
  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, idctx.data(), idctx_len, "Key", secret.data(),
              secret_len, salt.data(), salt_len, key.data(), key.size()),
            0);
  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "af2a1300a5e95788b356336eeecd2b92");

  std::array<uint8_t, 1> rid = { 0x01 };
  EXPECT_EQ(oc_oscore_context_derive_param(rid.data(), rid.size(), idctx.data(),
                                           idctx_len, "Key", secret.data(),
                                           secret_len, salt.data(), salt_len,
                                           key.data(), key.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "e39a0c7c77b43f03b4b39ab9a268699f");

  std::array<uint8_t, OSCORE_COMMON_IV_LEN> iv{};
  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, idctx.data(), idctx_len, "IV", secret.data(),
              secret_len, salt.data(), salt_len, iv.data(), iv.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv.data(), iv.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "2ca58fb85ff1b81c0b7181b85e");

  std::array<uint8_t, 1> piv{};
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(nullptr, 0, piv.data(), piv.size(), iv.data(),
                       nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "2ca58fb85ff1b81c0b7181b85e");

  oc_oscore_AEAD_nonce(rid.data(), rid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "2da58fb85ff1b81d0b7181b85e");
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

  std::array<uint8_t, 512> secret{};
  size_t secret_len = secret.size();
  std::string secret_str = "0102030405060708090a0b0c0d0e0f10";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(secret_str.c_str(),
                                             secret_str.length(), secret.data(),
                                             &secret_len),
            0);
  EXPECT_EQ(secret_len, 16);

  std::array<uint8_t, 512> salt{};
  size_t salt_len = salt.size();
  std::string salt_str = "9e7ca92223786340";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(
              salt_str.c_str(), salt_str.length(), salt.data(), &salt_len),
            0);
  EXPECT_EQ(salt_len, 8);

  std::array<uint8_t, 512> idctx{};
  size_t idctx_len = idctx.size();
  std::string idctx_str = "37cbf3210017a2d3";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(
              idctx_str.c_str(), idctx_str.length(), idctx.data(), &idctx_len),
            0);
  EXPECT_EQ(idctx_len, 8);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  std::array<uint8_t, 1> sid = { 0x01 };
  std::array<uint8_t, OSCORE_KEY_LEN> key{};
  EXPECT_EQ(oc_oscore_context_derive_param(sid.data(), sid.size(), idctx.data(),
                                           idctx_len, "Key", secret.data(),
                                           secret_len, salt.data(), salt_len,
                                           key.data(), key.size()),
            0);
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "e39a0c7c77b43f03b4b39ab9a268699f");

  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, idctx.data(), idctx_len, "Key", secret.data(),
              secret_len, salt.data(), salt_len, key.data(), key.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(key.data(), key.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "af2a1300a5e95788b356336eeecd2b92");

  std::array<uint8_t, OSCORE_COMMON_IV_LEN> iv{};
  EXPECT_EQ(oc_oscore_context_derive_param(
              nullptr, 0, idctx.data(), idctx_len, "IV", secret.data(),
              secret_len, salt.data(), salt_len, iv.data(), iv.size()),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(iv.data(), iv.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "2ca58fb85ff1b81c0b7181b85e");

  std::array<uint8_t, 1> piv{};
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(sid.data(), sid.size(), piv.data(), piv.size(),
                       iv.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "2da58fb85ff1b81d0b7181b85e");

  oc_oscore_AEAD_nonce(nullptr, 0, piv.data(), piv.size(), iv.data(),
                       nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "2ca58fb85ff1b81c0b7181b85e");
}

/* C.4.  Test Vector 4: OSCORE Request, Client */
TEST_F(TestOSCORE, ClientRequest1_P)
{
  /*
    Unprotected CoAP request:
     0x44015d1f00003974396c6f63616c686f737483747631 (22 bytes)
  */

  std::array<uint8_t, 512> buffer{};
  size_t buffer_len = buffer.size();
  std::string request_str = "44015d1f00003974396c6f63616c686f737483747631";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(request_str.c_str(),
                                             request_str.length(),
                                             buffer.data(), &buffer_len),
            0);

  coap_packet_t coap_pkt;
  coap_status_t code =
    coap_udp_parse_message(&coap_pkt, buffer.data(), buffer_len, false);
  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes) */

  std::string civ_str = "4622d4dd6d944168eefb54987c";
  std::array<uint8_t, 512> civ{};
  size_t civ_len = civ.size();
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(civ_str.c_str(), civ_str.length(),
                                             civ.data(), &civ_len),
            0);

  /*
    Sender ID: 0x (0 byte)
    Sender Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
    Sender Sequence Number: 20
  */
  std::string key_str = "f0910ed7295e6ad4b54fc793154302ff";
  std::array<uint8_t, 512> skey{};
  size_t skey_len = skey.size();
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(key_str.c_str(), key_str.length(),
                                             skey.data(), &skey_len),
            0);

  uint64_t ssn = 20;
  std::array<uint8_t, OSCORE_PIV_LEN> piv{};
  uint8_t piv_len = piv.size();
  oscore_store_piv(ssn, piv.data(), &piv_len);

  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */

  std::array<uint8_t, OSCORE_AAD_MAX_LEN> AAD{};
  uint8_t AAD_len = AAD.size();
  EXPECT_EQ(oc_oscore_compose_AAD(nullptr, 0, piv.data(), piv_len, AAD.data(),
                                  &AAD_len),
            0);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(AAD.data(), AAD_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x01b3747631 (5 bytes) */
  uint8_t *payload = buffer.data() + 256;
  size_t payload_size = buffer.size() - 256;
  size_t plaintext_len =
    oscore_serialize_plaintext(&coap_pkt, payload, payload_size);

  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(payload, plaintext_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "01b3747631");

  /* Verify nonce: 0x4622d4dd6d944168eefb549868 (13 bytes) */
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(nullptr, 0, piv.data(), piv_len, civ.data(),
                       nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4622d4dd6d944168eefb549868");

  /* Verify ciphertext: 0x612f1092f1776f1c1668b3825e (13 bytes) */
  EXPECT_EQ(oc_oscore_encrypt(payload, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey.data(), skey_len, nonce.data(), nonce.size(),
                              AAD.data(), AAD_len, payload),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(
              payload, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec.data(),
              &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "612f1092f1776f1c1668b3825e");

  coap_pkt.payload = payload;
  coap_pkt.payload_len =
    static_cast<uint32_t>(plaintext_len + OSCORE_AEAD_TAG_LEN);

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt.code = static_cast<uint8_t>(oscore_get_outer_code(&coap_pkt));

  /* Set the OSCORE option */
  coap_set_header_oscore(&coap_pkt, piv.data(), piv_len, nullptr, 0, nullptr,
                         0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len =
    oscore_serialize_message(&coap_pkt, buffer.data(), buffer.size());

  /* Verify protected CoAP request (OSCORE message): 0x44025d1f00003974396c6f6
      3616c686f7374620914ff612f1092f1776f1c1668b3825e (35 bytes)
  */
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer.data(), buffer_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(
    testvec.data(),
    "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e");
}

/* C.5.  Test Vector 5: OSCORE Request, Client */
TEST_F(TestOSCORE, ClientRequest2_P)
{
  /*
    Unprotected CoAP request:
     0x440171c30000b932396c6f63616c686f737483747631 (22 bytes)
  */

  std::array<uint8_t, 512> buffer{};
  size_t buffer_len = buffer.size();
  std::string request_str = "440171c30000b932396c6f63616c686f737483747631";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(request_str.c_str(),
                                             request_str.length(),
                                             buffer.data(), &buffer_len),
            0);

  coap_packet_t coap_pkt;
  coap_status_t code =
    coap_udp_parse_message(&coap_pkt, buffer.data(), buffer_len, false);
  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0xbe35ae297d2dace910c52e99f9 (13 bytes) */

  std::array<uint8_t, 512> civ{};
  size_t civ_len = civ.size();
  std::string civ_str = "be35ae297d2dace910c52e99f9";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(civ_str.c_str(), civ_str.length(),
                                             civ.data(), &civ_len),
            0);

  /*
    Sender ID: 0x00 (1 byte)
    Sender Key: 0x321b26943253c7ffb6003b0b64d74041 (16 bytes)
    Sender Sequence Number: 20
  */
  std::array<uint8_t, 1> sid{};
  std::array<uint8_t, 512> skey{};
  size_t skey_len = skey.size();
  std::string key_str = "321b26943253c7ffb6003b0b64d74041";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(key_str.c_str(), key_str.length(),
                                             skey.data(), &skey_len),
            0);

  uint64_t ssn = 20;
  std::array<uint8_t, OSCORE_PIV_LEN> piv{};
  uint8_t piv_len = piv.size();
  oscore_store_piv(ssn, piv.data(), &piv_len);

  /* Verify AAD: 0x8368456e63727970743040498501810a4100411440 (20 bytes) */

  std::array<uint8_t, OSCORE_AAD_MAX_LEN> AAD{};
  uint8_t AAD_len = AAD.size();
  EXPECT_EQ(oc_oscore_compose_AAD(sid.data(), sid.size(), piv.data(), piv_len,
                                  AAD.data(), &AAD_len),
            0);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(AAD.data(), AAD_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "8368456e63727970743040498501810a4100411440");

  /* Verify plaintext: 0x01b3747631 (5 bytes) */
  uint8_t *payload = buffer.data() + 256;
  size_t payload_size = buffer.size() - 256;
  size_t plaintext_len =
    oscore_serialize_plaintext(&coap_pkt, payload, payload_size);

  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(payload, plaintext_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "01b3747631");

  /* Verify nonce: 0xbf35ae297d2dace910c52e99ed (13 bytes) */
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(sid.data(), sid.size(), piv.data(), piv_len, civ.data(),
                       nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "bf35ae297d2dace910c52e99ed");

  /* Verify ciphertext: 0x4ed339a5a379b0b8bc731fffb0 (13 bytes) */
  EXPECT_EQ(oc_oscore_encrypt(payload, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey.data(), skey_len, nonce.data(), nonce.size(),
                              AAD.data(), AAD_len, payload),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(
              payload, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec.data(),
              &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4ed339a5a379b0b8bc731fffb0");

  coap_pkt.payload = payload;
  coap_pkt.payload_len =
    static_cast<uint32_t>(plaintext_len + OSCORE_AEAD_TAG_LEN);

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt.code = static_cast<uint8_t>(oscore_get_outer_code(&coap_pkt));

  /* Set the OSCORE option */
  coap_set_header_oscore(&coap_pkt, piv.data(), piv_len, sid.data(), sid.size(),
                         nullptr, 0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len =
    oscore_serialize_message(&coap_pkt, buffer.data(), buffer.size());

  /* Protected CoAP request (OSCORE message): 0x440271c30000b932396c6f6
      3616c686f737463091400ff4ed339a5a379b0b8bc731fffb0 (36 bytes)
  */
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer.data(), buffer_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(),
               "440271c30000b932396c6f63616c686f737463091400ff4ed339a5"
               "a379b0b8bc731fffb0");
}

/* C.6.  Test Vector 6: OSCORE Request, Client */
TEST_F(TestOSCORE, ClientRequest3_P)
{
  /*
    Unprotected CoAP request:
     0x44012f8eef9bbf7a396c6f63616c686f737483747631 (22 bytes)
  */

  std::array<uint8_t, 512> buffer{};
  size_t buffer_len = buffer.size();
  std::string request_str = "44012f8eef9bbf7a396c6f63616c686f737483747631";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(request_str.c_str(),
                                             request_str.length(),
                                             buffer.data(), &buffer_len),
            0);

  coap_packet_t coap_pkt;
  coap_status_t code =
    coap_udp_parse_message(&coap_pkt, buffer.data(), buffer_len, false);
  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x2ca58fb85ff1b81c0b7181b85e (13 bytes) */

  std::array<uint8_t, 512> civ{};
  size_t civ_len = civ.size();
  std::string civ_str = "2ca58fb85ff1b81c0b7181b85e";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(civ_str.c_str(), civ_str.length(),
                                             civ.data(), &civ_len),
            0);

  /*
    ID Context: 0x37cbf3210017a2d3 (8 bytes)
    Sender ID: 0x (0 bytes)
    Sender Key: 0xaf2a1300a5e95788b356336eeecd2b92 (16 bytes)
    Sender Sequence Number: 20
  */
  std::array<uint8_t, 512> idctx{};
  size_t idctx_len = idctx.size();
  std::string idctx_str = "37cbf3210017a2d3";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(
              idctx_str.c_str(), idctx_str.length(), idctx.data(), &idctx_len),
            0);

  std::array<uint8_t, 512> skey{};
  size_t skey_len = skey.size();
  std::string key_str = "af2a1300a5e95788b356336eeecd2b92";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(key_str.c_str(), key_str.length(),
                                             skey.data(), &skey_len),
            0);

  uint64_t ssn = 20;
  std::array<uint8_t, OSCORE_PIV_LEN> piv{};
  uint8_t piv_len = piv.size();
  oscore_store_piv(ssn, piv.data(), &piv_len);

  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */

  std::array<uint8_t, OSCORE_AAD_MAX_LEN> AAD{};
  uint8_t AAD_len = AAD.size();
  EXPECT_EQ(oc_oscore_compose_AAD(nullptr, 0, piv.data(), piv_len, AAD.data(),
                                  &AAD_len),
            0);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(AAD.data(), AAD_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x01b3747631 (5 bytes) */
  uint8_t *payload = buffer.data() + 256;
  size_t payload_size = buffer.size() - 256;
  size_t plaintext_len =
    oscore_serialize_plaintext(&coap_pkt, payload, payload_size);

  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(payload, plaintext_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "01b3747631");

  /* Verify nonce: 0x2ca58fb85ff1b81c0b7181b84a (13 bytes) */
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(nullptr, 0, piv.data(), piv_len, civ.data(),
                       nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "2ca58fb85ff1b81c0b7181b84a");

  /* Verify ciphertext: 0x72cd7273fd331ac45cffbe55c3 (13 bytes) */
  EXPECT_EQ(oc_oscore_encrypt(payload, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey.data(), skey_len, nonce.data(), nonce.size(),
                              AAD.data(), AAD_len, payload),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(
              payload, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec.data(),
              &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "72cd7273fd331ac45cffbe55c3");

  coap_pkt.payload = payload;
  coap_pkt.payload_len =
    static_cast<uint32_t>(plaintext_len + OSCORE_AEAD_TAG_LEN);

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt.code = static_cast<uint8_t>(oscore_get_outer_code(&coap_pkt));

  /* Set the OSCORE option */
  coap_set_header_oscore(&coap_pkt, piv.data(), piv_len, nullptr, 0,
                         idctx.data(), static_cast<uint8_t>(idctx_len));

  /* Serialize OSCORE message to oc_message_t */
  buffer_len =
    oscore_serialize_message(&coap_pkt, buffer.data(), buffer.size());

  /* Protected CoAP request (OSCORE message):
      0x44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff
      72cd7273fd331ac45cffbe55c3 (44 bytes)
  */
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer.data(), buffer_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(),
               "44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf32100"
               "17a2d3ff72cd7273fd331ac45cffbe55c3");
}

/* C.7.  Test Vector 7: OSCORE Response, Server */
TEST_F(TestOSCORE, ServerResponse1_P)
{
  /*
    Unprotected CoAP response:
     0x64455d1f00003974ff48656c6c6f20576f726c6421 (21 bytes)
  */

  std::array<uint8_t, 512> buffer{};
  size_t buffer_len = buffer.size();
  std::string response_str = "64455d1f00003974ff48656c6c6f20576f726c6421";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(response_str.c_str(),
                                             response_str.length(),
                                             buffer.data(), &buffer_len),
            0);

  coap_packet_t coap_pkt;
  coap_status_t code =
    coap_udp_parse_message(&coap_pkt, buffer.data(), buffer_len, false);
  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes) */

  std::array<uint8_t, 512> civ{};
  size_t civ_len = civ.size();
  std::string civ_str = "4622d4dd6d944168eefb54987c";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(civ_str.c_str(), civ_str.length(),
                                             civ.data(), &civ_len),
            0);

  /*
    Sender ID: 0x01 (1 byte)
    Sender Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
    Sender Sequence Number: 0
  */
  std::array<uint8_t, 512> skey{};
  size_t skey_len = skey.size();
  std::string key_str = "ffb14e093c94c9cac9471648b4f98710";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(key_str.c_str(), key_str.length(),
                                             skey.data(), &skey_len),
            0);

  /* Using request_piv & request_kid from test vector C.4 */
  std::array<uint8_t, 1> request_piv = { 0x14 };

  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */
  std::array<uint8_t, OSCORE_AAD_MAX_LEN> AAD{};
  uint8_t AAD_len = AAD.size();
  EXPECT_EQ(oc_oscore_compose_AAD(nullptr, 0, request_piv.data(),
                                  request_piv.size(), AAD.data(), &AAD_len),
            0);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(AAD.data(), AAD_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x45ff48656c6c6f20576f726c6421 (14 bytes) */
  uint8_t *payload = buffer.data() + 256;
  size_t payload_size = buffer.size() - 256;
  size_t plaintext_len =
    oscore_serialize_plaintext(&coap_pkt, payload, payload_size);

  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(payload, plaintext_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "45ff48656c6c6f20576f726c6421");

  /* Verify nonce: 0x4622d4dd6d944168eefb549868 (13 bytes) */
  /* Using nonce from request in test vector C.4 */
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(nullptr, 0, request_piv.data(), request_piv.size(),
                       civ.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4622d4dd6d944168eefb549868");

  /* Verify ciphertext: 0xdbaad1e9a7e7b2a813d3c31524378303cdafae119106 (22
      bytes) */
  EXPECT_EQ(oc_oscore_encrypt(payload, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey.data(), skey_len, nonce.data(), nonce.size(),
                              AAD.data(), AAD_len, payload),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(
              payload, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec.data(),
              &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "dbaad1e9a7e7b2a813d3c31524378303cdafae119106");

  coap_pkt.payload = payload;
  coap_pkt.payload_len =
    static_cast<uint32_t>(plaintext_len + OSCORE_AEAD_TAG_LEN);

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt.code = static_cast<uint8_t>(oscore_get_outer_code(&coap_pkt));

  /* Set the OSCORE option */
  coap_set_header_oscore(&coap_pkt, nullptr, 0, nullptr, 0, nullptr, 0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len =
    oscore_serialize_message(&coap_pkt, buffer.data(), buffer.size());

  /*
    Protected CoAP response (OSCORE message):
      0x64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106
      (32 bytes)
  */
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer.data(), buffer_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(
    testvec.data(),
    "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106");
}

/* C.8.  Test Vector 8: OSCORE Response with Partial IV, Server */
TEST_F(TestOSCORE, ServerResponse2_P)
{
  /*
    Unprotected CoAP response:
     0x64455d1f00003974ff48656c6c6f20576f726c6421 (21 bytes)
  */

  std::array<uint8_t, 512> buffer{};
  size_t buffer_len = buffer.size();
  std::string response_str = "64455d1f00003974ff48656c6c6f20576f726c6421";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(response_str.c_str(),
                                             response_str.length(),
                                             buffer.data(), &buffer_len),
            0);

  coap_packet_t coap_pkt;
  coap_status_t code =
    coap_udp_parse_message(&coap_pkt, buffer.data(), buffer_len, false);
  EXPECT_EQ(code, COAP_NO_ERROR);

  /* Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes) */

  std::array<uint8_t, 512> civ{};
  size_t civ_len = civ.size();
  std::string civ_str = "4622d4dd6d944168eefb54987c";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(civ_str.c_str(), civ_str.length(),
                                             civ.data(), &civ_len),
            0);

  /*
    Sender Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
  */
  std::array<uint8_t, 512> skey{};
  size_t skey_len = skey.size();
  std::string key_str = "ffb14e093c94c9cac9471648b4f98710";
  EXPECT_EQ(oc_conv_hex_string_to_byte_array(key_str.c_str(), key_str.length(),
                                             skey.data(), &skey_len),
            0);

  /* Using request_piv & request_kid from test vetor in C.4 */
  std::array<uint8_t, 1> request_piv = { 0x14 };
  /* Verify AAD: 0x8368456e63727970743040488501810a40411440 (20 bytes) */
  std::array<uint8_t, OSCORE_AAD_MAX_LEN> AAD{};
  uint8_t AAD_len = AAD.size();
  EXPECT_EQ(oc_oscore_compose_AAD(nullptr, 0, request_piv.data(),
                                  request_piv.size(), AAD.data(), &AAD_len),
            0);

  std::array<char, 512> testvec{};
  size_t testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(AAD.data(), AAD_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "8368456e63727970743040488501810a40411440");

  /* Verify plaintext: 0x45ff48656c6c6f20576f726c6421 (14 bytes) */
  uint8_t *payload = buffer.data() + 256;
  size_t payload_size = buffer.size() - 256;
  size_t plaintext_len =
    oscore_serialize_plaintext(&coap_pkt, payload, payload_size);

  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(payload, plaintext_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "45ff48656c6c6f20576f726c6421");

  /*
    Sender ID: 0x01 (1 byte)
    Sender Sequence Number: 0
  */
  std::array<uint8_t, 1> sid = { 0x01 };
  std::array<uint8_t, 1> piv{};
  /* Verify nonce: 0x4722d4dd6d944169eefb54987c (13 bytes) */
  std::array<uint8_t, OSCORE_AEAD_NONCE_LEN> nonce{};
  oc_oscore_AEAD_nonce(sid.data(), sid.size(), piv.data(), piv.size(),
                       civ.data(), nonce.data(), nonce.size());
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(nonce.data(), nonce.size(),
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4722d4dd6d944169eefb54987c");

  /* Verify ciphertext: 0x4d4c13669384b67354b2b6175ff4b8658c666a6cf88e (22
      bytes) */
  EXPECT_EQ(oc_oscore_encrypt(payload, plaintext_len, OSCORE_AEAD_TAG_LEN,
                              skey.data(), skey_len, nonce.data(), nonce.size(),
                              AAD.data(), AAD_len, payload),
            0);
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(
              payload, plaintext_len + OSCORE_AEAD_TAG_LEN, testvec.data(),
              &testvec_len),
            0);
  EXPECT_STREQ(testvec.data(), "4d4c13669384b67354b2b6175ff4b8658c666a6cf88e");

  coap_pkt.payload = payload;
  coap_pkt.payload_len =
    static_cast<uint32_t>(plaintext_len + OSCORE_AEAD_TAG_LEN);

  /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
  coap_pkt.code = static_cast<uint8_t>(oscore_get_outer_code(&coap_pkt));

  /* Set the OSCORE option */
  coap_set_header_oscore(&coap_pkt, piv.data(), piv.size(), nullptr, 0, nullptr,
                         0);

  /* Serialize OSCORE message to oc_message_t */
  buffer_len =
    oscore_serialize_message(&coap_pkt, buffer.data(), buffer.size());

  /*
    Protected CoAP response (OSCORE message): 0x64445d1f00003974920100
      ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e (34 bytes)
  */
  testvec_len = testvec.size();
  EXPECT_EQ(oc_conv_byte_array_to_hex_string(buffer.data(), buffer_len,
                                             testvec.data(), &testvec_len),
            0);
  EXPECT_STREQ(
    testvec.data(),
    "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e");
}

#endif /* OC_SECURITY && OC_OSCORE */
