/******************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "oc_config.h"
#include "port/oc_random.h"
#include "security/oc_keypair_internal.h"
#include "security/oc_security_internal.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/RepPool.h"

#include <array>
#include <gtest/gtest.h>
#include <stdint.h>
#include <string.h>

class TestKeyPair : public testing::Test {
  void SetUp() override
  {
    oc_random_init();
    oc_mbedtls_init();
  }

  void TearDown() override
  {
    oc_sec_free_ecdsa_keypairs();
    oc_random_destroy();
  }
};

TEST_F(TestKeyPair, GenerateFail_SmallBuffers)
{
  std::array<uint8_t, 1> too_small{};
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> public_key{};
  size_t private_key_size = 0;
  std::array<uint8_t, OC_ECDSA_PRIVKEY_SIZE> private_key{};
  size_t public_key_size = 0;
  int ret = oc_generate_ecdsa_keypair(MBEDTLS_ECP_DP_SECP256R1,
                                      too_small.data(), too_small.size(),
                                      &public_key_size, private_key.data(),
                                      private_key.size(), &private_key_size);
  EXPECT_NE(0, ret);

  ret = oc_generate_ecdsa_keypair(
    MBEDTLS_ECP_DP_SECP256R1, public_key.data(), public_key.size(),
    &public_key_size, too_small.data(), too_small.size(), &private_key_size);
  EXPECT_NE(0, ret);
}

TEST_F(TestKeyPair, GenerateFail_UnsupportedECP)
{
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> public_key{};
  size_t private_key_size = 0;
  std::array<uint8_t, OC_ECDSA_PRIVKEY_SIZE> private_key{};
  size_t public_key_size = 0;
  int ret = oc_generate_ecdsa_keypair(MBEDTLS_ECP_DP_SECP192R1,
                                      public_key.data(), public_key.size(),
                                      &public_key_size, private_key.data(),
                                      private_key.size(), &private_key_size);
  EXPECT_NE(0, ret);
}

TEST_F(TestKeyPair, Generate)
{
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> public_key{};
  size_t private_key_size = 0;
  std::array<uint8_t, OC_ECDSA_PRIVKEY_SIZE> private_key{};
  size_t public_key_size = 0;
  int ret = oc_generate_ecdsa_keypair(MBEDTLS_ECP_DP_SECP256R1,
                                      public_key.data(), public_key.size(),
                                      &public_key_size, private_key.data(),
                                      private_key.size(), &private_key_size);
  EXPECT_EQ(0, ret);
}

TEST_F(TestKeyPair, EncodeFail_BufferTooSmall)
{
  /* buffer for oc_rep_t */
  std::array<uint8_t, 10> buf{}; // Purposely small buffer
  oc_rep_new(buf.data(), buf.size());

  oc_ecdsa_keypair_t kp = oc::GetOCKeyPair(MBEDTLS_ECP_DP_SECP256R1);
  EXPECT_FALSE(oc_sec_encode_ecdsa_keypair(&kp));
}

TEST_F(TestKeyPair, Encode)
{
  oc::RepPool pool{};

  oc_ecdsa_keypair_t kp = oc::GetOCKeyPair(MBEDTLS_ECP_DP_SECP256R1);
  EXPECT_TRUE(oc_sec_encode_ecdsa_keypair(&kp));
}

TEST_F(TestKeyPair, DecodeFail_MissingPublicKey)
{
  oc::RepPool pool{};
  std::array<uint8_t, 4> pk{ '1', '3', '3', '7' };

  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_byte_string(root, private_key, pk.data(), pk.size());
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  oc_ecdsa_keypair_t kp{};
  EXPECT_FALSE(oc_sec_decode_ecdsa_keypair(rep.get(), &kp));
}

TEST_F(TestKeyPair, DecodeFail_MissingPrivateKey)
{
  oc::RepPool pool{};
  auto kp_in = oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1);

  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_byte_string(root, public_key, kp_in.public_key.data(),
                         kp_in.public_key.size());
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  oc_ecdsa_keypair_t kp{};
  EXPECT_FALSE(oc_sec_decode_ecdsa_keypair(rep.get(), &kp));
}

TEST_F(TestKeyPair, DecodeFail_InvalidPublicKey)
{
  oc::RepPool pool{};
  std::array<uint8_t, 4> pk{ '1', '3', '3', '7' };
  auto kp_in = oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1);

  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_byte_string(root, public_key, pk.data(), pk.size());
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_byte_string(root, private_key, kp_in.private_key.data(),
                         kp_in.private_key.size());
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  oc_ecdsa_keypair_t kp{};
  EXPECT_FALSE(oc_sec_decode_ecdsa_keypair(rep.get(), &kp));
}

TEST_F(TestKeyPair, DecodeFail_InvalidPrivateKey)
{
  oc::RepPool pool{};
  std::array<uint8_t, OC_ECDSA_PRIVKEY_SIZE + 1> pk{};
  auto kp_in = oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1);

  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_byte_string(root, public_key, kp_in.public_key.data(),
                         kp_in.public_key.size());
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_byte_string(root, private_key, pk.data(), pk.size());
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  oc_ecdsa_keypair_t kp{};
  EXPECT_FALSE(oc_sec_decode_ecdsa_keypair(rep.get(), &kp));
}

TEST_F(TestKeyPair, Decode)
{
  oc::RepPool pool{};
  oc_ecdsa_keypair_t kp_in = oc::GetOCKeyPair(MBEDTLS_ECP_DP_SECP256R1);
  EXPECT_TRUE(oc_sec_encode_ecdsa_keypair(&kp_in));

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  oc_ecdsa_keypair_t kp_out{};
  EXPECT_TRUE(oc_sec_decode_ecdsa_keypair(rep.get(), &kp_out));

  EXPECT_EQ(
    0, memcmp(&kp_in.public_key, &kp_out.public_key, OC_ECDSA_PUBKEY_SIZE));
  EXPECT_EQ(kp_in.private_key_size, kp_out.private_key_size);
  EXPECT_EQ(
    0, memcmp(&kp_in.private_key, &kp_out.private_key, kp_in.private_key_size));
}

TEST_F(TestKeyPair, GenerateForDevice)
{
  EXPECT_EQ(0, oc_sec_count_ecdsa_keypairs());
  EXPECT_TRUE(oc_generate_ecdsa_keypair_for_device(/*device*/ 0));
  EXPECT_EQ(1, oc_sec_count_ecdsa_keypairs());
  EXPECT_TRUE(oc_generate_ecdsa_keypair_for_device(/*device*/ 0));
  EXPECT_EQ(1, oc_sec_count_ecdsa_keypairs());

  EXPECT_NE(nullptr, oc_sec_get_ecdsa_keypair(/*device*/ 0));
  EXPECT_EQ(nullptr, oc_sec_get_ecdsa_keypair(/*device*/ 1));
}

TEST_F(TestKeyPair, GenerateForMultipleDevices)
{
#ifdef OC_DYNAMIC_ALLOCATION
  for (size_t i = 0; i < 4; ++i) {
    EXPECT_TRUE(oc_generate_ecdsa_keypair_for_device(/*device*/ i));
  }
  EXPECT_EQ(4, oc_sec_count_ecdsa_keypairs());
#else  /* !OC_DYNAMIC_ALLOCATION */
  // without dynamic allocation, the number of items is limited to
  // OC_MAX_NUM_DEVICES
  for (size_t i = 0; i < OC_MAX_NUM_DEVICES; ++i) {
    EXPECT_TRUE(oc_generate_ecdsa_keypair_for_device(/*device*/ i));
  }
  EXPECT_EQ(OC_MAX_NUM_DEVICES, oc_sec_count_ecdsa_keypairs());

  // additional allocations should fail
  EXPECT_FALSE(
    oc_generate_ecdsa_keypair_for_device(/*device*/ OC_MAX_NUM_DEVICES));
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestKeyPair, EncodeForDevice)
{
  oc::RepPool pool{};
  EXPECT_EQ(nullptr, oc_sec_get_ecdsa_keypair(/*device*/ 0));
  EXPECT_FALSE(oc_sec_encode_ecdsa_keypair_for_device(/*device*/ 0));

  EXPECT_TRUE(oc_generate_ecdsa_keypair_for_device(/*device*/ 0));
  EXPECT_TRUE(oc_sec_encode_ecdsa_keypair_for_device(/*device*/ 0));
  EXPECT_NE(nullptr, oc_sec_get_ecdsa_keypair(/*device*/ 0));
}

TEST_F(TestKeyPair, DecodeForDevice)
{
  oc::RepPool pool{};

  auto decodeForDevice = [&pool](size_t device, mbedtls_ecp_group_id grpid) {
    oc_ecdsa_keypair_t kp_in = oc::GetOCKeyPair(grpid);
    EXPECT_TRUE(oc_sec_encode_ecdsa_keypair(&kp_in));

    EXPECT_GE(1, oc_sec_count_ecdsa_keypairs());
    auto rep = pool.ParsePayload();
    EXPECT_TRUE(oc_sec_decode_ecdsa_keypair_for_device(rep.get(), device));
    oc_ecdsa_keypair_t *kp_out = oc_sec_get_ecdsa_keypair(device);
    EXPECT_NE(nullptr, kp_out);

    EXPECT_EQ(
      0, memcmp(&kp_in.public_key, &kp_out->public_key, OC_ECDSA_PUBKEY_SIZE));
    EXPECT_EQ(kp_in.private_key_size, kp_out->private_key_size);
    EXPECT_EQ(0, memcmp(&kp_in.private_key, &kp_out->private_key,
                        kp_in.private_key_size));
  };

  decodeForDevice(0, MBEDTLS_ECP_DP_SECP256R1);

  // overwrite data
  pool.Clear();
  decodeForDevice(0, MBEDTLS_ECP_DP_SECP256R1);

  EXPECT_EQ(1, oc_sec_count_ecdsa_keypairs());
}

TEST_F(TestKeyPair, DecodeForMultipleDevices)
{
  oc::RepPool pool{};
#ifdef OC_DYNAMIC_ALLOCATION
  size_t count = 4;
#else  /* !OC_DYNAMIC_ALLOCATION */
  size_t count = OC_MAX_NUM_DEVICES;
#endif /* OC_DYNAMIC_ALLOCATION */

  std::vector<oc_ecdsa_keypair_t> keypairs{};
  for (size_t i = 0; i < count; ++i) {
    oc_ecdsa_keypair_t kp_in = oc::GetOCKeyPair(MBEDTLS_ECP_DP_SECP256R1);
    keypairs.push_back(kp_in);

    EXPECT_TRUE(oc_sec_encode_ecdsa_keypair(&kp_in));
    auto rep = pool.ParsePayload();
    EXPECT_TRUE(
      oc_sec_decode_ecdsa_keypair_for_device(rep.get(), /*device*/ i));
    pool.Clear();
  }
  EXPECT_EQ(keypairs.size(), oc_sec_count_ecdsa_keypairs());

  for (size_t i = 0; i < keypairs.size(); ++i) {
    oc_ecdsa_keypair_t *kp_out = oc_sec_get_ecdsa_keypair(/*device*/ i);
    EXPECT_NE(nullptr, kp_out);

    const auto &kp_in = keypairs[i];
    EXPECT_EQ(
      0, memcmp(&kp_in.public_key, &kp_out->public_key, OC_ECDSA_PUBKEY_SIZE));
    EXPECT_EQ(kp_in.private_key_size, kp_out->private_key_size);
    EXPECT_EQ(0, memcmp(&kp_in.private_key, &kp_out->private_key,
                        kp_in.private_key_size));
  }

#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_TRUE(oc_sec_encode_ecdsa_keypair(&keypairs[0]));
  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_ecdsa_keypair_for_device(
    rep.get(), /*device*/ OC_MAX_NUM_DEVICES));
#endif /* !OC_DYNAMIC_ALLOCATION */
}

#endif /* OC_SECURITY && OC_PKI */
