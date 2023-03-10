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

#include "oc_certs.h"
#include "oc_config.h"
#include "port/oc_random.h"
#include "security/oc_keypair_internal.h"
#include "security/oc_security_internal.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/RepPool.h"

#include <array>
#include <mbedtls/ecp.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <string.h>

class TestKeyPair : public testing::Test {
public:
  static void SetUpTestCase()
  {
    // allow all ocf-supported ECs
    oc_sec_certs_ecp_set_group_ids_allowed(OCF_CERTS_SUPPORTED_ELLIPTIC_CURVES);
    for (int i = 1; i < MBEDTLS_ECP_DP_MAX; ++i) {
      auto ec = static_cast<mbedtls_ecp_group_id>(i);
      if (oc_sec_certs_ecp_group_id_is_allowed(ec)) {
        g_ocf_ecs.push_back(ec);
      }
    }
  }

  static void TearDownTestCase()
  {
    // restore defaults
    oc_sec_certs_ecp_set_group_ids_allowed(
      MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1));
  }

  static void CompareKeys(const oc_ecdsa_keypair_t &lhs,
                          const oc_ecdsa_keypair_t &rhs)
  {
    EXPECT_EQ(lhs.public_key_size, rhs.public_key_size);
    EXPECT_EQ(0, memcmp(&lhs.public_key, &rhs.public_key, rhs.public_key_size));
    EXPECT_EQ(lhs.private_key_size, rhs.private_key_size);
    EXPECT_EQ(0,
              memcmp(&lhs.private_key, &rhs.private_key, rhs.private_key_size));
  }

  void SetUp() override
  {
    oc_random_init();
    oc_mbedtls_init();
  }

  void TearDown() override
  {
    oc_sec_ecdsa_free_keypairs();
    oc_random_destroy();
  }

  static std::vector<mbedtls_ecp_group_id> g_ocf_ecs;
};

std::vector<mbedtls_ecp_group_id> TestKeyPair::g_ocf_ecs{};

TEST_F(TestKeyPair, GenerateFail_SmallBuffers)
{

  std::array<uint8_t, 1> too_small{};
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> public_key{};
  size_t private_key_size = 0;
  std::array<uint8_t, OC_ECDSA_PRIVKEY_SIZE> private_key{};
  size_t public_key_size = 0;
  int ret = oc_sec_ecdsa_generate_keypair(
    MBEDTLS_ECP_DP_SECP256R1, too_small.data(), too_small.size(),
    &public_key_size, private_key.data(), private_key.size(),
    &private_key_size);
  EXPECT_NE(0, ret);

  ret = oc_sec_ecdsa_generate_keypair(
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
  int ret = oc_sec_ecdsa_generate_keypair(
    MBEDTLS_ECP_DP_SECP192R1, public_key.data(), public_key.size(),
    &public_key_size, private_key.data(), private_key.size(),
    &private_key_size);
  EXPECT_NE(0, ret);
}

TEST_F(TestKeyPair, Generate)
{
  auto generate_keypair = [](mbedtls_ecp_group_id grpid) {
    OC_DBG("generate ecdsa keypair with elliptic-curve %d", (int)grpid);
    std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> public_key{};
    size_t private_key_size = 0;
    std::array<uint8_t, OC_ECDSA_PRIVKEY_SIZE> private_key{};
    size_t public_key_size = 0;
    int ret = oc_sec_ecdsa_generate_keypair(
      grpid, public_key.data(), public_key.size(), &public_key_size,
      private_key.data(), private_key.size(), &private_key_size);
    EXPECT_EQ(0, ret) << "error for ec(" << grpid << ")";

    oc_sec_ecdsa_free_keypairs();
  };

  for (auto ec : g_ocf_ecs) {
    generate_keypair(ec);
  }
}

TEST_F(TestKeyPair, EncodeFail_BufferTooSmall)
{
  /* buffer for oc_rep_t */
  std::array<uint8_t, 10> buf{}; // Purposely small buffer
  oc_rep_new(buf.data(), buf.size());

  oc_ecdsa_keypair_t kp = oc::GetOCKeyPair(MBEDTLS_ECP_DP_SECP256R1);
  EXPECT_FALSE(oc_sec_ecdsa_encode_keypair(&kp));
}

TEST_F(TestKeyPair, Encode)
{
  auto generate_keypair = [](mbedtls_ecp_group_id grpid) {
    OC_DBG("encode ecdsa keypair with elliptic-curve %d", (int)grpid);
    oc::RepPool pool{};

    oc_ecdsa_keypair_t kp = oc::GetOCKeyPair(grpid);
    EXPECT_TRUE(oc_sec_ecdsa_encode_keypair(&kp));

    oc_sec_ecdsa_free_keypairs();
  };

  for (auto ec : g_ocf_ecs) {
    generate_keypair(ec);
  }
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
  EXPECT_FALSE(oc_sec_ecdsa_decode_keypair(rep.get(), &kp));
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
  EXPECT_FALSE(oc_sec_ecdsa_decode_keypair(rep.get(), &kp));
}

TEST_F(TestKeyPair, DecodeFail_InvalidPublicKey)
{
  oc::RepPool pool{};
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE + 1> pk{};
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
  EXPECT_FALSE(oc_sec_ecdsa_decode_keypair(rep.get(), &kp));
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
  EXPECT_FALSE(oc_sec_ecdsa_decode_keypair(rep.get(), &kp));
}

TEST_F(TestKeyPair, Decode)
{
  auto decode_keypair = [](mbedtls_ecp_group_id grpid) {
    OC_DBG("decode ecdsa keypair with elliptic-curve %d", (int)grpid);
    oc::RepPool pool{};
    oc_ecdsa_keypair_t kp_in = oc::GetOCKeyPair(grpid);
    EXPECT_TRUE(oc_sec_ecdsa_encode_keypair(&kp_in))
      << "error for ec(" << grpid << ")";

    oc::oc_rep_unique_ptr rep = pool.ParsePayload();
    oc_ecdsa_keypair_t kp_out{};
    EXPECT_TRUE(oc_sec_ecdsa_decode_keypair(rep.get(), &kp_out))
      << "error for ec(" << grpid << ")";

    CompareKeys(kp_in, kp_out);

    oc_sec_ecdsa_free_keypairs();
  };

  for (auto ec : g_ocf_ecs) {
    decode_keypair(ec);
  }
}

TEST_F(TestKeyPair, GenerateForDeviceFail_UnsupportedEllipticCurve)
{
  EXPECT_FALSE(
    oc_sec_ecdsa_generate_keypair_for_device(MBEDTLS_ECP_DP_SECP192R1,
                                             /*device*/ 0));
}

TEST_F(TestKeyPair, GenerateForDevice)
{
  auto generate_keypair = [](mbedtls_ecp_group_id grpid) {
    OC_DBG("generate ecdsa keypair with elliptic-curve %d", (int)grpid);
    EXPECT_EQ(0, oc_sec_ecdsa_count_keypairs())
      << "error for ec(" << grpid << ")";
    EXPECT_TRUE(oc_sec_ecdsa_generate_keypair_for_device(grpid,
                                                         /*device*/ 0))
      << "error for ec(" << grpid << ")";
    EXPECT_EQ(1, oc_sec_ecdsa_count_keypairs())
      << "error for ec(" << grpid << ")";
    EXPECT_TRUE(oc_sec_ecdsa_generate_keypair_for_device(grpid,
                                                         /*device*/ 0))
      << "error for ec(" << grpid << ")";
    EXPECT_EQ(1, oc_sec_ecdsa_count_keypairs())
      << "error for ec(" << grpid << ")";

    EXPECT_NE(nullptr, oc_sec_ecdsa_get_keypair(/*device*/ 0))
      << "error for ec(" << grpid << ")";
    EXPECT_EQ(nullptr, oc_sec_ecdsa_get_keypair(/*device*/ 1))
      << "error for ec(" << grpid << ")";

    oc_sec_ecdsa_free_keypairs();
  };

  for (auto ec : g_ocf_ecs) {
    generate_keypair(ec);
  }
}

TEST_F(TestKeyPair, GenerateForMultipleDevices)
{
#ifdef OC_DYNAMIC_ALLOCATION
  for (size_t i = 0; i < 4; ++i) {
    EXPECT_TRUE(oc_sec_ecdsa_generate_keypair_for_device(
      MBEDTLS_ECP_DP_SECP256R1, /*device*/ i));
  }
  EXPECT_EQ(4, oc_sec_ecdsa_count_keypairs());
#else  /* !OC_DYNAMIC_ALLOCATION */
  // without dynamic allocation, the number of items is limited to
  // OC_MAX_NUM_DEVICES
  for (size_t i = 0; i < OC_MAX_NUM_DEVICES; ++i) {
    EXPECT_TRUE(oc_sec_ecdsa_generate_keypair_for_device(
      MBEDTLS_ECP_DP_SECP256R1, /*device*/ i));
  }
  EXPECT_EQ(OC_MAX_NUM_DEVICES, oc_sec_ecdsa_count_keypairs());

  // additional allocations should fail
  EXPECT_FALSE(oc_sec_ecdsa_generate_keypair_for_device(
    MBEDTLS_ECP_DP_SECP256R1, /*device*/ OC_MAX_NUM_DEVICES));
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestKeyPair, EncodeForDevice)
{
  auto encode_keypair = [](mbedtls_ecp_group_id grpid, size_t device) {
    OC_DBG("encode ecdsa keypair with elliptic-curve %d", (int)grpid);
    oc::RepPool pool{};
    EXPECT_EQ(nullptr, oc_sec_ecdsa_get_keypair(device))
      << "error for ec(" << grpid << ")";
    EXPECT_FALSE(oc_sec_ecdsa_encode_keypair_for_device(device))
      << "error for ec(" << grpid << ")";

    EXPECT_TRUE(oc_sec_ecdsa_generate_keypair_for_device(grpid, device))
      << "error for ec(" << grpid << ")";
    EXPECT_TRUE(oc_sec_ecdsa_encode_keypair_for_device(device))
      << "error for ec(" << grpid << ")";
    EXPECT_NE(nullptr, oc_sec_ecdsa_get_keypair(device))
      << "error for ec(" << grpid << ")";
  };

  size_t device = 0;
  for (auto ec : g_ocf_ecs) {
    encode_keypair(ec, device);
    ++device;
  }
}

TEST_F(TestKeyPair, DecodeForDevice)
{
  oc::RepPool pool{};

  auto decodeForDevice = [&pool](size_t device, mbedtls_ecp_group_id grpid) {
    OC_DBG("decode ecdsa keypair with elliptic-curve %d", (int)grpid);
    oc_ecdsa_keypair_t kp_in = oc::GetOCKeyPair(grpid);
    EXPECT_TRUE(oc_sec_ecdsa_encode_keypair(&kp_in))
      << "error for ec(" << grpid << ")";

    EXPECT_GE(1, oc_sec_ecdsa_count_keypairs())
      << "error for ec(" << grpid << ")";
    auto rep = pool.ParsePayload();
    EXPECT_TRUE(oc_sec_ecdsa_decode_keypair_for_device(rep.get(), device))
      << "error for ec(" << grpid << ")";

    oc_ecdsa_keypair_t *kp_out = oc_sec_ecdsa_get_keypair(device);
    EXPECT_NE(nullptr, kp_out) << "error for ec(" << grpid << ")";
    CompareKeys(kp_in, *kp_out);
  };

  decodeForDevice(0, MBEDTLS_ECP_DP_SECP256R1);

  // overwrite data
  pool.Clear();
  decodeForDevice(0, MBEDTLS_ECP_DP_SECP384R1);

  EXPECT_EQ(1, oc_sec_ecdsa_count_keypairs());
}

static std::vector<oc_ecdsa_keypair_t>
generateKeypairs(mbedtls_ecp_group_id grpid, size_t count)
{
  std::vector<oc_ecdsa_keypair_t> keypairs{};
  for (size_t i = 0; i < count; ++i) {
    oc::RepPool pool{};
    oc_ecdsa_keypair_t kp_in = oc::GetOCKeyPair(grpid);
    keypairs.push_back(kp_in);

    EXPECT_TRUE(oc_sec_ecdsa_encode_keypair(&kp_in))
      << "error for ec(" << grpid << ")";
    auto rep = pool.ParsePayload();
    EXPECT_TRUE(oc_sec_ecdsa_decode_keypair_for_device(rep.get(), /*device*/ i))
      << "error for ec(" << grpid << ")";
  }
  return keypairs;
}

TEST_F(TestKeyPair, DecodeForMultipleDevices)
{
  auto decode_keypair_for_devices = [](mbedtls_ecp_group_id grpid,
                                       size_t count) {
    OC_DBG("decode ecdsa keypair with elliptic-curve %d (for %zu devices)",
           (int)grpid, count);

    auto keypairs = generateKeypairs(grpid, count);
    EXPECT_EQ(keypairs.size(), oc_sec_ecdsa_count_keypairs());

    for (size_t i = 0; i < keypairs.size(); ++i) {
      oc_ecdsa_keypair_t *kp_out = oc_sec_ecdsa_get_keypair(/*device*/ i);
      EXPECT_NE(nullptr, kp_out) << "error for ec(" << grpid << ")";
      CompareKeys(keypairs[i], *kp_out);
    }
  };

#ifdef OC_DYNAMIC_ALLOCATION
  size_t count = 4;
#else  /* !OC_DYNAMIC_ALLOCATION */
  size_t count = OC_MAX_NUM_DEVICES;
#endif /* OC_DYNAMIC_ALLOCATION */
  for (auto ec : g_ocf_ecs) {
    decode_keypair_for_devices(ec, count);

#ifndef OC_DYNAMIC_ALLOCATION
    oc::RepPool pool{};
    EXPECT_TRUE(oc_sec_ecdsa_encode_keypair(oc_sec_ecdsa_get_keypair(0)))
      << "error for ec(" << ec << ")";
    auto rep = pool.ParsePayload();
    EXPECT_FALSE(oc_sec_ecdsa_decode_keypair_for_device(
      rep.get(), /*device*/ OC_MAX_NUM_DEVICES))
      << "error for ec(" << ec << ")";
#endif /* !OC_DYNAMIC_ALLOCATION */
  }
}

#endif /* OC_SECURITY && OC_PKI */
