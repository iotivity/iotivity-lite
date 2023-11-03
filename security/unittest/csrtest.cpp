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
#include "oc_core_res.h"
#include "oc_csr.h"
#include "port/oc_log_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_csr_internal.h"
#include "security/oc_keypair_internal.h"
#include "security/oc_obt_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/Resource.h"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <mbedtls/x509_crt.h>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID = 0;

class TestCSRWithDevice : public testing::Test {
public:
  static void SetUpTestCase()
  {
    for (int i = 1; i < MBEDTLS_ECP_DP_MAX; ++i) {
      if ((MBEDTLS_X509_ID_FLAG(i) & OCF_CERTS_SUPPORTED_ELLIPTIC_CURVES) !=
          0) {
        auto ec = static_cast<mbedtls_ecp_group_id>(i);
        g_ocf_ecs.push_back(ec);
      }
    }
  }

  void SetUp() override { EXPECT_TRUE(oc::TestDevice::StartServer()); }

  void TearDown() override
  {
    oc::TestDevice::StopServer();
    oc_sec_certs_default();
  }

  static std::vector<mbedtls_ecp_group_id> g_ocf_ecs;
};

std::vector<mbedtls_ecp_group_id> TestCSRWithDevice::g_ocf_ecs{};

TEST_F(TestCSRWithDevice, GenerateError)
{
  std::array<unsigned char, 1> too_small{};
  EXPECT_GT(0, oc_sec_csr_generate(/*device*/ -1, MBEDTLS_MD_SHA256,
                                   too_small.data(), too_small.size()))
    << "invalid device";

  EXPECT_GT(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA256,
                                   too_small.data(), too_small.size()))
    << "buffer too small";

  std::array<unsigned char, 512> csr{};
  EXPECT_GT(
    0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_NONE, csr.data(), csr.size()))
    << "invalid message digest type";
}

TEST_F(TestCSRWithDevice, GenerateMDs)
{
  std::array<unsigned char, 512> csr{};
  EXPECT_GT(
    0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_MD5, csr.data(), csr.size()))
    << "md5 enabled";
  EXPECT_GT(
    0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA1, csr.data(), csr.size()))
    << "sha1 enabled";
  EXPECT_GT(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_RIPEMD160, csr.data(),
                                   csr.size()))
    << "ripemd-160 enabled";

  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA224, csr.data(),
                                   csr.size()))
    << "sha224 disabled";
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA256, csr.data(),
                                   csr.size()))
    << "sha256 disabled";
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA384, csr.data(),
                                   csr.size()))
    << "sha384 disabled";
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA512, csr.data(),
                                   csr.size()))
    << "sha512 disabled";
}

TEST_F(TestCSRWithDevice, ValidateFail)
{
  std::array<unsigned char, 512> csr_pem{};
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA224, csr_pem.data(),
                                   csr_pem.size()));

  mbedtls_x509_csr csr;
  EXPECT_EQ(0, mbedtls_x509_csr_parse(&csr, csr_pem.data(), csr_pem.size()));

  EXPECT_FALSE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY,
                                   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
                                     MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384)))
    << "sha224 signature not supported";

  mbedtls_x509_csr_free(&csr);
}

TEST_F(TestCSRWithDevice, ValidateSkipSignature)
{
  std::array<unsigned char, 512> csr_pem{};
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA224, csr_pem.data(),
                                   csr_pem.size()));

  mbedtls_x509_csr csr;
  EXPECT_EQ(0, mbedtls_x509_csr_parse(&csr, csr_pem.data(), csr_pem.size()));
  EXPECT_TRUE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY, 0));

  mbedtls_x509_csr_free(&csr);
}

TEST_F(TestCSRWithDevice, Validate256)
{
  std::array<unsigned char, 512> csr_pem{};
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA256, csr_pem.data(),
                                   csr_pem.size()));

  mbedtls_x509_csr csr;
  EXPECT_EQ(0, mbedtls_x509_csr_parse(&csr, csr_pem.data(), csr_pem.size()));

  EXPECT_FALSE(oc_sec_csr_validate(&csr, MBEDTLS_PK_OPAQUE,
                                   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256)))
    << "unexpected public key type";

  EXPECT_FALSE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY,
                                   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384)))
    << "wrong signature type";

  EXPECT_TRUE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY,
                                  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256)));

  std::array<char, 1> too_small_sub{};
  EXPECT_GT(0, oc_sec_csr_extract_subject_DN(&csr, too_small_sub.data(),
                                             too_small_sub.size()))
    << "buffer too small";

  std::array<char, 128> sub{};
  EXPECT_LT(0, oc_sec_csr_extract_subject_DN(&csr, sub.data(), sub.size()))
    << "cannot extract subject";
  OC_DBG("Subject: %s", sub.data());

  mbedtls_x509_csr_free(&csr);
}

static mbedtls_x509_csr
generateValidCSR(mbedtls_md_type_t md, mbedtls_ecp_group_id grpid,
                 size_t device)
{
  oc_sec_ecdsa_update_or_generate_keypair_for_device(grpid, device);
  std::array<unsigned char, 1024> csr_pem{};
  EXPECT_EQ(0, oc_sec_csr_generate(device, md, csr_pem.data(), csr_pem.size()));

  mbedtls_x509_csr csr;
  EXPECT_EQ(0, mbedtls_x509_csr_parse(&csr, csr_pem.data(), csr_pem.size()));

  EXPECT_TRUE(
    oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY, MBEDTLS_X509_ID_FLAG(md)));
  return csr;
}

TEST_F(TestCSRWithDevice, Valid256ExtractPublicKey)
{
  auto generate_and_extract_pk = [](mbedtls_ecp_group_id grpid, size_t device) {
    OC_DBG("generate sha256 CSR with elliptic-curve %d for device %zu",
           (int)grpid, device);
    mbedtls_x509_csr csr = generateValidCSR(MBEDTLS_MD_SHA256, grpid, device);

    std::array<uint8_t, 1> too_small_pk{};
    EXPECT_GT(0, oc_sec_csr_extract_public_key(&csr, too_small_pk.data(),
                                               too_small_pk.size()))
      << "buffer too small";

    std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> pk{};
    int ret = oc_sec_csr_extract_public_key(&csr, pk.data(), pk.size());
    EXPECT_LT(0, ret) << "buffer too small";
    OC_DBG("Public key size: %d", ret);

    mbedtls_x509_csr_free(&csr);
  };

  for (auto ec : g_ocf_ecs) {
    generate_and_extract_pk(ec, 0);
  }
}

TEST_F(TestCSRWithDevice, Validate384)
{
  std::array<unsigned char, 512> csr_pem{};
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA384, csr_pem.data(),
                                   csr_pem.size()));

  mbedtls_x509_csr csr;
  EXPECT_EQ(0, mbedtls_x509_csr_parse(&csr, csr_pem.data(), csr_pem.size()));

  EXPECT_FALSE(oc_sec_csr_validate(&csr, MBEDTLS_PK_RSASSA_PSS,
                                   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384)))
    << "unexpected public key type";

  EXPECT_FALSE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY,
                                   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256)))
    << "wrong signature type";

  EXPECT_TRUE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY,
                                  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384)));

  std::array<char, 1> too_small_sub{};
  EXPECT_GT(0, oc_sec_csr_extract_subject_DN(&csr, too_small_sub.data(),
                                             too_small_sub.size()))
    << "buffer too small";

  std::array<char, 128> sub{};
  EXPECT_LT(0, oc_sec_csr_extract_subject_DN(&csr, sub.data(), sub.size()))
    << "cannot extract subject";
  OC_DBG("Subject: %s", sub.data());

  mbedtls_x509_csr_free(&csr);
}

TEST_F(TestCSRWithDevice, Valid384ExtractPublicKey)
{
  auto generate_and_extract_pk = [](mbedtls_ecp_group_id grpid, size_t device) {
    OC_DBG("generate sha256 CSR with elliptic-curve %d for device %zu",
           (int)grpid, device);
    mbedtls_x509_csr csr = generateValidCSR(MBEDTLS_MD_SHA384, grpid, device);

    std::array<uint8_t, 1> too_small_pk{};
    EXPECT_GT(0, oc_sec_csr_extract_public_key(&csr, too_small_pk.data(),
                                               too_small_pk.size()))
      << "buffer too small";

    std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> pk{};
    int ret = oc_sec_csr_extract_public_key(&csr, pk.data(), pk.size());
    EXPECT_LT(0, ret) << "buffer too small";
    OC_DBG("Public key size: %d", ret);

    mbedtls_x509_csr_free(&csr);
  };

  for (auto ec : g_ocf_ecs) {
    generate_and_extract_pk(ec, 0);
  }
}

TEST_F(TestCSRWithDevice, RegenerateDeviceKeypair)
{
  oc_sec_ecdsa_free_keypairs();
  ASSERT_EQ(0, oc_sec_ecdsa_count_keypairs());

  std::array<unsigned char, 512> csr{};
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA256, csr.data(),
                                   csr.size()));

  ASSERT_LT(0, oc_sec_ecdsa_count_keypairs());
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

TEST_F(TestCSRWithDevice, GetResourceBaseline)
{
  // biggest supported hash and elliptic curve to get the largest CSR payload
  oc_sec_certs_md_set_signature_algorithm(MBEDTLS_MD_SHA384);
  oc_sec_certs_ecp_set_group_id(MBEDTLS_ECP_DP_SECP384R1);

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  ASSERT_TRUE(
    oc::SetAccessInRFOTM(OCF_SEC_CSR, kDeviceID, true, OC_PERM_RETRIEVE));

  auto csr_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
    *static_cast<bool *>(data->user_data) = true;
  };

  auto timeout = 1s;
  bool invoked = false;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_SEC_CSR_URI, &ep, "if=oic.if.baseline",
                                     timeout.count(), csr_handler, HIGH_QOS,
                                     &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(invoked);
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

class TestCSRWithDeviceTPM : public TestCSRWithDevice {
public:
  void SetUp() override
  {
    TestCSRWithDevice::SetUp();
    static oc_pki_pk_functions_t pk_functions{
      /*mbedtls_pk_parse_key=*/TestCSRWithDeviceTPM::
        simulate_tpm_mbedtls_pk_parse_key,
      /*mbedtls_pk_write_key_der*/
      TestCSRWithDeviceTPM::simulate_tpm_mbedtls_pk_write_key_der,
      /*mbedtls_pk_ecp_gen_key=*/
      TestCSRWithDeviceTPM::simulate_tpm_mbedtls_pk_ecp_gen_key,
      /*pk_free_key=*/nullptr,
    };
    oc_pki_set_pk_functions(&pk_functions);
    clear_keypair();
  }

  void TearDown() override
  {
    oc_pki_set_pk_functions(nullptr);
    clear_keypair();
    TestCSRWithDevice::TearDown();
  }

protected:
  static oc::keypair_t g_key_pair;

  static void clear_keypair()
  {
    memset(&g_key_pair.public_key[0], 0, g_key_pair.public_key.size());
    g_key_pair.public_key_size = 0;
    memset(&g_key_pair.private_key[0], 0, g_key_pair.private_key.size());
    g_key_pair.private_key_size = 0;
  }

  static int simulate_tpm_mbedtls_pk_parse_key(
    size_t /*device*/, mbedtls_pk_context *pk, const unsigned char *key,
    size_t keylen, const unsigned char *pwd, size_t pwdlen,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
  {
    if (keylen == g_key_pair.public_key_size &&
        memcmp(key, &g_key_pair.public_key[0], g_key_pair.public_key_size) ==
          0) {
      return mbedtls_pk_parse_key(pk, &g_key_pair.private_key[0],
                                  g_key_pair.private_key_size, pwd, pwdlen,
                                  f_rng, p_rng);
    }
    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
  }

  static int simulate_tpm_mbedtls_pk_write_key_der(size_t /*device*/,
                                                   const mbedtls_pk_context *pk,
                                                   unsigned char *buf,
                                                   size_t size)
  {
    std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> pub_key;
    int ret = mbedtls_pk_write_pubkey_der(pk, &pub_key[0], sizeof(pub_key));
    if (ret > 0) {
      memmove(&pub_key[0], &pub_key[0] + pub_key.size() - ret, ret);
    } else {
      return ret;
    }
    if (((size_t)ret) != g_key_pair.public_key_size) {
      return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    if (memcmp(&pub_key[0], &g_key_pair.public_key[0], ret) != 0) {
      return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    if (size < (size_t)ret) {
      return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }
    memcpy(buf + size - ret, &pub_key[0], ret);
    return ret;
  }

  static int simulate_tpm_mbedtls_pk_ecp_gen_key(
    size_t device, mbedtls_ecp_group_id grp_id, mbedtls_pk_context *pk,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
  {
    (void)device;
    int ret = mbedtls_ecp_gen_key(grp_id, (mbedtls_ecp_keypair *)pk->pk_ctx,
                                  f_rng, p_rng);
    if (ret == 0) {
      ret = mbedtls_pk_write_pubkey_der(pk, &g_key_pair.public_key[0],
                                        g_key_pair.public_key.size());
      if (ret > 0) {
        memmove(&g_key_pair.public_key[0],
                &g_key_pair.public_key[0] + g_key_pair.public_key.size() - ret,
                ret);
        g_key_pair.public_key_size = ret;
        ret = 0;
      }
    }
    if (ret == 0) {
      ret = mbedtls_pk_write_key_der(pk, &g_key_pair.private_key[0],
                                     g_key_pair.private_key.size());
      if (ret > 0) {
        memmove(&g_key_pair.private_key[0],
                &g_key_pair.private_key[0] + g_key_pair.private_key.size() -
                  ret,
                ret);
        g_key_pair.private_key_size = ret;
        ret = 0;
      }
    }
    return ret;
  }
};

oc::keypair_t TestCSRWithDeviceTPM::g_key_pair{};

TEST_F(TestCSRWithDeviceTPM, Validate256SimulateTPM)
{
  std::array<unsigned char, 512> csr_pem{};
  EXPECT_EQ(0, oc_sec_csr_generate(kDeviceID, MBEDTLS_MD_SHA256, csr_pem.data(),
                                   csr_pem.size()));

  mbedtls_x509_csr csr;
  EXPECT_EQ(0, mbedtls_x509_csr_parse(&csr, csr_pem.data(), csr_pem.size()));

  EXPECT_FALSE(oc_sec_csr_validate(&csr, MBEDTLS_PK_OPAQUE,
                                   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256)))
    << "unexpected public key type";

  EXPECT_FALSE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY,
                                   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384)))
    << "wrong signature type";

  EXPECT_TRUE(oc_sec_csr_validate(&csr, MBEDTLS_PK_ECKEY,
                                  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256)));

  std::array<char, 1> too_small_sub{};
  EXPECT_GT(0, oc_sec_csr_extract_subject_DN(&csr, too_small_sub.data(),
                                             too_small_sub.size()))
    << "buffer too small";

  std::array<char, 128> sub{};
  EXPECT_LT(0, oc_sec_csr_extract_subject_DN(&csr, sub.data(), sub.size()))
    << "cannot extract subject";
  OC_DBG("Subject: %s", sub.data());

  mbedtls_x509_csr_free(&csr);
}

#endif /* OC_SECURITY && OC_PKI */
