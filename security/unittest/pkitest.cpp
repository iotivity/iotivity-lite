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

#include "api/oc_core_res_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_api.h"
#include "oc_cred.h"
#include "oc_pki.h"
#include "oc_config.h"
#include "port/oc_network_event_handler_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_cred_util_internal.h"
#include "security/oc_pki_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_svr_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/PKI.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <mbedtls/build_info.h>

#include <gtest/gtest.h>
#include <stdbool.h>
#include <string>

static constexpr size_t kDeviceID{ 0 };

class TestPKI : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
    ASSERT_EQ(0, oc_add_device(oc::DefaultDevice.uri.c_str(),
                               oc::DefaultDevice.rt.c_str(),
                               oc::DefaultDevice.name.c_str(),
                               oc::DefaultDevice.spec_version.c_str(),
                               oc::DefaultDevice.data_model_version.c_str(),
                               nullptr, nullptr));
    oc_sec_svr_create();
    oc_mbedtls_init();
  }

  static void TearDownTestCase()
  {
    oc_sec_svr_free();
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(kDeviceID);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }

  void TearDown() override { oc_sec_cred_clear(kDeviceID, nullptr, nullptr); }

#ifdef OC_DYNAMIC_ALLOCATION
  static size_t countCreds(size_t device)
  {
    const oc_sec_creds_t *device_creds = oc_sec_get_creds(device);
    if (device_creds == nullptr) {
      return 0;
    }

    size_t count = 0;
    oc_cred_iterate(
      device_creds->creds,
      [](const oc_sec_cred_t *, void *data) {
        ++(*static_cast<size_t *>(data));
        return true;
      },
      &count);
    return count;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
};

TEST_F(TestPKI, AddIdentityCertificate_FailInvalidInput)
{
  EXPECT_EQ(-1, oc_pki_add_identity_cert(kDeviceID, nullptr, 0, nullptr, 0));
}

TEST_F(TestPKI, AddTrustAnchor_FailInvalidInput)
{
  EXPECT_EQ(-1, oc_pki_add_trust_anchor(kDeviceID, nullptr, 0));
}

#ifdef OC_DYNAMIC_ALLOCATION

TEST_F(TestPKI, AddIdentityCertificate)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };

  auto pem = oc::pki::GeneratIdentityCertificate(rootKey, identKey);
  ASSERT_FALSE(pem.empty());
  oc::pki::KeyParser parser{};
  auto keyPem =
    parser.GetPrivateKey(rootKey.private_key.data(), rootKey.private_key_size);
  ASSERT_FALSE(keyPem.empty());
  EXPECT_NE(-1, oc_pki_add_identity_cert(kDeviceID, pem.data(), pem.size(),
                                         keyPem.data(), keyPem.size()));

  auto pem2 = oc::pki::GeneratIdentityCertificate(rootKey, identKey);
  ASSERT_FALSE(pem2.empty());
  // send size without nul-terminator for pem2 and keyPem
  EXPECT_NE(-1,
            oc_pki_add_identity_cert(kDeviceID, pem2.data(), pem2.size() - 1,
                                     keyPem.data(), keyPem.size() - 1));

  auto pem3 = oc::pki::GeneratIdentityCertificate(rootKey, identKey);
  ASSERT_FALSE(pem3.empty());
  // use DER format for key
  EXPECT_NE(-1, oc_pki_add_identity_cert(
                  kDeviceID, pem3.data(), pem3.size() - 1,
                  rootKey.private_key.data(), rootKey.private_key_size));
}

TEST_F(TestPKI, AddIdentityCertificate_FailInvalidDevice)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };

  auto pem = oc::pki::GeneratIdentityCertificate(rootKey, identKey);
  EXPECT_EQ(-1, oc_pki_add_identity_cert(/*device*/ 42, pem.data(), pem.size(),
                                         rootKey.private_key.data(),
                                         rootKey.private_key_size));
}

TEST_F(TestPKI, AddIdentityCertificate_Duplicate)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };

  auto pem = oc::pki::GeneratIdentityCertificate(rootKey, identKey);
  int credid = oc_pki_add_identity_cert(kDeviceID, pem.data(), pem.size(),
                                        rootKey.private_key.data(),
                                        rootKey.private_key_size);
  EXPECT_NE(-1, credid);
  ASSERT_EQ(1, TestPKI::countCreds(kDeviceID));

  EXPECT_EQ(credid, oc_pki_add_identity_cert(kDeviceID, pem.data(), pem.size(),
                                             rootKey.private_key.data(),
                                             rootKey.private_key_size));
  EXPECT_EQ(1, TestPKI::countCreds(kDeviceID));
}

TEST_F(TestPKI, AddIdentityCertificate_FailCorruptedKey)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };

  auto pem = oc::pki::GeneratIdentityCertificate(rootKey, identKey);
  ASSERT_FALSE(pem.empty());
  oc::pki::KeyParser parser{};
  auto keyPem =
    parser.GetPrivateKey(rootKey.private_key.data(), rootKey.private_key_size);
  ASSERT_FALSE(keyPem.empty());
  constexpr std::string_view label{ "-----BEGIN EC PRIVATE KEY-----" };
  keyPem.insert(keyPem.begin() + label.length(),
                { 'l', 'e', 'e', 't', '4', '2' });
  ASSERT_TRUE(oc_certs_is_PEM(keyPem.data(), keyPem.size()));

  EXPECT_EQ(-1, oc_pki_add_identity_cert(kDeviceID, pem.data(), pem.size(),
                                         keyPem.data(), keyPem.size()));
}

TEST_F(TestPKI, AddIdentityCertificate_FailCorruptedCertifiate)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };

  auto pem = oc::pki::GeneratIdentityCertificate(rootKey, identKey);
  ASSERT_FALSE(pem.empty());
  constexpr std::string_view label{ "-----BEGIN CERTIFICATE-----" };
  pem.insert(pem.begin() + label.length(), { 'l', 'e', 'e', 't', '4', '2' });
  ASSERT_TRUE(oc_certs_is_PEM(pem.data(), pem.size()));

  EXPECT_EQ(-1, oc_pki_add_identity_cert(kDeviceID, pem.data(), pem.size(),
                                         rootKey.private_key.data(),
                                         rootKey.private_key_size));
}

TEST_F(TestPKI, AddTrustAnchor)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  auto pem = oc::pki::GenerateRootCertificate(rootKey);
  ASSERT_FALSE(pem.empty());
  EXPECT_NE(-1, oc_pki_add_trust_anchor(kDeviceID, pem.data(), pem.size()));

  auto pem2 = oc::pki::GenerateRootCertificate(rootKey);
  ASSERT_FALSE(pem2.empty());
  // send size without nul-terminator for pem2
  EXPECT_NE(-1,
            oc_pki_add_trust_anchor(kDeviceID, pem2.data(), pem2.size() - 1));
}

TEST_F(TestPKI, AddTrustAnchor_FailInvalidDevice)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  auto pem = oc::pki::GenerateRootCertificate(rootKey);
  ASSERT_FALSE(pem.empty());

  EXPECT_EQ(-1, oc_pki_add_trust_anchor(/*device*/ 42, pem.data(), pem.size()));
}

// the same certificate should not be added to the same device twice
TEST_F(TestPKI, AddTrustAnchor_Duplicate)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  auto pem = oc::pki::GenerateRootCertificate(rootKey);
  ASSERT_FALSE(pem.empty());
  int credid = oc_pki_add_trust_anchor(kDeviceID, pem.data(), pem.size());
  EXPECT_NE(-1, credid);
  ASSERT_EQ(1, TestPKI::countCreds(kDeviceID));

  EXPECT_EQ(credid, oc_pki_add_trust_anchor(kDeviceID, pem.data(), pem.size()));
  EXPECT_EQ(1, TestPKI::countCreds(kDeviceID));
}

TEST_F(TestPKI, AddTrustAnchor_FailCorruptedCertifiate)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  auto pem = oc::pki::GenerateRootCertificate(rootKey);
  ASSERT_FALSE(pem.empty());
  constexpr std::string_view label{ "-----BEGIN CERTIFICATE-----" };
  pem.insert(pem.begin() + label.length(), { 'l', 'e', 'e', 't', '4', '2' });
  ASSERT_TRUE(oc_certs_is_PEM(pem.data(), pem.size()));

  EXPECT_EQ(-1, oc_pki_add_trust_anchor(kDeviceID, pem.data(), pem.size()));
}

#endif /* OC_DYNAMIC_ALLOCATION */

class TestPKIPK : public testing::Test {
public:
  void SetUp() override { oc::pki::PKDummyFunctions::Clear(); }

  void TearDown() override { oc_pki_set_pk_functions(nullptr); }
};

TEST_F(TestPKIPK, pk_functions)
{
  using namespace oc::pki;

  EXPECT_TRUE(oc_pki_set_pk_functions(nullptr));
  EXPECT_FALSE(oc_pki_get_pk_functions(nullptr));
  oc_pki_pk_functions_t pk_functions = PKDummyFunctions::GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  EXPECT_TRUE(oc_pki_get_pk_functions(nullptr));
  pk_functions.mbedtls_pk_parse_key = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));
  pk_functions.mbedtls_pk_parse_key = PKDummyFunctions::ParseKey;
  pk_functions.mbedtls_pk_write_key_der = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));
  pk_functions.mbedtls_pk_write_key_der = PKDummyFunctions::WriteKeyDer;
  pk_functions.mbedtls_pk_ecp_gen_key = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));
  pk_functions.mbedtls_pk_ecp_gen_key = PKDummyFunctions::GenKey;
  pk_functions.pk_free_key = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));

  oc_pki_pk_functions_t get_pk_functions{};
  EXPECT_TRUE(oc_pki_get_pk_functions(&get_pk_functions));
  EXPECT_EQ(get_pk_functions.mbedtls_pk_parse_key, &PKDummyFunctions::ParseKey);
  EXPECT_EQ(get_pk_functions.mbedtls_pk_write_key_der,
            &PKDummyFunctions::WriteKeyDer);
  EXPECT_EQ(get_pk_functions.mbedtls_pk_ecp_gen_key, &PKDummyFunctions::GenKey);
  EXPECT_EQ(get_pk_functions.pk_free_key, &PKDummyFunctions::FreeKey);
}

TEST_F(TestPKIPK, pk_free_key)
{
  oc_pki_pk_functions_t pk_functions =
    oc::pki::PKDummyFunctions::GetPKFunctions();
  EXPECT_FALSE(oc_pk_free_key(0, nullptr, 0));
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  EXPECT_TRUE(oc_pk_free_key(0, nullptr, 0));
  EXPECT_TRUE(oc::pki::PKDummyFunctions::freeKeyInvoked);
}

TEST_F(TestPKIPK, pk_gen_key)
{
  oc_pki_pk_functions_t pk_functions =
    oc::pki::PKDummyFunctions::GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  oc_mbedtls_pk_ecp_gen_key(0, MBEDTLS_ECP_DP_SECP256R1, nullptr, nullptr,
                            nullptr);
  EXPECT_TRUE(oc::pki::PKDummyFunctions::genKeyInvoked);
}

TEST_F(TestPKIPK, pk_write_key_der)
{
  oc_pki_pk_functions_t pk_functions =
    oc::pki::PKDummyFunctions::GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  oc_mbedtls_pk_write_key_der(0, nullptr, nullptr, 0);
  EXPECT_TRUE(oc::pki::PKDummyFunctions::writeKeyDerInvoked);
}

TEST_F(TestPKIPK, pk_parse_key)
{
  oc_pki_pk_functions_t pk_functions =
    oc::pki::PKDummyFunctions::GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  oc_mbedtls_pk_parse_key(0, nullptr, nullptr, 0, nullptr, 0, nullptr, nullptr);
  EXPECT_TRUE(oc::pki::PKDummyFunctions::parseKeyInvoked);
}

#endif /* OC_SECURITY && OC_PKI */