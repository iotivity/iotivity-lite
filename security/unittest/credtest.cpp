/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 * Copyright (c) 2024 ETRI Joo-Chul Kevin Lee
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

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_base64.h"
#include "oc_uuid.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_event_handler_internal.h"
#include "security/oc_certs_generate_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_cred_util_internal.h"
#include "security/oc_obt_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_svr_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/PKI.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#ifdef OC_HAS_FEATURE_BRIDGE
#include "oc_bridge.h"
#endif /* OC_HAS_FEATURE_BRIDGE */

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <mbedtls/build_info.h>
#include <mbedtls/md.h>
#include <vector>

static constexpr size_t kDeviceID{ 0 };

class TestCreds : public testing::Test {
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
    oc_connectivity_shutdown(0);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }

  void TearDown() override { oc_sec_cred_clear(kDeviceID, nullptr, nullptr); }

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

#if defined(OC_PKI) && (defined(OC_DYNAMIC_ALLOCATION) || defined(OC_TEST))
  static int addRootCertificate(size_t device, const oc::keypair_t &kp,
                                bool isMfg = false)
  {
    auto pem = oc::pki::GenerateRootCertificate(kp);
    return isMfg ? oc_pki_add_mfg_trust_anchor(device, pem.data(), pem.size())
                 : oc_pki_add_trust_anchor(device, pem.data(), pem.size());
  }

  static int addIdentityCertificate(size_t device, const oc::keypair_t &kp,
                                    const oc::keypair_t &issuer_kp,
                                    bool isMfg = false)
  {
    auto pem = oc::pki::GeneratIdentityCertificate(kp, issuer_kp);
    if (pem.empty()) {
      return -1;
    }
    oc::pki::KeyParser parser{};
    auto keyPem =
      parser.GetPrivateKey(kp.private_key.data(), kp.private_key_size);
    if (keyPem.empty()) {
      return -1;
    }

    return isMfg ? oc_pki_add_mfg_cert(device, pem.data(), pem.size(),
                                       keyPem.data(), keyPem.size())
                 : oc_pki_add_identity_cert(device, pem.data(), pem.size(),
                                            keyPem.data(), keyPem.size());
  }
#endif /* OC_PKI && (OC_DYNAMIC_ALLOCATION || OC_TEST) */
};

TEST_F(TestCreds, GetCreds)
{
  // invalid deviceID
  EXPECT_EQ(nullptr, oc_sec_get_creds(42));

  // valid deviceID
  EXPECT_NE(nullptr, oc_sec_get_creds(kDeviceID));
}

TEST_F(TestCreds, CreateAndRemovePSK)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);

  std::vector<unsigned char> pin{ '1', '2', '3' };
  // 16 = SYMMETRIC_KEY_128BIT_LEN
  std::array<uint8_t, 16> key{};
  ASSERT_EQ(0, oc_tls_pbkdf2(pin.data(), pin.size(), &uuid, 100,
                             MBEDTLS_MD_SHA256, &key[0], key.size()));

  std::array<char, OC_UUID_LEN> uuid_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid, &uuid_str[0], uuid_str.size()));
  oc_sec_encoded_data_t privatedata = { key.data(), key.size(),
                                        OC_ENCODING_RAW };
  int credid = oc_sec_add_new_psk_cred(kDeviceID, uuid_str.data(), privatedata,
                                       OC_STRING_VIEW_NULL);
  ASSERT_NE(-1, credid);
  EXPECT_EQ(1, countCreds(kDeviceID));

  EXPECT_NE(nullptr, oc_sec_get_cred_by_credid(credid, kDeviceID));

  auto *cred = oc_sec_cred_remove_from_device_by_credid(credid, kDeviceID);
  ASSERT_NE(nullptr, cred);
  oc_sec_cred_free(cred);

  EXPECT_EQ(nullptr, oc_sec_get_cred_by_credid(credid, kDeviceID));
}

TEST_F(TestCreds, CreatePSK_FailInvalidRawKey)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  std::array<char, OC_UUID_LEN> uuid_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid, &uuid_str[0], uuid_str.size()));
  std::array<uint8_t, 5> key{ 'e', 'l', 'i', 't', 'e' };
  oc_sec_encoded_data_t privatedata = { key.data(), key.size(),
                                        OC_ENCODING_RAW };
  EXPECT_EQ(-1, oc_sec_add_new_psk_cred(kDeviceID, uuid_str.data(), privatedata,
                                        OC_STRING_VIEW_NULL));
}

TEST_F(TestCreds, CreateAndRemovePSKWithBase64Key)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  std::array<char, OC_UUID_LEN> uuid_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid, &uuid_str[0], uuid_str.size()));

  std::vector<unsigned char> pin{ '1', '2', '3' };
  // 32 = SYMMETRIC_KEY_256BIT_LEN
  std::array<uint8_t, 32> key{};
  ASSERT_EQ(0, oc_tls_pbkdf2(pin.data(), pin.size(), &uuid, 100,
                             MBEDTLS_MD_SHA256, &key[0], key.size()));

  std::vector<uint8_t> keyB64;
  keyB64.resize(64);
  int len = oc_base64_encode(key.data(), key.size(), &keyB64[0], keyB64.size());
  ASSERT_NE(-1, len);
  keyB64.resize(len);

  oc_sec_encoded_data_t privatedata = { keyB64.data(), keyB64.size(),
                                        OC_ENCODING_BASE64 };
  int credid = oc_sec_add_new_psk_cred(kDeviceID, uuid_str.data(), privatedata,
                                       OC_STRING_VIEW_NULL);
  ASSERT_NE(-1, credid);
  EXPECT_EQ(1, countCreds(kDeviceID));

  ASSERT_TRUE(oc_sec_remove_cred_by_credid(credid, kDeviceID));
}

TEST_F(TestCreds, CreatePSK_FailInvalidBase64Key)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  std::array<char, OC_UUID_LEN> uuid_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid, &uuid_str[0], uuid_str.size()));

  std::vector<uint8_t> notB64{ '1', '2', '3', '4', '5' };
  oc_sec_encoded_data_t privatedata = { notB64.data(), notB64.size(),
                                        OC_ENCODING_BASE64 };
  EXPECT_EQ(-1, oc_sec_add_new_psk_cred(kDeviceID, uuid_str.data(), privatedata,
                                        OC_STRING_VIEW_NULL));

  std::vector<uint8_t> tooLong(128, 'x');
  std::vector<uint8_t> keyB64;
  keyB64.resize(tooLong.size() * 2);
  int len =
    oc_base64_encode(tooLong.data(), tooLong.size(), &keyB64[0], keyB64.size());
  ASSERT_NE(-1, len);
  keyB64.resize(len);
  privatedata = { keyB64.data(), keyB64.size(), OC_ENCODING_BASE64 };
  EXPECT_EQ(-1, oc_sec_add_new_psk_cred(kDeviceID, uuid_str.data(), privatedata,
                                        OC_STRING_VIEW_NULL));

  // key length is not valid according to cred_check_symmetric_key_length
  std::vector<uint8_t> notSymmetric(5, 'x');
  keyB64.resize(notSymmetric.size() * 2);
  len = oc_base64_encode(notSymmetric.data(), notSymmetric.size(), &keyB64[0],
                         keyB64.size());
  keyB64.resize(len);
  privatedata = { keyB64.data(), keyB64.size(), OC_ENCODING_BASE64 };
  EXPECT_EQ(-1, oc_sec_add_new_psk_cred(kDeviceID, uuid_str.data(), privatedata,
                                        OC_STRING_VIEW_NULL));
}

TEST_F(TestCreds, RemoveBySubjectID)
{
  oc_uuid_t uuid1{};
  oc_gen_uuid(&uuid1);
  std::array<char, OC_UUID_LEN> uuid1_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid1, &uuid1_str[0], uuid1_str.size()));

  oc_uuid_t uuid2{};
  do {
    oc_gen_uuid(&uuid2);
  } while (oc_uuid_is_equal(uuid1, uuid2));
  std::array<char, OC_UUID_LEN> uuid2_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid2, &uuid2_str[0], uuid2_str.size()));

  oc_uuid_t uuid3{ '*' };
  std::array<char, OC_UUID_LEN> uuid3_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid3, &uuid3_str[0], uuid3_str.size()));

  std::vector<unsigned char> pin{ '1', '2', '3' };
  auto add_psk_cred = [&pin](const oc_uuid_t &uuid) {
    std::array<uint8_t, 16> key{};
    if (oc_tls_pbkdf2(pin.data(), pin.size(), &uuid, 100, MBEDTLS_MD_SHA256,
                      &key[0], key.size()) != 0) {
      return -1;
    }
    std::array<char, OC_UUID_LEN> uuid_str{};
    if (oc_uuid_to_str_v1(&uuid, &uuid_str[0], uuid_str.size()) == -1) {
      return -1;
    }
    oc_sec_encoded_data_t privatedata = { key.data(), key.size(),
                                          OC_ENCODING_RAW };
    return oc_sec_add_new_psk_cred(kDeviceID, uuid_str.data(), privatedata,
                                   OC_STRING_VIEW_NULL);
  };
  int credid1 = add_psk_cred(uuid1);
  ASSERT_NE(-1, credid1);
  int credid2 = add_psk_cred(uuid2);
  ASSERT_NE(-1, credid2);

  EXPECT_EQ(2, countCreds(kDeviceID));

  EXPECT_EQ(nullptr, oc_cred_find_by_subject(uuid3_str.data(), kDeviceID));
  EXPECT_FALSE(oc_cred_remove_by_subject(uuid3_str.data(), kDeviceID));

  EXPECT_NE(nullptr, oc_cred_find_by_subject(uuid2_str.data(), kDeviceID));
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(credid2, kDeviceID));
  EXPECT_EQ(nullptr, oc_cred_find_by_subject(uuid2_str.data(), kDeviceID));
  EXPECT_FALSE(oc_sec_remove_cred_by_credid(credid2, kDeviceID));
  EXPECT_EQ(1, countCreds(kDeviceID));

  EXPECT_NE(nullptr, oc_cred_find_by_subject(uuid1_str.data(), kDeviceID));
  EXPECT_TRUE(oc_cred_remove_by_subject(uuid1_str.data(), kDeviceID));
  EXPECT_EQ(nullptr, oc_cred_find_by_subject(uuid1_str.data(), kDeviceID));
  EXPECT_EQ(0, countCreds(kDeviceID));
}

#ifdef OC_PKI

TEST_F(TestCreds, Serialize)
{
  // root ca certificate
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int rootCredID = addRootCertificate(kDeviceID, rootKey);
  ASSERT_LT(0, rootCredID);

#ifdef OC_DYNAMIC_ALLOCATION
  // identity certificate
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int identCredID = addIdentityCertificate(kDeviceID, identKey, rootKey);
  ASSERT_LT(0, identCredID);
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_sec_creds_t *device_creds = oc_sec_get_creds(kDeviceID);
  ASSERT_NE(nullptr, device_creds);

  auto isCACertificate = [](const oc_sec_cred_t *cred, void *) {
    return cred->credusage == OC_CREDUSAGE_TRUSTCA ||
           cred->credusage == OC_CREDUSAGE_MFG_TRUSTCA;
  };

  auto caPEMSize = oc_cred_serialize(device_creds->creds, isCACertificate,
                                     nullptr, nullptr, 0);
  ASSERT_LT(0, caPEMSize);
  std::vector<char> caPEM{};
  caPEM.resize(caPEMSize);
  ASSERT_EQ(caPEMSize, oc_cred_serialize(device_creds->creds, isCACertificate,
                                         nullptr, &caPEM[0], caPEM.size()));
  caPEM.resize(caPEMSize + 1);

#ifdef OC_DYNAMIC_ALLOCATION
  auto isIdentityCertificate = [](const oc_sec_cred_t *cred, void *) {
    return cred->credusage == OC_CREDUSAGE_IDENTITY_CERT ||
           cred->credusage == OC_CREDUSAGE_MFG_CERT;
  };

  auto identPEMSize = oc_cred_serialize(
    device_creds->creds, isIdentityCertificate, nullptr, nullptr, 0);
  ASSERT_LT(0, identPEMSize);
  std::vector<char> identPEM{};
  identPEM.resize(identPEMSize + 1);
  ASSERT_EQ(identPEMSize,
            oc_cred_serialize(device_creds->creds, isIdentityCertificate,
                              nullptr, &identPEM[0], identPEM.size()));
#endif /* OC_DYNAMIC_ALLOCATION */

  // no cred matches filter
  EXPECT_EQ(0, oc_cred_serialize(
                 device_creds->creds,
                 [](const oc_sec_cred_t *, void *) { return false; }, nullptr,
                 nullptr, 0));

  // match all
  auto pemSize =
    oc_cred_serialize(device_creds->creds, nullptr, nullptr, nullptr, 0);
  ASSERT_LT(0, pemSize);
  std::vector<char> pem{};
  pem.resize(pemSize + 1);
  ASSERT_EQ(pemSize, oc_cred_serialize(device_creds->creds, nullptr, nullptr,
                                       &pem[0], pem.size()));

  std::vector<char> expPem{};
  expPem.insert(expPem.end(), caPEM.begin(), caPEM.end());
#ifdef OC_DYNAMIC_ALLOCATION
  expPem.insert(expPem.end() - 1, identPEM.begin(), identPEM.end());
#endif /* OC_DYNAMIC_ALLOCATION */
  EXPECT_STREQ(expPem.data(), pem.data());
}

TEST_F(TestCreds, Serialize_Fail)
{
  // root ca certificate
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int rootCredID = addRootCertificate(kDeviceID, rootKey);
  ASSERT_LT(0, rootCredID);

  oc_sec_creds_t *device_creds = oc_sec_get_creds(kDeviceID);
  ASSERT_NE(nullptr, device_creds);

  std::vector<char> pem{};
  pem.resize(1024);
  auto pemSize = oc_cred_serialize(device_creds->creds, nullptr, nullptr,
                                   &pem[0], pem.size());
  ASSERT_LT(0, pemSize);
  pem.resize(pemSize);

  std::vector<char> too_small{};
  too_small.resize(pemSize - 1);
  EXPECT_EQ(-1, oc_cred_serialize(device_creds->creds, nullptr, nullptr,
                                  &too_small[0], too_small.size()));
}

#endif /* OC_PKI && (OC_DYNAMIC_ALLOCATION || OC_TEST) */

#ifdef OC_HAS_FEATURE_BRIDGE
static bool
IsCredsEntryInitialized(const oc_sec_creds_t *credsEntry)
{
  /*
   * resource owner should be null
   * subject list should be empty
   */
  if ((oc_uuid_is_nil(credsEntry->rowneruuid)) &&
      !oc_list_length(credsEntry->creds)) {
    return true;
  }

  return false;
}

/*
 * oc_sec_cred_new_device(device_index, need_realloc)
 */
TEST_F(TestCreds, CredNewDevice)
{
  /*
   * overwrite entry in the existing position
   */
  auto credsEntry = oc_sec_get_creds(kDeviceID);
//  auto orgCreds = std::make_unique<oc_sec_creds_t>();
  std::unique_ptr<oc-sec_creds_t> orgCreds(new oc_sec_creds_t());

  memcpy(orgCreds.get(), credsEntry, sizeof(oc_sec_creds_t));

  oc_sec_cred_new_device(kDeviceID, false);
  EXPECT_EQ(true, IsCredsEntryInitialized(credsEntry));

  memcpy(credsEntry, orgCreds.get(), sizeof(oc_sec_creds_t));
}
#endif /* OC_HAS_FEATURE_BRIDGE */

#endif /* OC_SECURITY */
