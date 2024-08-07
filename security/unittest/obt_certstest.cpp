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

#if defined(OC_SECURITY) && defined(OC_PKI) && defined(OC_DYNAMIC_ALLOCATION)

#include "oc_certs.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "security/oc_certs_internal.h"
#include "security/oc_certs_validate_internal.h"
#include "security/oc_obt_internal.h"
#include "security/oc_security_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/PKI.h"
#include "tests/gtest/Role.h"

#include "gtest/gtest.h"
#include "mbedtls/x509.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

class TestObtCerts : public testing::Test {
public:
  static void SetUpTestCase()
  {
    // allow all ocf-supported MDs and ECs
    oc_sec_certs_md_set_algorithms_allowed(OCF_CERTS_SUPPORTED_MDS);
    oc_sec_certs_ecp_set_group_ids_allowed(OCF_CERTS_SUPPORTED_ELLIPTIC_CURVES);
  }

  static void TearDownTestCase()
  {
    // restore defaults
    oc_sec_certs_md_set_algorithms_allowed(
      MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256));
    oc_sec_certs_ecp_set_group_ids_allowed(
      MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1));
  }

  void SetUp() override
  {
    oc_mbedtls_init();
    oc_random_init();

    oc_uuid_t uuid{};
    oc_gen_uuid(&uuid);
    std::array<char, 50> buf;
    EXPECT_TRUE(oc_certs_encode_CN_with_UUID(&uuid, buf.data(), buf.size()));
    uuid_ = buf.data();

    kp256_ = oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1);
    kp384_ = oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP384R1);

    roles_.Add("user", "admin");
  }

  void TearDown() override { oc_random_destroy(); }

  template<class Container>
  static std::string stripNewLines(Container &container)
  {
    container.erase(
      std::remove_if(container.begin(), container.end(),
                     [](char ch) { return (ch == '\n' || ch == '\r'); }),
      container.end());

    return std::string(container.begin(), container.end());
  }

  std::string uuid_{};
  oc::keypair_t kp256_{};
  oc::keypair_t kp384_{};
  oc::Roles roles_{};
};

static const std::string g_root_subject_name{ "IoTivity-Lite Test" };
static const std::string g_root_subject{ "C=US, O=OCF, CN=" +
                                         g_root_subject_name };

TEST_F(TestObtCerts, GenerateSelfSignedRootCertificateFail)
{
  oc_obt_generate_root_cert_data_t cert_data = {
    /*.subject_name = */ g_root_subject.c_str(),
    /*.public_key =*/kp256_.public_key.data(),
    /*.public_key_size =*/kp256_.public_key_size,
    /*.private_key =*/kp256_.private_key.data(),
    /*.private_key_size =*/kp256_.private_key_size,
    /*.signature_md_alg=*/MBEDTLS_MD_SHA256,
  };

  // bad buffer
  std::array<unsigned char, 1> too_small{};
  int err = oc_obt_generate_self_signed_root_cert_pem(
    cert_data, too_small.data(), too_small.size());
  EXPECT_GT(0, err);

  std::array<unsigned char, 4096> pem;
  // bad subject
  oc_obt_generate_root_cert_data_t bad_data{ cert_data };
  std::string bad_subject =
    "A=" + std::string(MBEDTLS_X509_MAX_DN_NAME_SIZE + 1, 'a');
  bad_data.subject_name = bad_subject.c_str();
  err =
    oc_obt_generate_self_signed_root_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad public key
  std::array<uint8_t, 1> bad_key{ '\0' };
  bad_data = cert_data;
  bad_data.public_key = bad_key.data();
  bad_data.public_key_size = 1;
  err =
    oc_obt_generate_self_signed_root_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad private key
  bad_data = cert_data;
  bad_data.private_key = bad_key.data();
  bad_data.private_key_size = 1;
  err =
    oc_obt_generate_self_signed_root_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);
}

TEST_F(TestObtCerts, GenerateValidSelfSignedCertificate)
{
  auto cert_buf = oc::pki::obt::GenerateSelfSignedRootCertificate(
    g_root_subject, kp256_, MBEDTLS_MD_SHA384);

  std::array<char, 128> serial{};
  int ret = oc_certs_parse_serial_number(&cert_buf[0], cert_buf.size(),
                                         serial.data(), serial.size());
  EXPECT_LT(0, ret);
  OC_DBG("serial: %s", &serial[0]);

  std::array<uint8_t, 200> private_key{};
  ret = oc_certs_parse_private_key(0, &cert_buf[0], cert_buf.size(),
                                   private_key.data(), private_key.size());
  EXPECT_EQ(kp256_.private_key_size, ret);

  oc_string_t pk{};
  ret =
    oc_certs_parse_public_key_to_oc_string(&cert_buf[0], cert_buf.size(), &pk);
  EXPECT_LT(0, ret);
  EXPECT_EQ(0, memcmp(kp256_.public_key.data(), oc_cast(pk, uint8_t), ret));
  oc_free_string(&pk);
}

#ifdef OC_TEST

TEST_F(TestObtCerts, SerializeSelfSignedCertificate)
{
  auto root_cert = oc::pki::obt::GenerateSelfSignedRootCertificate(
    g_root_subject, kp384_, MBEDTLS_MD_SHA384);
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  EXPECT_EQ(0, mbedtls_x509_crt_parse(&crt, &root_cert[0], root_cert.size()));

  std::vector<char> pem{};
  pem.resize(4096, '\0');
  int ret = oc_certs_serialize_chain_to_pem(&crt, pem.data(), pem.size());
  EXPECT_LT(0, ret);
  pem.resize(ret + 1); // +1 for nul-terminator

  EXPECT_STREQ(stripNewLines(root_cert).c_str(), stripNewLines(pem).c_str());

  mbedtls_x509_crt_free(&crt);
}

#endif /* OC_TEST */

TEST_F(TestObtCerts, ValidateSelfSignedCertificate)
{
  auto root_cert =
    oc::pki::obt::GenerateSelfSignedRootCertificate(g_root_subject, kp384_);
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  EXPECT_EQ(0, mbedtls_x509_crt_parse(&crt, &root_cert[0], root_cert.size()));
  // root == non end entity should succeed, others should fail
  uint32_t flags{};
  EXPECT_EQ(0, oc_certs_validate_non_end_entity_cert(&crt, true, true,
                                                     /*depth*/ 0, &flags));
  EXPECT_EQ(0, flags);
  EXPECT_NE(0, oc_certs_validate_end_entity_cert(&crt, &flags));
  EXPECT_NE(0, oc_certs_validate_role_cert(&crt, &flags));

  mbedtls_x509_crt_free(&crt);
}

TEST_F(TestObtCerts, GenerateIdentityCertificateFail)
{
  oc_obt_generate_identity_cert_data_t cert_data = {
    /*.subject_name =*/uuid_.c_str(),
    /*.public_key =*/kp256_.public_key.data(),
    /*.public_key_size =*/kp256_.public_key_size,
    /*.issuer_name =*/g_root_subject.c_str(),
    /*.issuer_private_key =*/kp256_.private_key.data(),
    /*.issuer_private_key_size =*/kp256_.private_key_size,
    /*.signature_md_alg=*/MBEDTLS_MD_SHA256,
  };

  // bad buffer
  std::array<unsigned char, 1> too_small{};
  int err = oc_obt_generate_identity_cert_pem(cert_data, too_small.data(),
                                              too_small.size());
  EXPECT_GT(0, err);

  std::array<unsigned char, 4096> pem;
  // bad subject
  oc_obt_generate_identity_cert_data_t bad_data{ cert_data };
  std::string bad_subject =
    "A=" + std::string(MBEDTLS_X509_MAX_DN_NAME_SIZE + 1, 'a');
  bad_data.subject_name = bad_subject.c_str();
  err = oc_obt_generate_identity_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad public key
  std::array<uint8_t, 1> bad_key{ '\0' };
  bad_data = cert_data;
  bad_data.public_key = bad_key.data();
  bad_data.public_key_size = 1;
  err = oc_obt_generate_identity_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad issuer
  std::string bad_issuer =
    "A=" + std::string(MBEDTLS_X509_MAX_DN_NAME_SIZE + 1, 'b');
  bad_data = cert_data;
  bad_data.issuer_name = bad_issuer.c_str();
  err = oc_obt_generate_identity_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad private key
  bad_data = cert_data;
  bad_data.issuer_private_key = bad_key.data();
  bad_data.issuer_private_key_size = 1;
  err = oc_obt_generate_identity_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);
}

TEST_F(TestObtCerts, GenerateValidIdentityCertificate)
{
  auto id_cert = oc::pki::obt::GenerateIdentityCertificate(
    uuid_, g_root_subject, kp256_, MBEDTLS_MD_SHA384);

  std::array<char, 128> serial{};
  int ret = oc_certs_parse_serial_number(&id_cert[0], id_cert.size(),
                                         serial.data(), serial.size());
  EXPECT_LT(0, ret);
  OC_DBG("serial: %s", &serial[0]);

  std::array<char, OC_UUID_LEN> uuid_cstr{};
  EXPECT_TRUE(oc_certs_parse_CN_for_UUID(&id_cert[0], id_cert.size(),
                                         uuid_cstr.data(), uuid_cstr.size()));
#ifdef _WIN32
  // linker error when ASAN is enabled
  EXPECT_NE(-1, uuid_.find(uuid_cstr.data(), 0));
#else
  EXPECT_NE(std::string::npos, uuid_.find(uuid_cstr.data(), 0));
#endif

  std::array<uint8_t, 200> private_key{};
  ret = oc_certs_parse_private_key(0, &id_cert[0], id_cert.size(),
                                   private_key.data(), private_key.size());
  EXPECT_EQ(kp256_.private_key_size, ret);

  std::array<uint8_t, 200> public_key{};
  ret = oc_certs_parse_public_key(&id_cert[0], id_cert.size(),
                                  public_key.data(), public_key.size());
  EXPECT_LT(0, ret);
  EXPECT_EQ(0, memcmp(kp256_.public_key.data(), public_key.data(), ret));
}

#ifdef OC_TEST

TEST_F(TestObtCerts, SerializeIdentityCertificate)
{
  auto id_cert =
    oc::pki::obt::GenerateIdentityCertificate(uuid_, g_root_subject, kp384_);
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  EXPECT_EQ(0, mbedtls_x509_crt_parse(&crt, &id_cert[0], id_cert.size()));

  std::vector<char> pem{};
  pem.resize(4096, '\0');
  int ret = oc_certs_serialize_chain_to_pem(&crt, pem.data(), pem.size());
  EXPECT_LT(0, ret);
  pem.resize(ret + 1); // +1 for nul-terminator

  EXPECT_STREQ(stripNewLines(id_cert).c_str(), stripNewLines(pem).c_str());

  mbedtls_x509_crt_free(&crt);
}

#endif /* OC_TEST */

TEST_F(TestObtCerts, ValidateIdentityCertificate)
{
  auto cert_buf = oc::pki::obt::GenerateIdentityCertificate(
    uuid_, g_root_subject, kp384_, MBEDTLS_MD_SHA384);

  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  EXPECT_EQ(0, mbedtls_x509_crt_parse(&crt, &cert_buf[0], cert_buf.size()));
  // identity == end entity test should succeed, others should fail
  uint32_t flags{};
  EXPECT_EQ(0, oc_certs_validate_end_entity_cert(&crt, &flags));
  EXPECT_EQ(0, flags);
  EXPECT_NE(0, oc_certs_validate_non_end_entity_cert(&crt, true, true,
                                                     /*depth*/ 0, &flags));
  EXPECT_NE(0, oc_certs_validate_role_cert(&crt, &flags));

  mbedtls_x509_crt_free(&crt);
}

TEST_F(TestObtCerts, GenerateRoleCertificateFail)
{
  oc_obt_generate_role_cert_data_t cert_data = {
    /*.roles =*/roles_.Head(),
    /*.subject_name =*/uuid_.c_str(),
    /*.public_key =*/kp256_.public_key.data(),
    /*.public_key_size =*/kp256_.public_key_size,
    /*.issuer_name =*/g_root_subject.c_str(),
    /*.issuer_private_key =*/kp256_.private_key.data(),
    /*.issuer_private_key_size =*/kp256_.private_key_size,
    /*.signature_md_alg=*/MBEDTLS_MD_SHA256,
  };

  // bad buffer
  std::array<unsigned char, 1> too_small{};
  int err = oc_obt_generate_role_cert_pem(cert_data, too_small.data(),
                                          too_small.size());
  EXPECT_GT(0, err);

  std::array<unsigned char, 4096> pem;
  // bad subject
  oc_obt_generate_role_cert_data_t bad_data{ cert_data };
  std::string bad_subject =
    "A=" + std::string(MBEDTLS_X509_MAX_DN_NAME_SIZE + 1, 'a');
  bad_data.subject_name = bad_subject.c_str();
  err = oc_obt_generate_role_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad public key
  std::array<uint8_t, 1> bad_key{ '\0' };
  bad_data = cert_data;
  bad_data.public_key = bad_key.data();
  bad_data.public_key_size = 1;
  err = oc_obt_generate_role_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad issuer
  std::string bad_issuer =
    "A=" + std::string(MBEDTLS_X509_MAX_DN_NAME_SIZE + 1, 'b');
  bad_data = cert_data;
  bad_data.issuer_name = bad_issuer.c_str();
  err = oc_obt_generate_role_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad private key
  bad_data = cert_data;
  bad_data.issuer_private_key = bad_key.data();
  bad_data.issuer_private_key_size = 1;
  err = oc_obt_generate_role_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad role - nullptr
  bad_data = cert_data;
  bad_data.roles = nullptr;
  err = oc_obt_generate_role_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);

  // bad role - bad value
  bad_data = cert_data;
  oc::Roles roles;
  roles.Add(std::string(MBEDTLS_X509_MAX_DN_NAME_SIZE + 1, 'c'), "");
  bad_data.roles = roles.Head();
  err = oc_obt_generate_role_cert_pem(bad_data, pem.data(), pem.size());
  EXPECT_GT(0, err);
}

TEST_F(TestObtCerts, GenerateValidRoleCertificate)
{
  auto role_cert = oc::pki::obt::GenerateRoleCertificate(
    uuid_, g_root_subject, kp256_, roles_, MBEDTLS_MD_SHA384);
  ASSERT_FALSE(role_cert.empty());

  std::array<char, 128> serial{};
  int ret = oc_certs_parse_serial_number(&role_cert[0], role_cert.size(),
                                         serial.data(), serial.size());
  ASSERT_LT(0, ret);
  OC_DBG("serial: %s", &serial[0]);

  std::array<char, OC_UUID_LEN> uuid_cstr{};
  ASSERT_TRUE(oc_certs_parse_CN_for_UUID(&role_cert[0], role_cert.size(),
                                         uuid_cstr.data(), uuid_cstr.size()));
#ifdef _WIN32
  // linker error when ASAN is enabled
  EXPECT_NE(-1, uuid_.find(uuid_cstr.data(), 0));
#else
  EXPECT_NE(std::string::npos, uuid_.find(uuid_cstr.data(), 0));
#endif

  std::array<uint8_t, 200> private_key{};
  ret = oc_certs_parse_private_key(0, &role_cert[0], role_cert.size(),
                                   private_key.data(), private_key.size());
  ASSERT_EQ(kp256_.private_key_size, ret);

  std::array<uint8_t, 200> public_key{};
  ret = oc_certs_parse_public_key(&role_cert[0], role_cert.size(),
                                  public_key.data(), public_key.size());
  ASSERT_LT(0, ret);
  EXPECT_EQ(0, memcmp(kp256_.public_key.data(), public_key.data(), ret));

  oc_string_t role{};
  oc_string_t authority{};
  ASSERT_TRUE(oc_certs_parse_first_role(&role_cert[0], role_cert.size(), &role,
                                        &authority));
  EXPECT_STREQ(oc_string(roles_.Get(0)->role), oc_string(role));
  EXPECT_STREQ(oc_string(roles_.Get(0)->authority), oc_string(authority));
  OC_DBG("role: %s", oc_string(role));
  OC_DBG("authority: %s", oc_string(authority));
  oc_free_string(&role);
  oc_free_string(&authority);
}

#ifdef OC_TEST

TEST_F(TestObtCerts, SerializeRoleCertificate)
{
  auto role_cert = oc::pki::obt::GenerateRoleCertificate(uuid_, g_root_subject,
                                                         kp384_, roles_);
  ASSERT_FALSE(role_cert.empty());

  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  EXPECT_EQ(0, mbedtls_x509_crt_parse(&crt, &role_cert[0], role_cert.size()));

  std::vector<char> pem{};
  pem.resize(4096, '\0');
  int ret = oc_certs_serialize_chain_to_pem(&crt, pem.data(), pem.size());
  EXPECT_LT(0, ret);
  pem.resize(ret + 1); // +1 for nul-terminator

  EXPECT_STREQ(stripNewLines(role_cert).c_str(), stripNewLines(pem).c_str());

  mbedtls_x509_crt_free(&crt);
}

#endif /* OC_TEST */

TEST_F(TestObtCerts, ValidateRoleCertificate)
{
  auto cert_buf = oc::pki::obt::GenerateRoleCertificate(
    uuid_, g_root_subject, kp384_, roles_, MBEDTLS_MD_SHA384);
  ASSERT_FALSE(cert_buf.empty());

  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  EXPECT_EQ(0, mbedtls_x509_crt_parse(&crt, &cert_buf[0], cert_buf.size()));
  // role == role test should succeed, others should fail
  uint32_t flags{};
  EXPECT_EQ(0, oc_certs_validate_role_cert(&crt, &flags));
  EXPECT_EQ(0, flags);
  EXPECT_NE(0, oc_certs_validate_end_entity_cert(&crt, &flags));
  EXPECT_NE(0, oc_certs_validate_non_end_entity_cert(&crt, true, true,
                                                     /*depth*/ 0, &flags));

  mbedtls_x509_crt_free(&crt);
}

static constexpr size_t kDeviceID{ 0 };

class TestObtCertsWithDevice : public testing::Test {
public:
  static void SetUpTestCase()
  {
    // allow all ocf-supported MDs and ECs
    oc_sec_certs_md_set_algorithms_allowed(OCF_CERTS_SUPPORTED_MDS);
    oc_sec_certs_ecp_set_group_ids_allowed(OCF_CERTS_SUPPORTED_ELLIPTIC_CURVES);

    EXPECT_TRUE(oc::TestDevice::StartServer());
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();

    // restore defaults
    oc_sec_certs_md_set_algorithms_allowed(
      MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256));
    oc_sec_certs_ecp_set_group_ids_allowed(
      MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1));
  }

  void SetUp() override
  {
    oc_uuid_t uuid{};
    oc_gen_uuid(&uuid);
    std::array<char, 50> buf;
    EXPECT_TRUE(oc_certs_encode_CN_with_UUID(&uuid, buf.data(), buf.size()));
    uuid_ = buf.data();

    // if empty authority should be taken from the Common Name of the issuer
    roles_.Add("user", "");
  }

  void TearDown() override { oc::TestDevice::Reset(); }

  std::string uuid_{};
  oc::Roles roles_{};
};

TEST_F(TestObtCertsWithDevice, RootCertificateCredential)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int credid = oc::pki::obt::GenerateSelfSignedRootCertificate(
    kDeviceID, g_root_subject, kp);
  ASSERT_LT(0, credid);

  oc_sec_cred_t *cred = oc_sec_get_cred_by_credid(credid, kDeviceID);
  EXPECT_NE(nullptr, cred);
  // is root CA
  EXPECT_EQ(OC_CREDUSAGE_TRUSTCA, cred->credusage);

  // public data should have a valid certificate in PEM format
  EXPECT_EQ(OC_ENCODING_PEM, cred->publicdata.encoding);

  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  EXPECT_EQ(0, mbedtls_x509_crt_parse(
                 &crt, oc_cast(cred->publicdata.data, unsigned char),
                 cred->publicdata.data.size));
  uint32_t flags{};
  EXPECT_EQ(0, oc_certs_validate_non_end_entity_cert(&crt, true, true,
                                                     /*depth*/ 0, &flags));
  EXPECT_EQ(0, flags);
  mbedtls_x509_crt_free(&crt);
}

TEST_F(TestObtCertsWithDevice, RoleCertificateCredential)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP384R1) };

  // need a trust anchor to verify Role Cert
  int credid = oc::pki::obt::GenerateSelfSignedRootCertificate(
    kDeviceID, g_root_subject, kp);
  ASSERT_LT(0, credid);

  oc_obt_generate_role_cert_data_t role_cert = {
    /*.roles =*/roles_.Head(),
    /*.subject_name =*/uuid_.c_str(),
    /*.public_key =*/kp.public_key.data(),
    /*.public_key_size =*/kp.public_key_size,
    /*.issuer_name =*/g_root_subject.c_str(),
    /*.issuer_private_key =*/kp.private_key.data(),
    /*.issuer_private_key_size =*/kp.private_key_size,
    /*.signature_md_alg=*/MBEDTLS_MD_SHA384,
  };

  std::vector<unsigned char> cert_buf{};
  cert_buf.resize(4096, '\0');
  int err =
    oc_obt_generate_role_cert_pem(role_cert, cert_buf.data(), cert_buf.size());
  EXPECT_EQ(0, err);

  oc_uuid_t subjectuuid{};
  subjectuuid.id[0] = '*';
  oc_sec_cred_t *cred = oc_sec_allocate_cred(&subjectuuid, OC_CREDTYPE_CERT,
                                             OC_CREDUSAGE_ROLE_CERT, kDeviceID);
  EXPECT_NE(nullptr, cred);
  EXPECT_EQ(0, oc_certs_parse_role_certificate(&cert_buf[0], cert_buf.size(),
                                               cred, false));
  OC_DBG("role: %s", oc_string(cred->role.role));
  EXPECT_STREQ(oc_string(roles_.Get(0)->role), oc_string(cred->role.role));

  OC_DBG("authority: %s", oc_string(cred->role.authority));
  EXPECT_STREQ(g_root_subject_name.c_str(), oc_string(cred->role.authority));

  oc_sec_remove_cred(cred, kDeviceID);
}

#endif /* OC_SECURITY && OC_PKI && OC_DYNAMIC_ALLOCATION  */
