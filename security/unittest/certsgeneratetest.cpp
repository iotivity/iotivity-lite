/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
#include "oc_helpers.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "security/oc_certs_generate_internal.h"
#include "security/oc_certs_internal.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/Role.h"
#include "tests/gtest/Utility.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <limits>
#include <mbedtls/ctr_drbg.h>
#include <string>
#include <vector>

class TestGenerateCerts : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }
};

static const std::vector<uint8_t> kPersonalizationString{
  oc::GetVector<uint8_t>("IoTivity-lite Test Cert")
};
static constexpr timestamp_t kInvalidTimestamp{ INT64_MAX, INT32_MAX,
                                                INT16_MAX };
static constexpr std::string_view kRootSubjectName{ "IoTivity-Lite Test" };
static const std::string kRootSubject{ "C=US, O=OCF, CN=" +
                                       std::string(kRootSubjectName) };

TEST_F(TestGenerateCerts, GenerateSerialNumber_Fail)
{
  std::array<unsigned char, 1> too_small{};
  EXPECT_EQ(
    -1, oc_certs_generate_serial_number(&too_small[0], too_small.size(), 20));

  std::array<unsigned char, MBEDTLS_CTR_DRBG_MAX_REQUEST + 1> buffer{};
  EXPECT_EQ(-1, oc_certs_generate_serial_number(
                  &buffer[0], buffer.size(), MBEDTLS_CTR_DRBG_MAX_REQUEST + 1));
}

TEST_F(TestGenerateCerts, GenerateSerialNumber)
{
  std::array<unsigned char, 20> buffer{};
  EXPECT_EQ(20, oc_certs_generate_serial_number(&buffer[0], buffer.size(), 20));
}

TEST_F(TestGenerateCerts, TimestampFormat_InvalidTimestamp)
{
  std::array<char, 64> buffer{};
  EXPECT_FALSE(
    oc_certs_timestamp_format(kInvalidTimestamp, buffer.data(), buffer.size()));
}

TEST_F(TestGenerateCerts, TimestampFormat_FailBufferTooSmall)
{
  timestamp_t ts = oc_certs_timestamp_now();

  std::array<char, 1> too_small{};
  EXPECT_FALSE(
    oc_certs_timestamp_format(ts, too_small.data(), too_small.size()));
}

TEST_F(TestGenerateCerts, TimestampFormat)
{
  timestamp_t ts = oc_certs_timestamp_now();

  std::array<char, 15> buffer{};
  EXPECT_TRUE(oc_certs_timestamp_format(ts, buffer.data(), buffer.size()));
  OC_DBG("now: %s", buffer.data());

  std::string notAfter{ "2029-12-31T23:59:59Z" };
  EXPECT_EQ(0, timestamp_parse(notAfter.c_str(), notAfter.length(), &ts));
  EXPECT_TRUE(oc_certs_timestamp_format(ts, buffer.data(), buffer.size()));
  OC_DBG("notAfter: %s", buffer.data());
}

TEST_F(TestGenerateCerts, EncodeRole_Fail)
{
  // CN=user,OU=admin
  oc::Role role{ "user", "admin" };
  std::array<char, 1> too_small_1{};
  // can't fit role
  EXPECT_FALSE(
    oc_certs_encode_role(role.Data(), &too_small_1[0], too_small_1.size()));

  // can fit role (CN=user) but can't fit OU=admin
  std::array<char, 10> too_small_2{};
  EXPECT_FALSE(
    oc_certs_encode_role(role.Data(), &too_small_2[0], too_small_2.size()));

  oc::Role empty{ "" };
  std::array<char, 64> buffer{};
  EXPECT_FALSE(oc_certs_encode_role(empty.Data(), &buffer[0], buffer.size()));
}

TEST_F(TestGenerateCerts, EncodeRole)
{
  oc::Role role{ "user" };
  std::array<char, 64> buffer{};
  ASSERT_TRUE(oc_certs_encode_role(role.Data(), &buffer[0], buffer.size()));
  EXPECT_STREQ("CN=user", buffer.data());

  buffer = {};
  oc_role_t oc_role{};
  oc_role.role.ptr = role.Data()->role.ptr;
  oc_role.role.size = role.Data()->role.size;
  std::string empty{};
  oc_role.authority.ptr = empty.data();
  oc_role.authority.size = empty.length();
  ASSERT_TRUE(oc_certs_encode_role(&oc_role, &buffer[0], buffer.size()));
  EXPECT_STREQ("CN=user", buffer.data());

  buffer = {};
  oc::Role role2{ "user", "admin" };
  ASSERT_TRUE(oc_certs_encode_role(role2.Data(), &buffer[0], buffer.size()));
  EXPECT_STREQ("CN=user,OU=admin", buffer.data());
}

TEST_F(TestGenerateCerts, Generate_FailBadDrbg)
{
  oc_certs_generate_t generate{};
  std::vector<uint8_t> too_long(MBEDTLS_CTR_DRBG_MAX_SEED_INPUT, 'a');
  generate.personalization_string.value = too_long.data();
  generate.personalization_string.size = too_long.size();

  std::array<unsigned char, 4096> cert_pem{};
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));
}

TEST_F(TestGenerateCerts, Generate_FailBadSerialNumber)
{
  oc_certs_generate_t generate{};
  generate.personalization_string.value = kPersonalizationString.data();
  generate.personalization_string.size = kPersonalizationString.size();
  #if MBEDTLS_VERSION_NUMBER <= 0x03010000
    generate.serial_number_size = 4096;
  #else /* MBEDTLS_VERSION_NUMBER >= 0x03010000 */
    generate.serial_number_size = MBEDTLS_CTR_DRBG_MAX_REQUEST;
  #endif /* MBEDTLS_VERSION_NUMBER <= 0x03010000 */

  std::array<unsigned char, 4096> cert_pem{};
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));
}

TEST_F(TestGenerateCerts, Generate_FailBadValidity)
{
  oc_certs_generate_t generate{};
  generate.personalization_string.value = kPersonalizationString.data();
  generate.personalization_string.size = kPersonalizationString.size();
  generate.validity.not_before = kInvalidTimestamp;

  std::array<unsigned char, 4096> cert_pem{};
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));

  generate.validity.not_before = {};
  generate.validity.not_after = kInvalidTimestamp;
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));
}

TEST_F(TestGenerateCerts, Generate_FailBadSubject)
{
  oc_certs_generate_t generate{};
  generate.personalization_string.value = kPersonalizationString.data();
  generate.personalization_string.size = kPersonalizationString.size();
  // invalid subject name, ',' is not supported as a value
  generate.subject.name = "subject=,";
  std::array<unsigned char, 4096> cert_pem{};
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));
}

TEST_F(TestGenerateCerts, Generate_FailBadIssuer)
{
  oc_certs_generate_t generate{};
  generate.personalization_string.value = kPersonalizationString.data();
  generate.personalization_string.size = kPersonalizationString.size();
  generate.subject.name = kRootSubject.c_str();
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  generate.subject.public_key.value = kp.public_key.data();
  generate.subject.public_key.size = kp.public_key_size;
    // invalid issuer name, ',' is not supported as a value
  generate.issuer.name = "issuer=,";

  std::array<unsigned char, 4096> cert_pem{};
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));
}

TEST_F(TestGenerateCerts, Generate_FailBadRoles)
{
  oc_certs_generate_t generate{};
  generate.personalization_string.value = kPersonalizationString.data();
  generate.personalization_string.size = kPersonalizationString.size();
  generate.subject.name = kRootSubject.c_str();
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  generate.subject.public_key.value = kp.public_key.data();
  generate.subject.public_key.size = kp.public_key_size;
  generate.issuer.name = kRootSubject.c_str();
  generate.issuer.private_key.value = kp.private_key.data();
  generate.issuer.private_key.size = kp.private_key_size;
  generate.signature_md = MBEDTLS_MD_SHA256;

  oc::Roles roles{};
  roles.Add("user", "admin");
  roles.Add(std::string(MBEDTLS_X509_MAX_DN_NAME_SIZE + 1, 'c'), "");
  generate.roles = roles.Head();

  std::array<unsigned char, 4096> cert_pem{};
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));
}

TEST_F(TestGenerateCerts, Generate_FailBadKeyUsage)
{
  oc_certs_generate_t generate{};
  generate.personalization_string.value = kPersonalizationString.data();
  generate.personalization_string.size = kPersonalizationString.size();
  generate.subject.name = kRootSubject.c_str();
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  generate.subject.public_key.value = kp.public_key.data();
  generate.subject.public_key.size = kp.public_key_size;
  generate.issuer.name = kRootSubject.c_str();
  generate.issuer.private_key.value = kp.private_key.data();
  generate.issuer.private_key.size = kp.private_key_size;
  generate.key_usage.key_usage =
    std::numeric_limits<decltype(generate.key_usage.key_usage)>::max();

  std::array<unsigned char, 4096> cert_pem{};
  EXPECT_GT(0, oc_certs_generate(&generate, &cert_pem[0], cert_pem.size()));
}

class TestParseCerts : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }
};

static oc_certs_generate_t
defaultCertificateGenerate(const oc::keypair_t &kp, bool isCA = false)
{
  oc_certs_generate_t generate{};
  generate.personalization_string.value = kPersonalizationString.data();
  generate.personalization_string.size = kPersonalizationString.size();
  generate.validity.not_before = oc_certs_timestamp_now();
  generate.validity.not_after = oc_certs_timestamp_now();
  generate.subject.name = kRootSubject.c_str();
  generate.subject.public_key.value = kp.public_key.data();
  generate.subject.public_key.size = kp.public_key_size;
  generate.issuer.name = kRootSubject.c_str();
  generate.issuer.private_key.value = kp.private_key.data();
  generate.issuer.private_key.size = kp.private_key_size;
  generate.signature_md = MBEDTLS_MD_SHA256;
  generate.is_CA = isCA;
  return generate;
}

static std::vector<unsigned char>
getCertificate(const oc_certs_generate_t &generate)
{
  std::vector<unsigned char> cert_buf{};
  cert_buf.resize(4096, '\0');
  int err = oc_certs_generate(&generate, cert_buf.data(), cert_buf.size());
  EXPECT_EQ(0, err);
  if (err != 0) {
    return {};
  }

  auto it = std::find(cert_buf.begin(), cert_buf.end(),
                      static_cast<unsigned char>('\0'));
  size_t data_len =
    std::distance(cert_buf.begin(), it) + 1; // size with NULL terminator
  if (cert_buf.end() == it || !oc_certs_is_PEM(&cert_buf[0], data_len)) {
    return {};
  }
  cert_buf.resize(data_len);
  return cert_buf;
}

TEST_F(TestParseCerts, ParseSerialNumber_Fail)
{
  // invalid PEM
  std::array<char, 10> buffer{};
  EXPECT_GT(
    0, oc_certs_parse_serial_number(nullptr, 0, &buffer[0], buffer.size()));

  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  // longer than the buffer size
  generate.serial_number_size = 20;
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  EXPECT_GT(0, oc_certs_parse_serial_number(pem.data(), pem.size(), &buffer[0],
                                            buffer.size()));
}

TEST_F(TestParseCerts, ParseSerialNumber)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  std::array<char, 64> buffer{};
  // certificate without serial number
  EXPECT_EQ(0, oc_certs_parse_serial_number(pem.data(), pem.size(), &buffer[0],
                                            buffer.size()));

  generate = defaultCertificateGenerate(kp);
  generate.serial_number_size = 10;
  pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  EXPECT_LT(0, oc_certs_parse_serial_number(pem.data(), pem.size(), &buffer[0],
                                            buffer.size()));
}

TEST_F(TestParseCerts, ParsePrivateKey_Fail)
{
  std::array<uint8_t, 200> private_key{};
  EXPECT_GT(0, oc_certs_parse_private_key(0, nullptr, 0, &private_key[0],
                                          private_key.size()));

  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  std::array<uint8_t, 1> too_small{};
  EXPECT_GT(0, oc_certs_parse_private_key(0, pem.data(), pem.size(),
                                          &too_small[0], too_small.size()));
}

TEST_F(TestParseCerts, ParsePrivateKey)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  std::array<uint8_t, 200> private_key{};
  int ret = oc_certs_parse_private_key(0, pem.data(), pem.size(),
                                       &private_key[0], private_key.size());
  ASSERT_EQ(generate.issuer.private_key.size, ret);
}

TEST_F(TestParseCerts, ParsePublicKey_Fail)
{
  std::array<uint8_t, 200> public_key{};
  EXPECT_GT(0, oc_certs_parse_public_key(nullptr, 0, &public_key[0],
                                         public_key.size()));

  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  std::array<uint8_t, 1> too_small{};
  EXPECT_GT(0, oc_certs_parse_public_key(pem.data(), pem.size(), &too_small[0],
                                         too_small.size()));
}

TEST_F(TestParseCerts, ParsePublicKey)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  std::array<uint8_t, 200> public_key{};
  int ret = oc_certs_parse_public_key(pem.data(), pem.size(), &public_key[0],
                                      public_key.size());
  ASSERT_EQ(generate.subject.public_key.size, ret);
  EXPECT_EQ(0,
            memcmp(generate.subject.public_key.value, public_key.data(), ret));
}

TEST_F(TestParseCerts, ExtractPublicKeyToOCString_Fail)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  oc_string_t public_key{};
  EXPECT_GT(0, oc_certs_extract_public_key_to_oc_string(&crt, &public_key));

  mbedtls_x509_crt_free(&crt);
}

TEST_F(TestParseCerts, ParsePublicKeyToOCString_Fail)
{
  oc_string_t public_key{};
  EXPECT_GT(0, oc_certs_parse_public_key_to_oc_string(nullptr, 0, &public_key));
}

TEST_F(TestParseCerts, ParsePublicKeyToOCString)
{
  oc_string_t public_key{};
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  int ret =
    oc_certs_parse_public_key_to_oc_string(pem.data(), pem.size(), &public_key);
  ASSERT_LT(0, ret);
  EXPECT_EQ(generate.subject.public_key.size, ret);
  EXPECT_EQ(
    0, memcmp(generate.subject.public_key.value, oc_string(public_key), ret));
  oc_free_string(&public_key);
}

TEST_F(TestParseCerts, ParseFirstRole_Fail)
{
  oc_string_t role{};
  oc_string_t authority{};
  EXPECT_FALSE(oc_certs_parse_first_role(nullptr, 0, &role, &authority));

  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  EXPECT_FALSE(
    oc_certs_parse_first_role(pem.data(), pem.size(), &role, &authority));
}

TEST_F(TestParseCerts, ParseFirstRole_FailInvalidSubjectRole)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  // role is expected to be a "CN" attribute
  std::string invalidRole = "title=test";
#if MBEDTLS_VERSION_NUMBER <= 0x03010000
  generate.modify_fn = [](mbedtls_x509write_cert *crt, const void *data) {
    const auto *alt_names =
      static_cast<const mbedtls_x509_general_names *>(data);
    return mbedtls_x509write_crt_set_subject_alt_names(crt, alt_names) == 0;
  };
  mbedtls_x509_general_names names{};
  names.general_name.name_type = MBEDTLS_X509_GENERALNAME_DIRECTORYNAME;
  ASSERT_EQ(0, mbedtls_x509_string_to_names(
                 &names.general_name.name.directory_name, invalidRole.c_str()));
  generate.modify_fn_data = &names;
  auto pem = getCertificate(generate);
  mbedtls_asn1_free_named_data_list(&names.general_name.name.directory_name);
#else  /*  MBEDTLS_VERSION_NUMBER > 0x03010000  */
  generate.modify_fn = [](mbedtls_x509write_cert *crt, const void *data) {
    const auto *alt_names = static_cast<const mbedtls_x509_san_list *>(data);
    return mbedtls_x509write_crt_set_subject_alternative_name(crt, alt_names) ==
           0;
  };
  mbedtls_x509_san_list names{};
  names.node.type = MBEDTLS_X509_SAN_DIRECTORY_NAME;
  mbedtls_asn1_named_data *namedData = nullptr;
  ASSERT_EQ(0, mbedtls_x509_string_to_names(&namedData, invalidRole.c_str()));
  names.node.san.directory_name = *namedData;
  generate.modify_fn_data = &names;
  auto pem = getCertificate(generate);
  mbedtls_asn1_free_named_data_list(&namedData);
#endif /* MBEDTLS_VERSION_NUMBER <= 0x03010000 */
  ASSERT_FALSE(pem.empty());
  oc_string_t role{};
  oc_string_t authority{};
  EXPECT_FALSE(
    oc_certs_parse_first_role(pem.data(), pem.size(), &role, &authority));
}

TEST_F(TestParseCerts, ParseFirstRole_FailMissingSubjectRole)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  // authority (OU) exists, but role (CN) is missing
  std::string invalidSubject = "O=OCF, OU=admin";
#if MBEDTLS_VERSION_NUMBER <= 0x03010000
  generate.modify_fn = [](mbedtls_x509write_cert *crt, const void *data) {
    const auto *alt_names =
      static_cast<const mbedtls_x509_general_names *>(data);
    return mbedtls_x509write_crt_set_subject_alt_names(crt, alt_names) == 0;
  };
  mbedtls_x509_general_names names{};
  names.general_name.name_type = MBEDTLS_X509_GENERALNAME_DIRECTORYNAME;
  ASSERT_EQ(
    0, mbedtls_x509_string_to_names(&names.general_name.name.directory_name,
                                    invalidSubject.c_str()));
  generate.modify_fn_data = &names;
  auto pem = getCertificate(generate);
  mbedtls_asn1_free_named_data_list(&names.general_name.name.directory_name);
#else  /*  MBEDTLS_VERSION_NUMBER > 0x03010000  */
  generate.modify_fn = [](mbedtls_x509write_cert *crt, const void *data) {
    const auto *alt_names = static_cast<const mbedtls_x509_san_list *>(data);
    return mbedtls_x509write_crt_set_subject_alternative_name(crt, alt_names) ==
           0;
  };
  mbedtls_x509_san_list names{};
  names.node.type = MBEDTLS_X509_SAN_DIRECTORY_NAME;
  mbedtls_asn1_named_data *namedData = nullptr;
  ASSERT_EQ(0,
            mbedtls_x509_string_to_names(&namedData, invalidSubject.c_str()));
  names.node.san.directory_name = *namedData;
  generate.modify_fn_data = &names;
  auto pem = getCertificate(generate);
  mbedtls_asn1_free_named_data_list(&namedData);
#endif /* MBEDTLS_VERSION_NUMBER <= 0x03010000 */
  ASSERT_FALSE(pem.empty());
  oc_string_t role{};
  oc_string_t authority{};
  EXPECT_FALSE(
    oc_certs_parse_first_role(pem.data(), pem.size(), &role, &authority));
}

TEST_F(TestParseCerts, ParseFirstRole_FailInvalidSubjectType)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  auto invalidSubject = oc::GetVector<unsigned char>("test");
#if MBEDTLS_VERSION_NUMBER <= 0x03010000
  generate.modify_fn = [](mbedtls_x509write_cert *crt, const void *data) {
    const auto *alt_names =
      static_cast<const mbedtls_x509_general_names *>(data);
    return mbedtls_x509write_crt_set_subject_alt_names(crt, alt_names) == 0;
  };
  mbedtls_x509_general_names names{};
  names.general_name.name_type = MBEDTLS_X509_GENERALNAME_DNSNAME;
  names.general_name.name.dns_name.p = invalidSubject.data();
  names.general_name.name.dns_name.len = invalidSubject.size();
  generate.modify_fn_data = &names;
  auto pem = getCertificate(generate);
#else  /*  MBEDTLS_VERSION_NUMBER > 0x03010000  */
  generate.modify_fn = [](mbedtls_x509write_cert *crt, const void *data) {
    const auto *alt_names = static_cast<const mbedtls_x509_san_list *>(data);
    return mbedtls_x509write_crt_set_subject_alternative_name(crt, alt_names) ==
           0;
  };
  mbedtls_x509_san_list names{};
  names.node.type = MBEDTLS_X509_SAN_DNS_NAME;
  names.node.san.unstructured_name.p = invalidSubject.data();
  names.node.san.unstructured_name.len = invalidSubject.size();
  generate.modify_fn_data = &names;
  auto pem = getCertificate(generate);
#endif /* MBEDTLS_VERSION_NUMBER <= 0x03010000 */
  ASSERT_FALSE(pem.empty());
  oc_string_t role{};
  oc_string_t authority{};
  EXPECT_FALSE(
    oc_certs_parse_first_role(pem.data(), pem.size(), &role, &authority));
}

TEST_F(TestParseCerts, ParseFirstRole_FailInvalidSubjectAuthority)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  generate.issuer.name = "C=US, O=OCF";
  oc::Roles roles{};
  roles.Add("user1");
  generate.roles = roles.Head();
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());
  oc_string_t role{};
  oc_string_t authority{};
  EXPECT_FALSE(
    oc_certs_parse_first_role(pem.data(), pem.size(), &role, &authority));
}

TEST_F(TestParseCerts, ParseFirstRole)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  oc::Roles roles{};
  roles.Add("user1", "admin1");
  roles.Add("user2", "admin2");
  generate.roles = roles.Head();
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());

  oc_string_t role{};
  oc_string_t authority{};
  ASSERT_TRUE(
    oc_certs_parse_first_role(pem.data(), pem.size(), &role, &authority));
  // roles are written in reverse order
  EXPECT_STREQ(oc_string(roles.Get(1)->role), oc_string(role));
  EXPECT_STREQ(oc_string(roles.Get(1)->authority), oc_string(authority));
  oc_free_string(&role);
  oc_free_string(&authority);
}

TEST_F(TestParseCerts, ParseFirstRoleGetAuthorityFromIssuer)
{
  oc::keypair_t kp{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc_certs_generate_t generate{ defaultCertificateGenerate(kp) };
  oc::Roles roles{};
  roles.Add("user1");
  generate.roles = roles.Head();
  auto pem = getCertificate(generate);
  ASSERT_FALSE(pem.empty());

  oc_string_t role{};
  oc_string_t authority{};
  ASSERT_TRUE(
    oc_certs_parse_first_role(pem.data(), pem.size(), &role, &authority));
  EXPECT_STREQ(oc_string(roles.Get(0)->role), oc_string(role));
  EXPECT_STREQ(kRootSubjectName.data(), oc_string(authority));
  oc_free_string(&role);
  oc_free_string(&authority);
}

#endif /* OC_SECURITY && OC_PKI && OC_DYNAMIC_ALLOCATION */
