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

#include "port/oc_random.h"
#include "security/oc_certs_generate_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_keypair_internal.h"
#include "security/oc_security_internal.h"
#include "tests/gtest/KeyPair.h"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509.h>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

using mbedtls_x509_crt_uptr =
  std::unique_ptr<mbedtls_x509_crt, void (*)(mbedtls_x509_crt *)>;

class TestCerts : public testing::Test {
public:
  template<class T>
  static std::vector<T> toArray(const std::string &str)
  {
    std::vector<T> res;
    std::copy(str.begin(), str.end(), std::back_inserter(res));
    return res;
  }
};

TEST_F(TestCerts, IsPem)
{
  auto is_pem = [](const std::string &str) {
    std::vector<unsigned char> buf{ toArray<unsigned char>(str) };
    return oc_certs_is_PEM(buf.data(), buf.size());
  };

  EXPECT_FALSE(is_pem(""));
  EXPECT_FALSE(is_pem("-----BEGIN"));
  EXPECT_FALSE(is_pem("-----BEGIN "));
  EXPECT_TRUE(is_pem("-----BEGIN CERTIFICATE-----"));
}

TEST_F(TestCerts, TimestampFormatFail)
{
  timestamp_t ts = oc_certs_timestamp_now();

  std::array<char, 1> too_small;
  EXPECT_FALSE(
    oc_certs_timestamp_format(ts, too_small.data(), too_small.size()));
}

TEST_F(TestCerts, TimestampFormat)
{
  timestamp_t ts = oc_certs_timestamp_now();

  std::array<char, 15> buffer;
  EXPECT_TRUE(oc_certs_timestamp_format(ts, buffer.data(), buffer.size()));
  OC_DBG("now: %s", buffer.data());

  std::string notAfter{ "2029-12-31T23:59:59Z" };
  EXPECT_EQ(0, timestamp_parse(notAfter.c_str(), notAfter.length(), &ts));
  EXPECT_TRUE(oc_certs_timestamp_format(ts, buffer.data(), buffer.size()));
  OC_DBG("notAfter: %s", buffer.data());
}

class TestGenerateCerts : public testing::Test {
public:
  void SetUp() override
  {
    oc_mbedtls_init();
    oc_random_init();

    oc_uuid_t uuid{};
    oc_gen_uuid(&uuid);
    std::array<char, 50> buf;
    EXPECT_TRUE(oc_certs_encode_CN_with_UUID(&uuid, buf.data(), buf.size()));
    uuid_ = buf.data();
  }

  void TearDown() override { oc_random_destroy(); }

  static std::vector<unsigned char> GeneratePEM(oc_certs_generate_t data);
  static mbedtls_x509_crt_uptr Generate(oc_certs_generate_t data);

  std::string uuid_{};

  static const std::vector<unsigned char> g_personalization_string;
  static const std::string g_root_subject_name;
  static const std::string g_root_subject_CN;
};

const std::string TestGenerateCerts::g_root_subject_name{
  "IoTivity-Lite Test"
};
const std::string TestGenerateCerts::g_root_subject_CN{ "C=US, O=OCF, CN=" +
                                                        g_root_subject_name };
const std::vector<unsigned char> TestGenerateCerts::g_personalization_string =
  []() {
    auto ps = TestCerts::toArray<unsigned char>("IoTivity-Lite-Test");
    ps.push_back('\0');
    return ps;
  }();

std::vector<unsigned char>
TestGenerateCerts::GeneratePEM(oc_certs_generate_t data)
{
  std::vector<unsigned char> pem{};
  pem.resize(4096, '\0');
  EXPECT_EQ(0, oc_certs_generate(data, pem.data(), pem.size()));
  auto it = std::find(pem.begin(), pem.end(), static_cast<unsigned char>('\0'));
  size_t pem_size =
    std::distance(pem.begin(), it) + 1; // size with NULL terminator
  EXPECT_NE(pem.end(), it);
  EXPECT_TRUE(oc_certs_is_PEM(&pem[0], pem_size));
  pem.resize(pem_size);
  return pem;
}

mbedtls_x509_crt_uptr
TestGenerateCerts::Generate(oc_certs_generate_t data)
{
  auto pem = GeneratePEM(data);
  mbedtls_x509_crt_uptr crt(new mbedtls_x509_crt, [](mbedtls_x509_crt *crt) {
    mbedtls_x509_crt_free(crt);
    delete crt;
  });
  mbedtls_x509_crt_init(crt.get());
  EXPECT_EQ(0, mbedtls_x509_crt_parse(crt.get(), pem.data(), pem.size()));
  return crt;
}

// TEST_F(TestGenerateCerts, SerialNumber)
// {
//   keypair_t kp{};
//   int err = oc_generate_ecdsa_keypair(
//     MBEDTLS_ECP_DP_SECP256R1, kp.public_key.data(), kp.public_key.size(),
//     &kp.public_key_size, kp.private_key.data(), kp.private_key.size(),
//     &kp.private_key_size);
//   EXPECT_EQ(0, err);

//   oc_certs_generate_t data{};
//   data.personalization_string.value = g_personalization_string.data();
//   data.personalization_string.size = g_personalization_string.size();
//   // data.serial_number_size = 20;
//   // data.validity.not_before = oc_certs_timestamp_now();
//   data.subject.name = g_root_subject_CN.c_str();
//   data.subject.public_key.value = kp.public_key.data();
//   data.subject.public_key.size = kp.public_key_size;
//   data.subject.private_key.value = kp.private_key.data();
//   data.subject.private_key.size = kp.private_key_size;
//   data.is_CA = true;
//   // data.key_usage.key_usage =
//   //   MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT;
//   data.signature_md = MBEDTLS_MD_SHA256;

//   std::array<unsigned char, 4096> pem{};
//   EXPECT_EQ(0, oc_certs_generate(data, pem.data(), pem.size()));
// }

TEST_F(TestGenerateCerts, MinimalCA)
{
  oc::keypair_t kp = oc::GetECPKeypair(MBEDTLS_ECP_DP_SECP256R1);

  oc_certs_generate_t data{};
  data.personalization_string.value = g_personalization_string.data();
  data.personalization_string.size = g_personalization_string.size();
  data.subject.name = g_root_subject_CN.c_str();
  data.subject.public_key.value = kp.public_key.data();
  data.subject.public_key.size = kp.public_key_size;
  data.subject.private_key.value = kp.private_key.data();
  data.subject.private_key.size = kp.private_key_size;
  data.validity.not_before = oc_certs_timestamp_now();
  data.is_CA = true;
  data.signature_md = MBEDTLS_MD_SHA256;

  auto cert = Generate(data);
  EXPECT_NE(0, cert->ca_istrue);
}

#endif /* OC_SECURITY && OC_PKI  */
