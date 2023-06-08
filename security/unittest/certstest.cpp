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
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "security/oc_certs_internal.h"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <mbedtls/asn1.h>
#include <string>
#include <vector>

class TestCerts : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }

  void TearDown() override
  {
    // restore defaults
    oc_sec_certs_default();
  }

  template<class T>
  static std::vector<T> toArray(const std::string &str)
  {
    std::vector<T> res{};
    std::copy(std::begin(str), std::end(str), std::back_inserter(res));
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

TEST_F(TestCerts, SetSignatureMDAlgorithm)
{
  std::vector<mbedtls_md_type_t> all_mds{
    MBEDTLS_MD_MD5,      MBEDTLS_MD_SHA1,   MBEDTLS_MD_SHA224,
    MBEDTLS_MD_SHA256,   MBEDTLS_MD_SHA384, MBEDTLS_MD_SHA512,
    MBEDTLS_MD_RIPEMD160
  };

  for (auto md : all_mds) {
    oc_sec_certs_md_set_signature_algorithm(md);
    EXPECT_EQ(md, oc_sec_certs_md_signature_algorithm());
  }
}

TEST_F(TestCerts, AllowedMDAlgorithms)
{
  std::vector<mbedtls_md_type_t> all_mds{
    MBEDTLS_MD_MD5,      MBEDTLS_MD_SHA1,   MBEDTLS_MD_SHA224,
    MBEDTLS_MD_SHA256,   MBEDTLS_MD_SHA384, MBEDTLS_MD_SHA512,
    MBEDTLS_MD_RIPEMD160
  };

  std::vector<mbedtls_md_type_t> ocf_mds{};
  std::vector<mbedtls_md_type_t> nonocf_mds{};
  for (const auto md : all_mds) {
    if ((MBEDTLS_X509_ID_FLAG(md) & OCF_CERTS_SUPPORTED_MDS) != 0) {
      ocf_mds.push_back(md);
    } else {
      nonocf_mds.push_back(md);
    }
  }

  // disable all
  oc_sec_certs_md_set_algorithms_allowed(MBEDTLS_MD_NONE);
  EXPECT_EQ(0, oc_sec_certs_md_algorithms_allowed());
  for (const auto md : all_mds) {
    EXPECT_FALSE(oc_sec_certs_md_algorithm_is_allowed(md));
  }

  // enable supported MDs one by one
  unsigned ocf_mask = 0;
  for (const auto md : ocf_mds) {
    ocf_mask |= MBEDTLS_X509_ID_FLAG(md);
    oc_sec_certs_md_set_algorithms_allowed(ocf_mask);
    EXPECT_TRUE(oc_sec_certs_md_algorithm_is_allowed(md));
  }

  unsigned non_ocf_mask = ocf_mask;
  // enabling unsupported MDs should not work, they should be stripped from the
  // mask, keeping only the supported MDs
  for (const auto md : nonocf_mds) {
    non_ocf_mask |= MBEDTLS_X509_ID_FLAG(md);
    oc_sec_certs_md_set_algorithms_allowed(non_ocf_mask);
    EXPECT_FALSE(oc_sec_certs_md_algorithm_is_allowed(md));
    EXPECT_EQ(ocf_mask, oc_sec_certs_md_algorithms_allowed());
  }
}

TEST_F(TestCerts, SetEllipticCurve)
{
  std::vector<mbedtls_ecp_group_id> all_ecs{
    MBEDTLS_ECP_DP_SECP192R1,  MBEDTLS_ECP_DP_SECP224R1,
    MBEDTLS_ECP_DP_SECP256R1,  MBEDTLS_ECP_DP_SECP384R1,
    MBEDTLS_ECP_DP_SECP521R1,  MBEDTLS_ECP_DP_BP256R1,
    MBEDTLS_ECP_DP_BP384R1,    MBEDTLS_ECP_DP_BP512R1,
    MBEDTLS_ECP_DP_CURVE25519, MBEDTLS_ECP_DP_SECP192K1,
    MBEDTLS_ECP_DP_SECP224K1,  MBEDTLS_ECP_DP_SECP256K1,
    MBEDTLS_ECP_DP_CURVE448,
  };

  for (auto ec : all_ecs) {
    oc_sec_certs_ecp_set_group_id(ec);
    EXPECT_EQ(ec, oc_sec_certs_ecp_group_id());
  }
}

TEST_F(TestCerts, AllowedEllipticCurves)
{
  std::vector<mbedtls_ecp_group_id> all_ecs{
    MBEDTLS_ECP_DP_SECP192R1,  MBEDTLS_ECP_DP_SECP224R1,
    MBEDTLS_ECP_DP_SECP256R1,  MBEDTLS_ECP_DP_SECP384R1,
    MBEDTLS_ECP_DP_SECP521R1,  MBEDTLS_ECP_DP_BP256R1,
    MBEDTLS_ECP_DP_BP384R1,    MBEDTLS_ECP_DP_BP512R1,
    MBEDTLS_ECP_DP_CURVE25519, MBEDTLS_ECP_DP_SECP192K1,
    MBEDTLS_ECP_DP_SECP224K1,  MBEDTLS_ECP_DP_SECP256K1,
    MBEDTLS_ECP_DP_CURVE448,
  };

  std::vector<mbedtls_ecp_group_id> ocf_ecs{};
  std::vector<mbedtls_ecp_group_id> nonocf_ecs{};
  for (const auto ec : all_ecs) {
    if ((MBEDTLS_X509_ID_FLAG(ec) & OCF_CERTS_SUPPORTED_ELLIPTIC_CURVES) != 0) {
      ocf_ecs.push_back(ec);
    } else {
      nonocf_ecs.push_back(ec);
    }
  }

  // disable all
  oc_sec_certs_ecp_set_group_ids_allowed(MBEDTLS_ECP_DP_NONE);
  EXPECT_EQ(0, oc_sec_certs_ecp_group_ids_allowed());
  for (const auto ec : all_ecs) {
    EXPECT_FALSE(oc_sec_certs_ecp_group_id_is_allowed(ec));
  }

  // enable supported elliptic curves one by one
  unsigned ocf_mask = 0;
  for (const auto ec : ocf_ecs) {
    ocf_mask |= MBEDTLS_X509_ID_FLAG(ec);
    oc_sec_certs_ecp_set_group_ids_allowed(ocf_mask);
    EXPECT_TRUE(oc_sec_certs_ecp_group_id_is_allowed(ec));
  }

  unsigned non_ocf_mask = ocf_mask;
  // enabling unsupported ECs should not work, they should be stripped from
  // the mask, keeping only the supported ECs
  for (const auto ec : nonocf_ecs) {
    non_ocf_mask |= MBEDTLS_X509_ID_FLAG(ec);
    oc_sec_certs_ecp_set_group_ids_allowed(non_ocf_mask);
    EXPECT_FALSE(oc_sec_certs_ecp_group_id_is_allowed(ec));
    EXPECT_EQ(ocf_mask, oc_sec_certs_ecp_group_ids_allowed());
  }
}

static mbedtls_asn1_buf
getMbedTLSAsn1Buffer(std::vector<unsigned char> &bytes)
{
  mbedtls_asn1_buf buf{};
  buf.p = bytes.data();
  buf.len = bytes.size();
  return buf;
}

static std::string
getUUID(const std::string &prefix = "")
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  std::array<char, OC_UUID_LEN> uuid_str{};
  oc_uuid_to_str(&uuid, uuid_str.data(), uuid_str.size());
  return prefix + uuid_str.data();
}

TEST_F(TestCerts, ExtractUUIDFromCommonNameFail)
{
  // invalid CN: empty str
  auto empty = toArray<unsigned char>("");
  std::array<char, OC_UUID_LEN> CN_uuid{};
  EXPECT_FALSE(oc_certs_parse_CN_buffer_for_UUID(
    getMbedTLSAsn1Buffer(empty), CN_uuid.data(), CN_uuid.size()));

  // invalid CN: invalid format (valid prefix, but invalid uuid string)
  auto invalid_uuid = toArray<unsigned char>("uuid:invalid");
  EXPECT_FALSE(oc_certs_parse_CN_buffer_for_UUID(
    getMbedTLSAsn1Buffer(invalid_uuid), CN_uuid.data(), CN_uuid.size()));

  // invalid CN: invalid format (missing prefix "uuid:")
  invalid_uuid = toArray<unsigned char>(getUUID());
  EXPECT_FALSE(oc_certs_parse_CN_buffer_for_UUID(
    getMbedTLSAsn1Buffer(invalid_uuid), CN_uuid.data(), CN_uuid.size()));

  // invalid CN: invalid format (invalid prefix "leet:")
  invalid_uuid = toArray<unsigned char>(getUUID("leet:"));
  EXPECT_FALSE(oc_certs_parse_CN_buffer_for_UUID(
    getMbedTLSAsn1Buffer(invalid_uuid), CN_uuid.data(), CN_uuid.size()));

  // correct format (uuid:<UUID string>), but buffer is too small
  auto valid_uuid = toArray<unsigned char>(getUUID("uuid:"));
  std::array<char, OC_UUID_LEN - 1> too_small{};
  EXPECT_FALSE(oc_certs_parse_CN_buffer_for_UUID(
    getMbedTLSAsn1Buffer(valid_uuid), too_small.data(), too_small.size()));
}

TEST_F(TestCerts, ExtractUUIDFromCommonName)
{
  std::string uuid = getUUID();
  auto uuid_encoded = toArray<unsigned char>("uuid:" + uuid);
  std::array<char, OC_UUID_LEN> CN_uuid{};
  EXPECT_TRUE(oc_certs_parse_CN_buffer_for_UUID(
    getMbedTLSAsn1Buffer(uuid_encoded), CN_uuid.data(), CN_uuid.size()));
  EXPECT_STREQ(uuid.c_str(), CN_uuid.data());

  uuid_encoded =
    toArray<unsigned char>("prefix data in the CN field, uuid:" + uuid);
  EXPECT_TRUE(oc_certs_parse_CN_buffer_for_UUID(
    getMbedTLSAsn1Buffer(uuid_encoded), CN_uuid.data(), CN_uuid.size()));
  EXPECT_STREQ(uuid.c_str(), CN_uuid.data());
}

#endif /* OC_SECURITY && OC_PKI */
