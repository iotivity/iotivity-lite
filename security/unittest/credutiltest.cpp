/******************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
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

#ifdef OC_SECURITY

#include "oc_cred.h"
#include "oc_helpers.h"
#include "port/oc_random.h"
#include "security/oc_cred_internal.h"
#include "security/oc_cred_util_internal.h"
#include "tests/gtest/Utility.h"
#include "util/oc_macros_internal.h"
#include "util/oc_mmem_internal.h"

#include <array>
#include <gtest/gtest.h>
#include <limits>
#include <string>
#include <vector>

class TestCredUtil : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }
  static void TearDownTestCase() { oc_random_destroy(); }
};

TEST_F(TestCredUtil, DataIsEqualToEncodedData)
{
  oc_cred_data_t cd_null{};
  oc_sec_encoded_data_t sed_null{};
  cd_null.encoding = OC_ENCODING_PEM;
  sed_null.encoding = OC_ENCODING_PEM;
  EXPECT_TRUE(oc_cred_data_is_equal_to_encoded_data(cd_null, sed_null));
  cd_null.encoding = OC_ENCODING_RAW;
  sed_null.encoding = OC_ENCODING_RAW;
  EXPECT_TRUE(oc_cred_data_is_equal_to_encoded_data(cd_null, sed_null));

  std::string data1{ "leet" };
  oc_cred_data_t cd1{ OC_MMEM(data1.data(), data1.length() + 1, nullptr),
                      OC_ENCODING_PEM };
  oc_sec_encoded_data_t sed1{ (const uint8_t *)data1.data(), data1.length(),
                              OC_ENCODING_PEM };
  EXPECT_TRUE(oc_cred_data_is_equal_to_encoded_data(cd1, sed1));

  EXPECT_FALSE(oc_cred_data_is_equal_to_encoded_data(cd_null, sed1));
  EXPECT_FALSE(oc_cred_data_is_equal_to_encoded_data(cd1, sed_null));

  std::string data2{ "aaaa" };
  oc_cred_data_t cd2{ OC_MMEM(data2.data(), data2.length() + 1, nullptr),
                      OC_ENCODING_PEM };
  oc_sec_encoded_data_t sed2{ (const uint8_t *)data2.data(), data2.length(),
                              OC_ENCODING_PEM };
  EXPECT_FALSE(oc_cred_data_is_equal_to_encoded_data(cd2, sed1));
  EXPECT_FALSE(oc_cred_data_is_equal_to_encoded_data(cd1, sed2));

  std::string data3{ "42" };
  oc_cred_data_t cd3{ OC_MMEM(data3.data(), data3.length() + 1, nullptr),
                      OC_ENCODING_PEM };
  oc_sec_encoded_data_t sed3{ (const uint8_t *)data3.data(), data3.length(),
                              OC_ENCODING_PEM };
  EXPECT_FALSE(oc_cred_data_is_equal_to_encoded_data(cd3, sed1));
  EXPECT_FALSE(oc_cred_data_is_equal_to_encoded_data(cd2, sed3));
}

TEST_F(TestCredUtil, HasTag)
{
  oc_sec_cred_t cred_null{};
  EXPECT_TRUE(oc_cred_has_tag(&cred_null, OC_STRING_VIEW_NULL));
  EXPECT_TRUE(oc_cred_has_tag(&cred_null, oc_string_view("", 0)));

  std::string tag1{ "tag" };
  std::string tag2{ "xxx" };
  EXPECT_FALSE(
    oc_cred_has_tag(&cred_null, oc_string_view(tag1.data(), tag1.length())));
  EXPECT_FALSE(
    oc_cred_has_tag(&cred_null, oc_string_view(tag2.data(), tag2.length())));

  oc_sec_cred_t cred1{};
  cred1.tag = OC_MMEM(&tag1[0], tag1.length() + 1, nullptr);
  EXPECT_TRUE(oc_cred_has_tag(&cred1, oc_string_view2(&cred1.tag)));
  EXPECT_FALSE(oc_cred_has_tag(&cred1, OC_STRING_VIEW_NULL));
  EXPECT_FALSE(
    oc_cred_has_tag(&cred1, oc_string_view(tag2.data(), tag2.length())));
}

TEST_F(TestCredUtil, IsDuplicate)
{
  oc_sec_cred_t cred{};
  cred.credtype = OC_CREDTYPE_CERT;
  oc_gen_uuid(&cred.subjectuuid);
  std::string credtag{ "tag1" };
  cred.tag = OC_MMEM(&credtag[0], credtag.length() + 1, nullptr);

  auto creddata = oc::GetVector<uint8_t>("leet", true);
  cred.privatedata = { OC_MMEM(creddata.data(), creddata.size(), nullptr),
                       OC_ENCODING_PEM };
  oc_sec_encoded_data_t credprivatedata{ creddata.data(), creddata.size() - 1,
                                         OC_ENCODING_PEM };
#ifdef OC_PKI
  auto credpublicdata = oc::GetVector<uint8_t>("based");
  cred.publicdata = { OC_MMEM(credpublicdata.data(), credpublicdata.size(),
                              nullptr),
                      OC_ENCODING_RAW };
  oc_sec_encoded_data_t publicdata{ credpublicdata.data(),
                                    credpublicdata.size(), OC_ENCODING_RAW };
  oc_sec_credusage_t credusage = OC_CREDUSAGE_IDENTITY_CERT;
  cred.credusage = credusage;
#else  /* !OC_PKI */
  oc_sec_encoded_data_t publicdata{};
  oc_sec_credusage_t credusage{};
#endif /* OC_PKI */

  EXPECT_TRUE(oc_cred_is_duplicate(&cred, cred.credtype, cred.subjectuuid,
                                   oc_string_view2(&cred.tag), credprivatedata,
                                   publicdata, credusage));

  oc_sec_credtype_t credtype = OC_CREDTYPE_PSK;
  ASSERT_NE(cred.credtype, credtype);
  EXPECT_FALSE(oc_cred_is_duplicate(&cred, OC_CREDTYPE_PSK, cred.subjectuuid,
                                    oc_string_view2(&cred.tag), credprivatedata,
                                    publicdata, credusage));
  oc_uuid_t subjectuuid{};
  subjectuuid.id[0] = '*';
  ASSERT_FALSE(oc_uuid_is_equal(cred.subjectuuid, subjectuuid));
  EXPECT_FALSE(oc_cred_is_duplicate(&cred, cred.credtype, subjectuuid,
                                    oc_string_view2(&cred.tag), credprivatedata,
                                    publicdata, credusage));

  std::string tag{ "tag2" };
  EXPECT_FALSE(oc_cred_is_duplicate(&cred, cred.credtype, cred.subjectuuid,
                                    oc_string_view(tag.c_str(), tag.length()),
                                    credprivatedata, publicdata, credusage));

  auto data = oc::GetVector<uint8_t>("42", true);
  oc_sec_encoded_data_t sedData{ data.data(), data.size() - 1,
                                 OC_ENCODING_PEM };
  EXPECT_FALSE(oc_cred_is_duplicate(&cred, cred.credtype, cred.subjectuuid,
                                    oc_string_view2(&cred.tag), sedData,
                                    publicdata, credusage));

#ifdef OC_PKI
  EXPECT_FALSE(oc_cred_is_duplicate(&cred, cred.credtype, cred.subjectuuid,
                                    oc_string_view2(&cred.tag), credprivatedata,
                                    sedData, credusage));

  oc_sec_credusage_t usage = OC_CREDUSAGE_MFG_CERT;
  EXPECT_FALSE(oc_cred_is_duplicate(&cred, cred.credtype, cred.subjectuuid,
                                    oc_string_view2(&cred.tag), credprivatedata,
                                    publicdata, usage));
#endif /* OC_PKI */
}

TEST_F(TestCredUtil, SetSubject)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  std::array<char, OC_UUID_LEN> uuid_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid, &uuid_str[0], uuid_str.size()));

  oc_uuid_t subject{};
  ASSERT_TRUE(oc_sec_cred_set_subject(uuid_str.data(),
                                      OC_CREDUSAGE_IDENTITY_CERT, &subject));
  EXPECT_TRUE(oc_uuid_is_equal(uuid, subject));

  subject = {};
  ASSERT_TRUE(oc_sec_cred_set_subject("*", OC_CREDUSAGE_TRUSTCA, &subject));
  EXPECT_EQ('*', subject.id[0]);
}

TEST_F(TestCredUtil, SetNullSubject)
{
  oc_uuid_t subject{};
  EXPECT_FALSE(oc_sec_cred_set_subject(nullptr, OC_CREDUSAGE_NULL, &subject));
  EXPECT_FALSE(
    oc_sec_cred_set_subject(nullptr, OC_CREDUSAGE_IDENTITY_CERT, &subject));
  EXPECT_FALSE(
    oc_sec_cred_set_subject(nullptr, OC_CREDUSAGE_MFG_TRUSTCA, &subject));
  EXPECT_FALSE(
    oc_sec_cred_set_subject(nullptr, OC_CREDUSAGE_MFG_CERT, &subject));

  EXPECT_TRUE(
    oc_sec_cred_set_subject(nullptr, OC_CREDUSAGE_ROLE_CERT, &subject));
  EXPECT_EQ('*', subject.id[0]);
}

TEST_F(TestCredUtil, CredTypeString)
{
  std::vector<oc_sec_credtype_t> credtypes{
    OC_CREDTYPE_NULL,
    OC_CREDTYPE_PSK,
    OC_CREDTYPE_CERT,
    OC_CREDTYPE_OSCORE,
    OC_CREDTYPE_OSCORE_MCAST_CLIENT,
    OC_CREDTYPE_OSCORE_MCAST_SERVER,
  };
  std::vector<std::string> credtypesStrings{
    "Unknown", OC_CREDTYPE_PSK_STR, OC_CREDTYPE_CERT_STR,
    "Unknown", "Unknown",           "Unknown",
  };

  for (size_t i = 0; i < credtypes.size(); ++i) {
    EXPECT_STREQ(credtypesStrings[i].c_str(),
                 oc_cred_credtype_string(credtypes[i]));
  }

  EXPECT_STREQ("Unknown", oc_cred_credtype_string(
                            std::numeric_limits<oc_sec_credtype_t>::max()));
}

TEST_F(TestCredUtil, ParseEncoding)
{
  std::vector<oc_sec_encoding_t> encodings{
    OC_ENCODING_BASE64,
    OC_ENCODING_RAW,
#ifdef OC_PKI
    OC_ENCODING_PEM,
#endif /* OC_PKI */
    OC_ENCODING_HANDLE,
  };
  std::vector<std::string> encStrings{
    OC_ENCODING_BASE64_STR,
    OC_ENCODING_RAW_STR,
#ifdef OC_PKI
    OC_ENCODING_PEM_STR,
#endif /* OC_PKI */
    OC_ENCODING_HANDLE_STR,
  };

  oc_string_t enc{};
  for (size_t i = 0; i < encodings.size(); ++i) {
    std::string encoding = encStrings[i];
    oc_set_string(&enc, encoding.c_str(), encoding.length());
    EXPECT_EQ(encodings[i], oc_cred_parse_encoding(&enc));
  }

  oc_set_string(&enc, nullptr, 0);
  EXPECT_EQ(OC_ENCODING_UNSUPPORTED, oc_cred_parse_encoding(&enc));
  std::string invalid{};
  oc_set_string(&enc, invalid.c_str(), invalid.length());
  EXPECT_EQ(OC_ENCODING_UNSUPPORTED, oc_cred_parse_encoding(&enc));
  invalid = "invalid";
  oc_set_string(&enc, invalid.c_str(), invalid.length());
  EXPECT_EQ(OC_ENCODING_UNSUPPORTED, oc_cred_parse_encoding(&enc));

  oc_free_string(&enc);
}

TEST_F(TestCredUtil, ReadEncoding)
{
  std::vector<oc_sec_encoding_t> encodings{
    OC_ENCODING_BASE64,
    OC_ENCODING_RAW,
#ifdef OC_PKI
    OC_ENCODING_PEM,
#endif /* OC_PKI */
    OC_ENCODING_HANDLE,
  };
  std::vector<std::string> encStrings{
    OC_ENCODING_BASE64_STR,
    OC_ENCODING_RAW_STR,
#ifdef OC_PKI
    OC_ENCODING_PEM_STR,
#endif /* OC_PKI */
    OC_ENCODING_HANDLE_STR,
  };
  for (size_t i = 0; i < encodings.size(); ++i) {
    EXPECT_STREQ(encStrings[i].c_str(), oc_cred_read_encoding(encodings[i]));
  }

  EXPECT_STREQ("Unknown", oc_cred_read_encoding(
                            std::numeric_limits<oc_sec_encoding_t>::max()));
}

#ifdef OC_PKI

TEST_F(TestCredUtil, ParseCredUsage)
{
  std::vector<oc_sec_credusage_t> usages{
    OC_CREDUSAGE_TRUSTCA,   OC_CREDUSAGE_IDENTITY_CERT,
    OC_CREDUSAGE_ROLE_CERT, OC_CREDUSAGE_MFG_TRUSTCA,
    OC_CREDUSAGE_MFG_CERT,
  };
  std::vector<std::string> usageStrings{
    OC_CREDUSAGE_TRUSTCA_STR,   OC_CREDUSAGE_IDENTITY_CERT_STR,
    OC_CREDUSAGE_ROLE_CERT_STR, OC_CREDUSAGE_MFG_TRUSTCA_STR,
    OC_CREDUSAGE_MFG_CERT_STR,
  };

  oc_string_t usage{};
  for (size_t i = 0; i < usageStrings.size(); ++i) {
    oc_set_string(&usage, usageStrings[i].c_str(), usageStrings[i].length());
    EXPECT_EQ(usages[i], oc_cred_parse_credusage(&usage));
  }

  oc_set_string(&usage, nullptr, 0);
  EXPECT_EQ(OC_CREDUSAGE_NULL, oc_cred_parse_credusage(&usage));
  std::string invalid = "";
  oc_set_string(&usage, invalid.c_str(), invalid.length());
  EXPECT_EQ(OC_CREDUSAGE_NULL, oc_cred_parse_credusage(&usage));
  invalid = "invalid";
  oc_set_string(&usage, invalid.c_str(), invalid.length());
  EXPECT_EQ(OC_CREDUSAGE_NULL, oc_cred_parse_credusage(&usage));

  oc_free_string(&usage);
}

TEST_F(TestCredUtil, ReadCredUsage)
{
  std::vector<oc_sec_credusage_t> usages{
    OC_CREDUSAGE_TRUSTCA,   OC_CREDUSAGE_IDENTITY_CERT,
    OC_CREDUSAGE_ROLE_CERT, OC_CREDUSAGE_MFG_TRUSTCA,
    OC_CREDUSAGE_MFG_CERT,
  };
  std::vector<std::string> usageStrings{
    OC_CREDUSAGE_TRUSTCA_STR,   OC_CREDUSAGE_IDENTITY_CERT_STR,
    OC_CREDUSAGE_ROLE_CERT_STR, OC_CREDUSAGE_MFG_TRUSTCA_STR,
    OC_CREDUSAGE_MFG_CERT_STR,
  };

  for (size_t i = 0; i < usages.size(); ++i) {
    EXPECT_STREQ(usageStrings[i].c_str(), oc_cred_read_credusage(usages[i]));
  }

  EXPECT_STREQ("None", oc_cred_read_credusage(OC_CREDUSAGE_NULL));
  EXPECT_STREQ("None", oc_cred_read_credusage(
                         std::numeric_limits<oc_sec_credusage_t>::max()));
}

#endif /* OC_PKI */

#endif /* OC_SECURITY */
