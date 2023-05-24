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
#include "security/oc_cred_internal.h"
#include "util/oc_macros_internal.h"

#include <gtest/gtest.h>

class TestCred : public testing::Test {};

TEST_F(TestCred, ParseEncoding)
{
  oc_string_t enc{};
  oc_set_string(&enc, "", 0);
  EXPECT_EQ(OC_ENCODING_UNSUPPORTED, oc_cred_parse_encoding(&enc));

  oc_set_string(&enc, OC_ENCODING_BASE64_STR,
                OC_CHAR_ARRAY_LEN(OC_ENCODING_BASE64_STR));
  EXPECT_EQ(OC_ENCODING_BASE64, oc_cred_parse_encoding(&enc));

  oc_set_string(&enc, OC_ENCODING_RAW_STR,
                OC_CHAR_ARRAY_LEN(OC_ENCODING_RAW_STR));
  EXPECT_EQ(OC_ENCODING_RAW, oc_cred_parse_encoding(&enc));

  oc_set_string(&enc, OC_ENCODING_HANDLE_STR,
                OC_CHAR_ARRAY_LEN(OC_ENCODING_HANDLE_STR));
  EXPECT_EQ(OC_ENCODING_HANDLE, oc_cred_parse_encoding(&enc));

#ifdef OC_PKI
  oc_set_string(&enc, OC_ENCODING_PEM_STR,
                OC_CHAR_ARRAY_LEN(OC_ENCODING_PEM_STR));
  EXPECT_EQ(OC_ENCODING_PEM, oc_cred_parse_encoding(&enc));
#endif /* OC_PKI */

  oc_free_string(&enc);
}

TEST_F(TestCred, ReadEncoding)
{
  EXPECT_STREQ(OC_ENCODING_BASE64_STR,
               oc_cred_read_encoding(OC_ENCODING_BASE64));
  EXPECT_STREQ(OC_ENCODING_RAW_STR, oc_cred_read_encoding(OC_ENCODING_RAW));
  EXPECT_STREQ(OC_ENCODING_HANDLE_STR,
               oc_cred_read_encoding(OC_ENCODING_HANDLE));
#ifdef OC_PKI
  EXPECT_STREQ(OC_ENCODING_PEM_STR, oc_cred_read_encoding(OC_ENCODING_PEM));
#endif /* OC_PKI */
}

#ifdef OC_PKI

TEST_F(TestCred, ParseCredUsage)
{
  oc_string_t usage{};
  oc_set_string(&usage, "", 0);
  EXPECT_EQ(OC_CREDUSAGE_NULL, oc_cred_parse_credusage(&usage));

  oc_set_string(&usage, OC_CREDUSAGE_TRUSTCA_STR,
                OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_TRUSTCA_STR));
  EXPECT_EQ(OC_CREDUSAGE_TRUSTCA, oc_cred_parse_credusage(&usage));

  oc_set_string(&usage, OC_CREDUSAGE_IDENTITY_CERT_STR,
                OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_IDENTITY_CERT_STR));
  EXPECT_EQ(OC_CREDUSAGE_IDENTITY_CERT, oc_cred_parse_credusage(&usage));

  oc_set_string(&usage, OC_CREDUSAGE_ROLE_CERT_STR,
                OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_ROLE_CERT_STR));
  EXPECT_EQ(OC_CREDUSAGE_ROLE_CERT, oc_cred_parse_credusage(&usage));

  oc_set_string(&usage, OC_CREDUSAGE_MFG_TRUSTCA_STR,
                OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_MFG_TRUSTCA_STR));
  EXPECT_EQ(OC_CREDUSAGE_MFG_TRUSTCA, oc_cred_parse_credusage(&usage));

  oc_set_string(&usage, OC_CREDUSAGE_MFG_CERT_STR,
                OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_MFG_CERT_STR));
  EXPECT_EQ(OC_CREDUSAGE_MFG_CERT, oc_cred_parse_credusage(&usage));

  oc_free_string(&usage);
}

TEST_F(TestCred, ReadCredUsage)
{
  EXPECT_STREQ(OC_CREDUSAGE_TRUSTCA_STR,
               oc_cred_read_credusage(OC_CREDUSAGE_TRUSTCA));
  EXPECT_STREQ(OC_CREDUSAGE_IDENTITY_CERT_STR,
               oc_cred_read_credusage(OC_CREDUSAGE_IDENTITY_CERT));
  EXPECT_STREQ(OC_CREDUSAGE_ROLE_CERT_STR,
               oc_cred_read_credusage(OC_CREDUSAGE_ROLE_CERT));
  EXPECT_STREQ(OC_CREDUSAGE_MFG_TRUSTCA_STR,
               oc_cred_read_credusage(OC_CREDUSAGE_MFG_TRUSTCA));
  EXPECT_STREQ(OC_CREDUSAGE_MFG_CERT_STR,
               oc_cred_read_credusage(OC_CREDUSAGE_MFG_CERT));
}

#endif /* OC_PKI */

#endif /* OC_SECURITY */
