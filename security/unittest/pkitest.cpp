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

#include "oc_pki.h"
#include "oc_config.h"
#include "security/oc_pki_internal.h"

#include <stdbool.h>
#include <gtest/gtest.h>

class TestPKIPK : public testing::Test {
public:
  void SetUp() override
  {
    pk_free_key_invoked = false;
    pk_gen_key_invoked = false;
    pk_write_key_der_invoked = false;
    pk_parse_key_invoked = false;
  }

  void TearDown() override { oc_pki_set_pk_functions(nullptr); }

  static bool PKFreeKey(size_t /*device*/, const unsigned char * /*key*/,
                        size_t /*keylen*/)
  {
    pk_free_key_invoked = true;
    return true;
  }
  static int MbedtlsPKEcpGenKey(
    size_t /*device*/, mbedtls_ecp_group_id /*grp_id*/,
    mbedtls_pk_context * /*pk*/,
    int (* /*f_rng*/)(void *, unsigned char *, size_t), void * /*p_rng*/)
  {
    pk_gen_key_invoked = true;
    return 0;
  }
  static int MbedtlsPKWriteKeyDer(size_t /*device*/,
                                  const mbedtls_pk_context * /*pk*/,
                                  unsigned char * /*buf*/, size_t /*size*/)
  {
    pk_write_key_der_invoked = true;
    return 0;
  }
  static int MbedtlsPKParseKey(size_t /*device*/, mbedtls_pk_context * /*pk*/,
                               const unsigned char * /*key*/, size_t /*keylen*/,
                               const unsigned char * /*pwd*/, size_t /*pwdlen*/,
                               int (* /*f_rng*/)(void *, unsigned char *,
                                                 size_t),
                               void * /*p_rng*/)
  {
    pk_parse_key_invoked = true;
    return 0;
  }

  static oc_pki_pk_functions_t GetPKFunctions()
  {
    oc_pki_pk_functions_t pk_functions;
    pk_functions.mbedtls_pk_parse_key = MbedtlsPKParseKey;
    pk_functions.mbedtls_pk_write_key_der = MbedtlsPKWriteKeyDer;
    pk_functions.mbedtls_pk_ecp_gen_key = MbedtlsPKEcpGenKey;
    pk_functions.pk_free_key = PKFreeKey;
    return pk_functions;
  }

  static bool pk_free_key_invoked;
  static bool pk_gen_key_invoked;
  static bool pk_write_key_der_invoked;
  static bool pk_parse_key_invoked;
};

bool TestPKIPK::pk_free_key_invoked = false;
bool TestPKIPK::pk_gen_key_invoked = false;
bool TestPKIPK::pk_write_key_der_invoked = false;
bool TestPKIPK::pk_parse_key_invoked = false;

TEST_F(TestPKIPK, pk_functions)
{
  EXPECT_TRUE(oc_pki_set_pk_functions(nullptr));
  EXPECT_FALSE(oc_pki_get_pk_functions(nullptr));
  oc_pki_pk_functions_t pk_functions = GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  EXPECT_TRUE(oc_pki_get_pk_functions(nullptr));
  pk_functions.mbedtls_pk_parse_key = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));
  pk_functions.mbedtls_pk_parse_key = MbedtlsPKParseKey;
  pk_functions.mbedtls_pk_write_key_der = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));
  pk_functions.mbedtls_pk_write_key_der = MbedtlsPKWriteKeyDer;
  pk_functions.mbedtls_pk_ecp_gen_key = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));
  pk_functions.mbedtls_pk_ecp_gen_key = MbedtlsPKEcpGenKey;
  pk_functions.pk_free_key = nullptr;
  EXPECT_FALSE(oc_pki_set_pk_functions(&pk_functions));

  oc_pki_pk_functions_t get_pk_functions{};
  EXPECT_TRUE(oc_pki_get_pk_functions(&get_pk_functions));
  EXPECT_EQ(get_pk_functions.mbedtls_pk_parse_key, &MbedtlsPKParseKey);
  EXPECT_EQ(get_pk_functions.mbedtls_pk_write_key_der, &MbedtlsPKWriteKeyDer);
  EXPECT_EQ(get_pk_functions.mbedtls_pk_ecp_gen_key, &MbedtlsPKEcpGenKey);
  EXPECT_EQ(get_pk_functions.pk_free_key, &PKFreeKey);
}

TEST_F(TestPKIPK, pk_free_key)
{
  oc_pki_pk_functions_t pk_functions = GetPKFunctions();
  EXPECT_FALSE(oc_pk_free_key(0, nullptr, 0));
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  EXPECT_TRUE(oc_pk_free_key(0, nullptr, 0));
  EXPECT_TRUE(pk_free_key_invoked);
}

TEST_F(TestPKIPK, pk_gen_key)
{
  oc_pki_pk_functions_t pk_functions = GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  oc_mbedtls_pk_ecp_gen_key(0, MBEDTLS_ECP_DP_SECP256R1, nullptr, nullptr,
                            nullptr);
  EXPECT_TRUE(pk_gen_key_invoked);
}

TEST_F(TestPKIPK, pk_write_key_der)
{
  oc_pki_pk_functions_t pk_functions = GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  oc_mbedtls_pk_write_key_der(0, nullptr, nullptr, 0);
  EXPECT_TRUE(pk_write_key_der_invoked);
}

TEST_F(TestPKIPK, pk_parse_key)
{
  oc_pki_pk_functions_t pk_functions = GetPKFunctions();
  EXPECT_TRUE(oc_pki_set_pk_functions(&pk_functions));
  oc_mbedtls_pk_parse_key(0, nullptr, nullptr, 0, nullptr, 0, nullptr, nullptr);
  EXPECT_TRUE(pk_parse_key_invoked);
}

#endif /* OC_SECURITY && OC_PKI */