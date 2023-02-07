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

#include "oc_csr.h"
#include "security/oc_csr_internal.h"
#include "security/oc_keypair.h"
#include "tests/gtest/Device.h"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>

class TestCSR : public testing::Test {
public:
  void SetUp() override { EXPECT_TRUE(StartServer()); }

  void TearDown() override { StopServer(); }

private:
  static int AppInit()
  {
    int result = oc_init_platform("OCFCloud", nullptr, nullptr);
    result |= oc_add_device("/oic/d", "oic.d.light", "Cloud's Light",
                            "ocf.1.0.0", "ocf.res.1.0.0", nullptr, nullptr);
    return result;
  }

  static void RegisterResources()
  {
    // no-op
  }

  static void SignalEventLoop() { s_device.SignalEventLoop(); }

  static bool StartServer()
  {
    static oc_handler_t s_handler{};
    s_handler.init = AppInit;
    s_handler.signal_event_loop = SignalEventLoop;
    s_handler.register_resources = RegisterResources;

    int ret = oc_main_init(&s_handler);
    if (ret < 0) {
      s_is_device_started = false;
      return false;
    }
    s_is_device_started = true;
    s_device.PoolEventsMs(200); // give some time for everything to start-up
    return true;
  }

  static void StopServer()
  {
    s_device.Terminate();
    if (s_is_device_started) {
      oc_main_shutdown();
    }
  }

  static oc::Device s_device;
  static bool s_is_device_started;
};

oc::Device TestCSR::s_device{};
bool TestCSR::s_is_device_started{ false };

TEST_F(TestCSR, GenerateError)
{
  std::array<unsigned char, 1> too_small{};
  EXPECT_GT(0, oc_sec_csr_generate(/*device*/ -1, MBEDTLS_MD_SHA256,
                                   too_small.data(), too_small.size()))
    << "invalid device";

  EXPECT_GT(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA256,
                                   too_small.data(), too_small.size()))
    << "buffer too small";

  std::array<unsigned char, 512> csr{};
  EXPECT_GT(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_NONE, csr.data(),
                                   csr.size()))
    << "invalid message digest type";
}

TEST_F(TestCSR, GenerateMDs)
{
  std::array<unsigned char, 512> csr{};
  EXPECT_GT(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_MD5, csr.data(),
                                   csr.size()))
    << "md5 enabled";
  EXPECT_GT(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA1, csr.data(),
                                   csr.size()))
    << "sha1 enabled";
  EXPECT_GT(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_RIPEMD160,
                                   csr.data(), csr.size()))
    << "ripemd-160 enabled";

  EXPECT_EQ(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA224, csr.data(),
                                   csr.size()))
    << "sha224 disabled";
  EXPECT_EQ(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA256, csr.data(),
                                   csr.size()))
    << "sha256 disabled";
  EXPECT_EQ(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA384, csr.data(),
                                   csr.size()))
    << "sha384 disabled";
  EXPECT_EQ(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA512, csr.data(),
                                   csr.size()))
    << "sha512 disabled";
}

TEST_F(TestCSR, ValidateError)
{
  std::array<unsigned char, 512> csr{};
  EXPECT_EQ(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA224, csr.data(),
                                   csr.size()));

  EXPECT_GT(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_ECKEY,
                                   OC_CSR_SIGNATURE_MD_SHA384_FLAG |
                                     OC_CSR_SIGNATURE_MD_SHA256_FLAG,
                                   nullptr, nullptr, 0))
    << "sha224 signature not supported";
}

TEST_F(TestCSR, Validate256)
{
  std::array<unsigned char, 512> csr{};
  EXPECT_EQ(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA256, csr.data(),
                                   csr.size()));

  EXPECT_GT(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_OPAQUE,
                                   OC_CSR_SIGNATURE_MD_SHA256_FLAG, nullptr,
                                   nullptr, 0))
    << "unexpected public key type";

  std::array<unsigned char, 1> too_small{};
  EXPECT_GT(0, oc_sec_csr_validate(
                 too_small.data(), too_small.size(), MBEDTLS_PK_ECKEY,
                 OC_CSR_SIGNATURE_MD_SHA256_FLAG, nullptr, nullptr, 0))
    << "buffer too small";

  EXPECT_GT(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_ECKEY,
                                   OC_CSR_SIGNATURE_MD_SHA384_FLAG, nullptr,
                                   nullptr, 0))
    << "wrong signature type";

  EXPECT_EQ(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_ECKEY,
                                   OC_CSR_SIGNATURE_MD_SHA256_FLAG, nullptr,
                                   nullptr, 0));

  oc_string_t subject{};
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> pk{};
  EXPECT_EQ(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_ECKEY,
                                   OC_CSR_SIGNATURE_MD_SHA256_FLAG |
                                     OC_CSR_SIGNATURE_MD_SHA384_FLAG,
                                   &subject, pk.data(), pk.size()));
  EXPECT_LT(0, oc_string_len(subject));
  OC_DBG("Subject: %s", oc_string(subject));
  oc_free_string(&subject);
}

TEST_F(TestCSR, Validate384)
{
  std::array<unsigned char, 512> csr{};
  EXPECT_EQ(0, oc_sec_csr_generate(/*device*/ 0, MBEDTLS_MD_SHA384, csr.data(),
                                   csr.size()));

  EXPECT_GT(0, oc_sec_csr_validate(
                 csr.data(), csr.size(), MBEDTLS_PK_RSASSA_PSS,
                 OC_CSR_SIGNATURE_MD_SHA384_FLAG, nullptr, nullptr, 0))
    << "unexpected public key type";

  std::array<unsigned char, 1> too_small{};
  EXPECT_GT(0, oc_sec_csr_validate(
                 too_small.data(), too_small.size(), MBEDTLS_PK_ECKEY,
                 OC_CSR_SIGNATURE_MD_SHA384_FLAG, nullptr, nullptr, 0))
    << "buffer too small";

  EXPECT_GT(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_ECKEY,
                                   OC_CSR_SIGNATURE_MD_SHA256_FLAG, nullptr,
                                   nullptr, 0))
    << "wrong signature type";

  EXPECT_EQ(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_ECKEY,
                                   OC_CSR_SIGNATURE_MD_SHA384_FLAG, nullptr,
                                   nullptr, 0));

  oc_string_t subject{};
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> pk{};
  EXPECT_EQ(0, oc_sec_csr_validate(csr.data(), csr.size(), MBEDTLS_PK_ECKEY,
                                   OC_CSR_SIGNATURE_MD_SHA256_FLAG |
                                     OC_CSR_SIGNATURE_MD_SHA384_FLAG,
                                   &subject, pk.data(), pk.size()));
  EXPECT_LT(0, oc_string_len(subject));
  OC_DBG("Subject: %s", oc_string(subject));
  oc_free_string(&subject);
}

#endif /* OC_SECURITY && OC_PKI */
