/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING

#include "api/oc_runtime_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_internal.h"

#include "gtest/gtest.h"

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

static constexpr size_t kDeviceID = 0;

class TestDPSWithContext : public testing::Test {
protected:
  void SetUp() override
  {
    oc_runtime_init();
    memset(ctx_.get(), 0, sizeof(plgd_dps_context_t));
    dps_context_init(ctx_.get(), kDeviceID);
  }
  void TearDown() override
  {
    dps_context_deinit(ctx_.get());
    oc_runtime_shutdown();
  }

public:
  std::unique_ptr<plgd_dps_context_t> ctx_{
    std::make_unique<plgd_dps_context_t>()
  };
};

TEST_F(TestDPSWithContext, HasForcedReprovision)
{
  EXPECT_FALSE(plgd_dps_has_forced_reprovision(ctx_.get()));

  plgd_dps_force_reprovision(ctx_.get());
  EXPECT_TRUE(plgd_dps_has_forced_reprovision(ctx_.get()));
}

TEST_F(TestDPSWithContext, HasBeenProvisionedSinceReset)
{
  EXPECT_FALSE(plgd_dps_has_been_provisioned_since_reset(ctx_.get()));

  dps_set_has_been_provisioned_since_reset(ctx_.get(), /*dump*/ false);
  EXPECT_TRUE(plgd_dps_has_been_provisioned_since_reset(ctx_.get()));
}

TEST_F(TestDPSWithContext, GetProvisionStatus)
{
  EXPECT_EQ(0, plgd_dps_get_provision_status(ctx_.get()));

  dps_set_ps_and_last_error(ctx_.get(), PLGD_DPS_INITIALIZED, 0, PLGD_DPS_OK);
  EXPECT_EQ(PLGD_DPS_INITIALIZED, plgd_dps_get_provision_status(ctx_.get()));
}

TEST_F(TestDPSWithContext, GetLastError)
{
  EXPECT_EQ(PLGD_DPS_OK, plgd_dps_get_last_error(ctx_.get()));

  dps_set_last_error(ctx_.get(), PLGD_DPS_ERROR_CONNECT);
  EXPECT_EQ(PLGD_DPS_ERROR_CONNECT, plgd_dps_get_last_error(ctx_.get()));
}

TEST_F(TestDPSWithContext, SetCloudObserver)
{
  plgd_cloud_status_observer_configuration_t cfg =
    plgd_dps_get_cloud_observer_configuration(ctx_.get());
  EXPECT_EQ(30, cfg.max_count);
  EXPECT_EQ(1, cfg.interval_s);

  EXPECT_FALSE(plgd_dps_set_cloud_observer_configuration(
    ctx_.get(), /*max_retry_count*/ 0, /*retry_interval_s*/ 0));
  cfg = plgd_dps_get_cloud_observer_configuration(ctx_.get());
  EXPECT_EQ(30, cfg.max_count);
  EXPECT_EQ(1, cfg.interval_s);

  EXPECT_TRUE(plgd_dps_set_cloud_observer_configuration(
    ctx_.get(), /*max_retry_count*/ 13, /*retry_interval_s*/ 37));
  cfg = plgd_dps_get_cloud_observer_configuration(ctx_.get());
  EXPECT_EQ(13, cfg.max_count);
  EXPECT_EQ(37, cfg.interval_s);
}

TEST_F(TestDPSWithContext, SetExpiringLimit)
{
  const uint16_t expiresIn = 1337;
  plgd_dps_pki_set_expiring_limit(ctx_.get(), expiresIn);
  EXPECT_EQ(expiresIn, plgd_dps_pki_get_expiring_limit(ctx_.get()));
}

TEST_F(TestDPSWithContext, SetEndpoint)
{
  std::array<char, 256> buffer{ '\0' };
  EXPECT_EQ(0, plgd_dps_get_endpoint(ctx_.get(), buffer.data(), buffer.size()));

  const char endpoint[] = "coaps+tcp://plgd.cloud:25684";
#ifndef OC_DYNAMIC_ALLOCATION
  ASSERT_GE(OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH,
            std::string(endpoint).length());
#endif /* OC_DYNAMIC_ALLOCATION */

  plgd_dps_set_endpoint(ctx_.get(), endpoint);
  std::array<char, 10> too_small{ '\0' };
  EXPECT_GT(
    0, plgd_dps_get_endpoint(ctx_.get(), too_small.data(), too_small.size()));

  size_t s = plgd_dps_get_endpoint(ctx_.get(), buffer.data(), buffer.size());
  EXPECT_EQ(sizeof(endpoint), s);
  EXPECT_STREQ(endpoint, buffer.data());
}

TEST_F(TestDPSWithContext, SetRetry)
{
  EXPECT_FALSE(plgd_dps_set_retry_configuration(ctx_.get(), nullptr, 0));
  std::vector<uint8_t> empty{};
  EXPECT_FALSE(
    plgd_dps_set_retry_configuration(ctx_.get(), empty.data(), empty.size()));
  std::array<uint8_t, PLGD_DPS_MAX_RETRY_VALUES_SIZE + 1> too_large;
  EXPECT_FALSE(plgd_dps_set_retry_configuration(ctx_.get(), too_large.data(),
                                                too_large.size()));
  std::array<uint8_t, PLGD_DPS_MAX_RETRY_VALUES_SIZE> empty_values = { 0 };
  EXPECT_FALSE(plgd_dps_set_retry_configuration(ctx_.get(), empty_values.data(),
                                                empty_values.size()));

  std::array<uint8_t, 5> arr{ 1, 2, 3, 4, 5 };
  EXPECT_TRUE(
    plgd_dps_set_retry_configuration(ctx_.get(), arr.data(), arr.size()));
  std::array<uint8_t, 4> too_small;
  size_t cfg_size = plgs_dps_get_retry_configuration(
    ctx_.get(), too_small.data(), too_small.size());
  EXPECT_EQ(-1, cfg_size);

  std::array<uint8_t, PLGD_DPS_MAX_RETRY_VALUES_SIZE> buffer{ 0 };
  auto EXPECT_ARR_EQ = [](const uint8_t *arr1, const uint8_t *arr2,
                          size_t size) {
    for (size_t i = 0; i < size; ++i) {
      EXPECT_EQ(arr1[i], arr2[i])
        << "Arrays differ at index " << i << " (" << (int)arr1[i] << " vs "
        << (int)arr2[i] << ")";
    }
  };
  std::array<uint8_t, 1> single{ 1 };
  EXPECT_TRUE(
    plgd_dps_set_retry_configuration(ctx_.get(), single.data(), single.size()));
  cfg_size =
    plgs_dps_get_retry_configuration(ctx_.get(), buffer.data(), buffer.size());
  EXPECT_EQ(single.size(), cfg_size);
  EXPECT_ARR_EQ(single.data(), buffer.data(), cfg_size);

  std::array<uint8_t, 8> full{ 1, 2, 3, 4, 5, 6, 7, 8 };
  EXPECT_TRUE(
    plgd_dps_set_retry_configuration(ctx_.get(), full.data(), full.size()));
  cfg_size =
    plgs_dps_get_retry_configuration(ctx_.get(), buffer.data(), buffer.size());
  EXPECT_EQ(full.size(), cfg_size);
  EXPECT_ARR_EQ(full.data(), buffer.data(), cfg_size);
}

TEST_F(TestDPSWithContext, SetScheduleAction)
{
  bool cbk_called = false;
  auto cbk = [](plgd_dps_context_t *, plgd_dps_status_t, uint8_t, uint64_t *,
                uint16_t *, void *user_data) {
    auto called = static_cast<bool *>(user_data);
    *called = true;
    return false;
  };
  plgd_dps_set_schedule_action(ctx_.get(), cbk, &cbk_called);
  dps_retry_increment(ctx_.get(), PLGD_DPS_GET_CREDENTIALS);
  EXPECT_EQ(0, ctx_.get()->retry.count);
  EXPECT_TRUE(cbk_called);
  plgd_dps_set_schedule_action(ctx_.get(), nullptr, nullptr);
}

TEST_F(TestDPSWithContext, SetCertificateFingerprint)
{
  // no fingerprint set
  std::array<uint8_t, 32> fingerprint_ok{ '\0' };
  mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
  EXPECT_EQ(0, plgd_dps_get_certificate_fingerprint(ctx_.get(), &md_type,
                                                    &fingerprint_ok[0],
                                                    fingerprint_ok.size()));

  EXPECT_EQ(true, plgd_dps_set_certificate_fingerprint(
                    ctx_.get(), MBEDTLS_MD_NONE, nullptr, 0));

  std::array<uint8_t, 32> fingerprint = {
    (uint8_t)0xB8, (uint8_t)0xF5, (uint8_t)0xBA, (uint8_t)0x0D, (uint8_t)0x9F,
    (uint8_t)0x6D, (uint8_t)0x4D, (uint8_t)0xEF, (uint8_t)0x3F, (uint8_t)0x82,
    (uint8_t)0x28, (uint8_t)0xD2, (uint8_t)0x5F, (uint8_t)0x53, (uint8_t)0xD9,
    (uint8_t)0x42, (uint8_t)0x8E, (uint8_t)0xAF, (uint8_t)0x0B, (uint8_t)0x36,
    (uint8_t)0x71, (uint8_t)0xED, (uint8_t)0x80, (uint8_t)0xD7, (uint8_t)0x6C,
    (uint8_t)0xE7, (uint8_t)0xDB, (uint8_t)0xAF, (uint8_t)0x44, (uint8_t)0xEC,
    (uint8_t)0x28, (uint8_t)0xD3
  };

  EXPECT_EQ(false,
            plgd_dps_set_certificate_fingerprint(
              ctx_.get(), MBEDTLS_MD_MD5, &fingerprint[0], fingerprint.size()));
  EXPECT_EQ(false, plgd_dps_set_certificate_fingerprint(
                     ctx_.get(), MBEDTLS_MD_SHA256, &fingerprint[0],
                     fingerprint.size() + 1));
  EXPECT_EQ(true, plgd_dps_set_certificate_fingerprint(
                    ctx_.get(), MBEDTLS_MD_SHA256, &fingerprint[0],
                    fingerprint.size()));

  std::array<uint8_t, 16> fingerprint_too_small{ '\0' };
  EXPECT_EQ(-1, plgd_dps_get_certificate_fingerprint(
                  ctx_.get(), &md_type, &fingerprint_too_small[0],
                  fingerprint_too_small.size()));

  EXPECT_EQ(fingerprint_ok.size(),
            plgd_dps_get_certificate_fingerprint(
              ctx_.get(), &md_type, &fingerprint_ok[0], fingerprint_ok.size()));
  EXPECT_EQ(MBEDTLS_MD_SHA256, md_type);

  EXPECT_EQ(fingerprint, fingerprint_ok);
}

TEST_F(TestDPSWithContext, SetValuesFromVendorEncapsulatedOptions)
{
  std::string data = "c8:1c:63:6f:61:70:73:2b:74:63:70:3a:2f:2f:70:6c:67:64:2e:"
                     "63:6c:6f:75:64:3a:32:36:36:38:34:c9:20:"
                     "a1:e1:c3:4c:3e:3:17:8d:e4:77:79:f9:92:28:7d:fe:b4:b7:70:"
                     "2f:80:ee:d9:15:dd:ec:d6:"
                     "54:e4:c6:4f:e2:ca:6:53:48:41:32:35:36";
  ssize_t ret =
    plgd_dps_hex_string_to_bytes(data.c_str(), data.length(), nullptr, 0);
  ASSERT_EQ(72, ret);
  std::array<uint8_t, 72> buf;
  ret = plgd_dps_hex_string_to_bytes(data.c_str(), data.length(), &buf[0], ret);
  ASSERT_EQ(72, ret);
  EXPECT_EQ(PLGD_DPS_DHCP_SET_VALUES_ERROR,
            plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
              ctx_.get(), &buf[0], ret - 1));
  // last byte is '6' from SHA256
  buf[ret - 1] = 'A';
  // invalid SHA25A
  EXPECT_EQ(PLGD_DPS_DHCP_SET_VALUES_ERROR,
            plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
              ctx_.get(), &buf[0], ret));
  buf[ret - 1] = '6';
  EXPECT_EQ(PLGD_DPS_DHCP_SET_VALUES_NEED_REPROVISION,
            plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
              ctx_.get(), &buf[0], ret));
  EXPECT_EQ(PLGD_DPS_DHCP_SET_VALUES_NOT_CHANGED,
            plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
              ctx_.get(), &buf[0], ret));
  std::string data1 = "c8:1c:63:6f:61:70:73:2b:74:63:70:3a:2f:2f:70:6c:67:64:"
                      "2e:63:6c:6f:75:64:3a:32:36:36:38:34:c9:20:"
                      "a1:e1:c3:4c:3e:3:17:8d:e4:77:79:f9:92:28:7d:fe:b4:b7:70:"
                      "2f:81:ee:d9:15:dd:ec:d6:"
                      "54:e4:c6:4f:e2:ca:6:53:48:41:32:35:36";
  std::array<uint8_t, 72> buf1;
  ret = plgd_dps_hex_string_to_bytes(data1.c_str(), data1.length(), &buf1[0],
                                     buf1.size());
  ASSERT_EQ(72, ret);
  ctx_.get()->status = PLGD_DPS_PROVISIONED_MASK;
  EXPECT_EQ(PLGD_DPS_DHCP_SET_VALUES_UPDATED,
            plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
              ctx_.get(), &buf1[0], ret));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */