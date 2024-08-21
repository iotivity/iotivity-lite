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

#include "api/plgd/device-provisioning-client/plgd_dps_pki_internal.h"

#include "gtest/gtest.h"

#include <ctime>

TEST(DPSSecurityTest, CalculateCertificateCheckInterval)
{
  time_t now = time(nullptr);
  EXPECT_NE(-1, now);

  const uint16_t expiresIn = 60;
  dps_pki_configuration_t cfg = { /*.expiring_limit =*/expiresIn };
  uint64_t expired{ static_cast<uint64_t>(now) - 1 };
  uint64_t expiring{ static_cast<uint64_t>(now) + (expiresIn / 2) };
  // expiring and expired certificates should be immediately renewed
  EXPECT_EQ(0, dps_pki_calculate_renew_certificates_interval(cfg, expired));
  EXPECT_EQ(0, dps_pki_calculate_renew_certificates_interval(cfg, expiring));

  // non-expiring certificates should have some non-zero time for renewal
  uint64_t valid{ static_cast<uint64_t>(now) + (expiresIn * 2) };
  EXPECT_LT(0, dps_pki_calculate_renew_certificates_interval(cfg, valid));
}

TEST(DPSSecurityTest, CertificateStateToStr)
{
  EXPECT_STREQ("valid",
               dps_pki_certificate_state_to_str(DPS_CERTIFICATE_VALID));
  EXPECT_STREQ("expired",
               dps_pki_certificate_state_to_str(DPS_CERTIFICATE_EXPIRED));
}

TEST(DPSSecurityTest, CertificateValidityToState)
{
  time_t now = time(nullptr);
  EXPECT_NE(-1, now);

  dps_pki_configuration_t cfg = {
    /*.expiring_limit = */ 60,
  };

  time_t future = now + 60;
  EXPECT_EQ(DPS_CERTIFICATE_NOT_YET_VALID,
            dps_pki_validate_certificate(cfg, future, 0));

  time_t expiring = now + cfg.expiring_limit - 1;
  EXPECT_EQ(DPS_CERTIFICATE_EXPIRING,
            dps_pki_validate_certificate(cfg, now, expiring));

  time_t past = now - 1;
  EXPECT_EQ(DPS_CERTIFICATE_EXPIRED,
            dps_pki_validate_certificate(cfg, past, past));

  time_t valid = now + cfg.expiring_limit + 60;
  EXPECT_EQ(DPS_CERTIFICATE_VALID,
            dps_pki_validate_certificate(cfg, now, valid));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
