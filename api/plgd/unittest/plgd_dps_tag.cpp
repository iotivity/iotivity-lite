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

#include "api/plgd/device-provisioning-client/plgd_dps_tag_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_cred.h"
#include "oc_pki.h"
#include "plgd_dps_test.h"

#include "gtest/gtest.h"

#include <string>
#include <vector>

class TestDPSTag : public testing::Test {
private:
  static void SignalEventLoop()
  {
    // no-op for tests
  }

  static int AppInit()
  {
    if (oc_init_platform("Samsung", nullptr, nullptr) != 0) {
      return -1;
    }
    if (oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                      "ocf.res.1.0.0", nullptr, nullptr) != 0) {
      return -1;
    }
    return 0;
  }

public:
  void SetUp() override
  {
    static oc_handler_t handler{};
    handler.init = AppInit;
    handler.signal_event_loop = SignalEventLoop;
    EXPECT_EQ(0, oc_main_init(&handler));
  }

  void TearDown() override { oc_main_shutdown(); }
};

#ifdef OC_DYNAMIC_ALLOCATION

TEST_F(TestDPSTag, TagCredentials)
{
  oc::keypair_t rootKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  oc::keypair_t identKey{ oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1) };
  int mfg_credid =
    dps::addIdentityCertificate(0, identKey, rootKey, true, true);
  ASSERT_LT(0, mfg_credid);

  dps_credentials_set_stale_tag(0);
  oc_sec_cred_t *cred = oc_sec_get_cred_by_credid(mfg_credid, 0);
  ASSERT_NE(nullptr, cred);
  EXPECT_STREQ(DPS_STALE_TAG, oc_string(cred->tag));

  dps_credentials_remove_stale_tag(0);
  cred = oc_sec_get_cred_by_credid(mfg_credid, 0);
  ASSERT_NE(nullptr, cred);
  EXPECT_STREQ(DPS_TAG, oc_string(cred->tag));

  ASSERT_TRUE(oc_sec_remove_cred_by_credid(mfg_credid, 0));
}

#endif /* OC_DYNAMIC_ALLOCATION */

TEST_F(TestDPSTag, TagNoCredentials)
{
  oc_sec_creds_t *creds = oc_sec_get_creds(0);
  ASSERT_NE(nullptr, creds);

  for (const auto *cred =
         static_cast<oc_sec_cred_t *>(oc_list_head(creds->creds));
       cred != nullptr; cred = cred->next) {
    ASSERT_EQ(nullptr, oc_string(cred->tag));
  }
  dps_credentials_set_stale_tag(0);

  for (const auto *cred =
         static_cast<oc_sec_cred_t *>(oc_list_head(creds->creds));
       cred != nullptr; cred = cred->next) {
    EXPECT_EQ(nullptr, oc_string(cred->tag));
  }

  dps_credentials_remove_stale_tag(0);
}

TEST_F(TestDPSTag, TagACLs)
{
  EXPECT_TRUE(oc_sec_acl_add_bootstrap_acl(0));
  auto *ace = (oc_sec_ace_t *)oc_list_head(oc_sec_get_acl(0)->subjects);
  EXPECT_NE(nullptr, ace);
  oc_set_string(&ace->tag, DPS_TAG, DPS_TAG_LEN);

  dps_acls_set_stale_tag(0);
  ace = (oc_sec_ace_t *)oc_list_head(oc_sec_get_acl(0)->subjects);
  ASSERT_NE(nullptr, ace);
  EXPECT_STREQ(DPS_STALE_TAG, oc_string(ace->tag));

  dps_acls_remove_stale_tag(0);
  ace = (oc_sec_ace_t *)oc_list_head(oc_sec_get_acl(0)->subjects);
  ASSERT_NE(nullptr, ace);
  EXPECT_STREQ(DPS_TAG, oc_string(ace->tag));

  oc_set_string(&ace->tag, nullptr, 0);
}

TEST_F(TestDPSTag, TagNoACLs)
{
  oc_sec_acl_t *acl = oc_sec_get_acl(0);
  ASSERT_NE(nullptr, acl);

  for (const auto *ace =
         static_cast<oc_sec_ace_t *>(oc_list_head(acl->subjects));
       ace != nullptr; ace = ace->next) {
    ASSERT_EQ(nullptr, oc_string(ace->tag));
  }

  dps_acls_set_stale_tag(0);
  for (const auto *ace =
         static_cast<oc_sec_ace_t *>(oc_list_head(acl->subjects));
       ace != nullptr; ace = ace->next) {
    EXPECT_EQ(nullptr, oc_string(ace->tag));
  }

  dps_acls_remove_stale_tag(0);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
