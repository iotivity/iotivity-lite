/******************************************************************
 *
 * Copyright (c) 2022 Daniel Adam
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2018 Samsung Electronics
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

#ifdef OC_DYNAMIC_ALLOCATION // need bigger OC_BYTES_POOL_SIZE for this test to
                             // pass

#include "api/oc_core_res_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_cred_internal.h"
#include "oc_pki.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_random.h"
#include "security/oc_svr_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/PKI.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <array>
#include <cstdio>
#include <ctime>
#include <gtest/gtest.h>
#include <string>
#include <stdexcept>
#include <vector>

class TestTlsCertificates : public testing::Test {
public:
  void SetUp() override
  {
    oc_core_init();
    oc_random_init();
    oc_network_event_handler_mutex_init();
    oc_tls_init_context();
    oc_add_new_device_t cfg{};
    cfg.name = "Lamp";
    cfg.uri = "/oic/d";
    cfg.rt = "oic.d.light";
    cfg.spec_version = "ocf.1.0.0";
    cfg.data_model_version = "ocf.res.1.0.0";
    oc_device_info_t *info = oc_core_add_new_device(cfg);
    EXPECT_NE(nullptr, info);
    oc_sec_svr_create();

    EXPECT_EQ(1, oc_core_get_num_devices());
    device_ = oc_core_get_num_devices() - 1;
    EXPECT_GE(device_, 0);

    ASSERT_TRUE(idcert1_.Add(device_));
    ASSERT_TRUE(subca1_.Add(device_, idcert1_.CredentialID()));
    ASSERT_TRUE(idcert2_.Add(device_));
    ASSERT_TRUE(rootca1_.Add(device_));
    ASSERT_TRUE(rootca2_.Add(device_));
  }

  void TearDown() override
  {
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(device_);
    oc_sec_svr_free();
    oc_tls_shutdown();
    oc_network_event_handler_mutex_destroy();
    oc_random_destroy();
    oc_core_shutdown();
  }

  int device_{ -1 };
  oc::pki::IdentityCertificate idcert1_{ "pki_certs/ee.pem",
                                         "pki_certs/key.pem", true };
  oc::pki::IdentityCertificate idcert2_{
    "pki_certs/certification_tests_ee.pem",
    "pki_certs/certification_tests_key.pem", true
  };
  oc::pki::IntermediateCertificate subca1_{ "pki_certs/subca1.pem" };
  oc::pki::TrustAnchor rootca1_{ "pki_certs/rootca1.pem", true };
  oc::pki::TrustAnchor rootca2_{ "pki_certs/rootca2.pem", true };

  static time_t now_;
};

time_t TestTlsCertificates::now_{ time(nullptr) };

static size_t
oc_sec_cred_count(size_t device)
{
  size_t count = 0;
  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  const oc_sec_cred_t *c = (oc_sec_cred_t *)oc_list_head(creds->creds);
  while (c != nullptr) {
    ++count;
    c = c->next;
  }
  return count;
}

TEST_F(TestTlsCertificates, ClearCertificates)
{
  // 4 = 2 root certificates + 2 mfg certs
  EXPECT_EQ(4, oc_sec_cred_count(device_));

  oc_sec_cred_clear(
    device_, [](const oc_sec_cred_t *, void *) { return false; }, nullptr);
  EXPECT_EQ(4, oc_sec_cred_count(device_));

  EXPECT_NE(nullptr,
            oc_sec_get_cred_by_credid(idcert1_.CredentialID(), device_));
  oc_sec_cred_clear(
    device_,
    [](const oc_sec_cred_t *cred, void *data) {
      const auto *cert = static_cast<oc::pki::IdentityCertificate *>(data);
      return cred->credid == cert->CredentialID();
    },
    &idcert1_);
  EXPECT_EQ(3, oc_sec_cred_count(device_));
  EXPECT_EQ(nullptr,
            oc_sec_get_cred_by_credid(idcert1_.CredentialID(), device_));

  EXPECT_NE(nullptr,
            oc_sec_get_cred_by_credid(idcert2_.CredentialID(), device_));
  auto removeMfgCert = [](const oc_sec_cred_t *cred, void *) {
    return cred->credtype == OC_CREDTYPE_CERT &&
           cred->credusage == OC_CREDUSAGE_MFG_CERT;
  };
  oc_sec_cred_clear(device_, removeMfgCert, nullptr);
  EXPECT_EQ(2, oc_sec_cred_count(device_));
  EXPECT_EQ(nullptr,
            oc_sec_get_cred_by_credid(idcert2_.CredentialID(), device_));

  oc_sec_cred_clear(device_, nullptr, nullptr);
  EXPECT_EQ(0, oc_sec_cred_count(device_));
}

#ifdef OC_TEST

TEST_F(TestTlsCertificates, RemoveIdentityCertificates)
{
  EXPECT_TRUE(oc_tls_validate_identity_certs_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(idcert1_.CredentialID(), device_));
  EXPECT_TRUE(oc_tls_validate_identity_certs_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(idcert2_.CredentialID(), device_));
  EXPECT_TRUE(oc_tls_validate_identity_certs_consistency());
}

TEST_F(TestTlsCertificates, RemoveTrustAnchors)
{
  EXPECT_TRUE(oc_tls_validate_trust_anchors_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(rootca1_.CredentialID(), device_));
  EXPECT_TRUE(oc_tls_validate_trust_anchors_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(rootca2_.CredentialID(), device_));
  EXPECT_TRUE(oc_tls_validate_trust_anchors_consistency());
}

#endif /* OC_TEST */

TEST_F(TestTlsCertificates, VerifyCredCerts)
{
  auto verify_cert_validity = [](const oc_sec_certs_data_t *data, void *) {
    return (time_t)data->valid_from <= TestTlsCertificates::now_ &&
           (time_t)data->valid_to > TestTlsCertificates::now_;
  };

  oc_sec_cred_t invalid{};
  EXPECT_EQ((size_t)-1, oc_cred_verify_certificate_chain(
                          &invalid, verify_cert_validity, nullptr));

  // valid - rootca1_ valid_from: 30.11.2018, valid_to: 27.11.2028
  oc_sec_cred_t *cred =
    oc_sec_get_cred_by_credid(rootca1_.CredentialID(), device_);
  EXPECT_NE(nullptr, cred);
  EXPECT_EQ(
    0, oc_cred_verify_certificate_chain(cred, verify_cert_validity, nullptr));

  // expired - idcert1_ valid_from: 14.4.2020, valid_to: 14.5.2020
  cred = oc_sec_get_cred_by_credid(idcert1_.CredentialID(), device_);
  EXPECT_NE(nullptr, cred);
  EXPECT_EQ(
    1, oc_cred_verify_certificate_chain(cred, verify_cert_validity, nullptr));
}

#endif /* OC_DYNAMIC_ALLOCATION */
#endif /* OC_SECURITY && OC_PKI */
