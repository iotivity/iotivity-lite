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
#include "oc_cred.h"
#include "oc_pki.h"
#include "plgd_dps_test.h"
#include "tests/gtest/PKI.h"

#include <vector>

namespace dps {

context_unique_ptr
make_unique_context(size_t device)
{
  auto ctxUPtr =
    context_unique_ptr{ new plgd_dps_context_t, [](plgd_dps_context_t *ctx) {
                         dps_context_deinit(ctx);
                         delete ctx;
                       } };
  memset(ctxUPtr.get(), 0, sizeof(plgd_dps_context_t));
  dps_context_init(ctxUPtr.get(), device);
  return ctxUPtr;
}

#ifdef OC_DYNAMIC_ALLOCATION

static bool
addTag(size_t device, int credid)
{
  oc_sec_cred_t *cred = oc_sec_get_cred_by_credid(credid, device);
  if (cred == nullptr) {
    return false;
  }
  oc_set_string(&cred->tag, DPS_TAG, DPS_TAG_LEN);
  return true;
}

int
addRootCertificate(size_t device, const oc::keypair_t &kp, bool is_mfg,
                   bool add_tag)
{
  auto pem = oc::pki::GenerateRootCertificate(kp);
  int credid = is_mfg
                 ? oc_pki_add_mfg_trust_anchor(device, pem.data(), pem.size())
                 : oc_pki_add_trust_anchor(device, pem.data(), pem.size());
  if ((credid < 0) || (add_tag && !addTag(device, credid))) {
    goto error;
  }
  return credid;

error:
  if (credid != -1) {
    oc_sec_remove_cred_by_credid(credid, device);
  }
  return -1;
}

int
addIdentityCertificate(size_t device, const oc::keypair_t &kp,
                       const oc::keypair_t &issuer_kp, bool is_mfg,
                       bool add_tag)
{
  auto pem = oc::pki::GeneratIdentityCertificate(kp, issuer_kp);
  if (pem.empty()) {
    return -1;
  }
  oc::pki::KeyParser parser{};
  auto keyPem =
    parser.GetPrivateKey(kp.private_key.data(), kp.private_key_size);
  if (keyPem.empty()) {
    return -1;
  }

  int credid = is_mfg ? oc_pki_add_mfg_cert(device, pem.data(), pem.size(),
                                            keyPem.data(), keyPem.size())
                      : oc_pki_add_identity_cert(device, pem.data(), pem.size(),
                                                 keyPem.data(), keyPem.size());
  if ((credid < 0) || (add_tag && !addTag(device, credid))) {
    goto error;
  }
  return credid;
error:
  if (credid != -1) {
    oc_sec_remove_cred_by_credid(credid, device);
  }
  return -1;
}

#endif /* OC_DYNAMIC_ALLOCATION */

} // namespace dps

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
