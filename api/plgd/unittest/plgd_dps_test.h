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

#pragma once

#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "tests/gtest/KeyPair.h"
#include "util/oc_features.h"

#include <cstring>
#include <cstddef>
#include <memory>
#include <string>

namespace dps {

using context_unique_ptr =
  std::unique_ptr<plgd_dps_context_t, void (*)(plgd_dps_context_t *)>;

context_unique_ptr make_unique_context(size_t device);

#ifdef OC_DYNAMIC_ALLOCATION

int addRootCertificate(size_t device, const oc::keypair_t &kp,
                       bool is_mfg = false, bool add_tag = false);

int addIdentityCertificate(size_t device, const oc::keypair_t &kp,
                           const oc::keypair_t &issuer_kp, bool is_mfg = false,
                           bool add_tag = false);

#endif /* OC_DYNAMIC_ALLOCATION */

} // namespace dps
