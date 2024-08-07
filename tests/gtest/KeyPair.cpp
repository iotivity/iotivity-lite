/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#include "KeyPair.h"

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "gtest/gtest.h"

#include <algorithm>

namespace oc {

keypair_t::keypair_t(const oc_ecdsa_keypair_t &ockp)
  : public_key_size{ ockp.public_key_size }
  , private_key_size{ ockp.private_key_size }
{
  std::copy(std::cbegin(ockp.public_key),
            std::cbegin(ockp.public_key) + public_key_size,
            std::begin(public_key));
  std::copy(std::cbegin(ockp.private_key),
            std::cbegin(ockp.private_key) + private_key_size,
            std::begin(private_key));
}

keypair_t
GetECPKeyPair(mbedtls_ecp_group_id grpid)
{
  keypair_t kp{};
  int err = oc_sec_ecdsa_generate_keypair(
    0, grpid, kp.public_key.data(), kp.public_key.size(), &kp.public_key_size,
    kp.private_key.data(), kp.private_key.size(), &kp.private_key_size);
  EXPECT_EQ(0, err);
  return kp;
}

oc_ecdsa_keypair_t
GetOCKeyPair(mbedtls_ecp_group_id grpid)
{
  oc_ecdsa_keypair_t kp{};
  size_t public_key_size{};
  int err = oc_sec_ecdsa_generate_keypair(
    0, grpid, kp.public_key, sizeof(kp.public_key), &public_key_size,
    kp.private_key, sizeof(kp.private_key), &kp.private_key_size);
  EXPECT_EQ(0, err);
  return kp;
}

} // namespace oc

#endif /* OC_SECURITY && OC_PKI */
