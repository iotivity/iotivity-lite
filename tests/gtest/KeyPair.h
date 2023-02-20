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

#pragma once

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "security/oc_keypair_internal.h"

#include <array>
#include <stddef.h>
#include <stdint.h>

namespace oc {

struct keypair_t
{
  std::array<uint8_t, OC_ECDSA_PUBKEY_SIZE> public_key{};
  size_t public_key_size{ 0 };
  std::array<uint8_t, OC_ECDSA_PRIVKEY_SIZE> private_key{};
  size_t private_key_size{ 0 };
};

keypair_t GetECPKeyPair(mbedtls_ecp_group_id grpid);

oc_ecdsa_keypair_t GetOCKeyPair(mbedtls_ecp_group_id grpid);

} // namespace oc

#endif /* OC_SECURITY && OC_PKI */
