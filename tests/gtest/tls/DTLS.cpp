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

#include "oc_config.h"

#ifdef OC_SECURITY

#include "DTLS.h"

#include "api/oc_core_res_internal.h"
#include "security/oc_cred_internal.h"
#include "util/oc_macros_internal.h"

namespace oc::tls {

std::optional<IdentityHint>
AddPresharedKey(size_t device, const PreSharedKey &psk)
{
  oc_uuid_t *uuid = oc_core_get_device_id(device);
  std::array<char, OC_UUID_LEN> uuid_str{};
  oc_uuid_to_str(uuid, uuid_str.data(), uuid_str.size());
  if (oc_sec_add_new_psk_cred(device, uuid_str.data(),
                              { psk.data(), psk.size(), OC_ENCODING_RAW },
                              OC_STRING_VIEW_NULL) == -1) {
    return {};
  }
  IdentityHint hint{};
  std::copy(std::begin(uuid->id), std::end(uuid->id), std::begin(hint));
  return hint;
}

} // namespace oc::tls

#endif /* OC_SECURITY */
