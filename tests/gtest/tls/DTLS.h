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

#include "oc_config.h"

#ifdef OC_SECURITY

#include <array>
#include <optional>
#include <stddef.h>
#include <stdint.h>

namespace oc::tls {

using IdentityHint = std::array<uint8_t, 16>;
using PreSharedKey = std::array<uint8_t, 16>;

std::optional<IdentityHint> AddPresharedKey(size_t device,
                                            const PreSharedKey &psk);

} // namespace oc::tls

#endif /* OC_SECURITY */
