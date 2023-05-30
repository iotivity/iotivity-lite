/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "oc_ri.h"
#include "util/oc_features.h"

#include <cstddef>

namespace oc {

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

bool SetAccessInRFOTM(oc_core_resource_t index, size_t device,
                      unsigned permissions);

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

} // namespace oc
