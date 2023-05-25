/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#pragma once

#include "oc_config.h"
#include "port/oc_clock.h"

#include <chrono>

namespace oc {

constexpr oc_clock_time_t
DurationToTicks(std::chrono::milliseconds ms)
{
  if constexpr (OC_CLOCK_SECOND == 1000000) {
    return ms.count() * 1000;
  }
  if constexpr (OC_CLOCK_SECOND == 1000) {
    return ms.count();
  }
  return static_cast<oc_clock_time_t>(static_cast<double>(ms.count()) /
                                      OC_CLOCK_SECOND) *
         1000;
}

} // nmespace oc
