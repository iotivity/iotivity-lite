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
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace oc {

struct BaselineData
{
  std::string name;
  std::vector<std::string> rts;
  std::vector<std::string> ifs;
  std::string tag_locn;
  std::vector<double> tag_pos_rel;
  std::string tag_pos_desc;
  std::string tag_func_desc;
};

/** @brief Iterate all resources in the Iotivity stack */
void IterateAllResources(const std::function<void(oc_resource_t *)> &fn);

/** @brief Iterate all resources in in given device */
void IterateDeviceResources(size_t device, bool includePlatformResources,
                            const std::function<void(oc_resource_t *)> &fn);

std::optional<BaselineData> ParseBaselineData(const oc_rep_t *rep);

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

bool SetAccessInRFOTM(oc_resource_t *resource, bool make_public,
                      unsigned permissions);

bool SetAccessInRFOTM(oc_core_resource_t index, size_t device, bool make_public,
                      unsigned permissions);

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

} // namespace oc
