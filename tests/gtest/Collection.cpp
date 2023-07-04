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

#include "oc_config.h"

#ifdef OC_COLLECTIONS

#include "api/oc_rep_internal.h"
#include "tests/gtest/Collection.h"
#include "tests/gtest/Resource.h"

namespace oc {

std::optional<CollectionData>
Collection::ParsePayload(const oc_rep_t *rep)
{
  CollectionData data{};
  auto baseline = oc::ParseBaselineData(rep);
  if (baseline) {
    data.baseline = *baseline;
  }

  for (; rep != nullptr; rep = rep->next) {
    if (data.baseline && oc_rep_is_baseline_interface_property(rep)) {
      continue;
    }
    if (rep->type == OC_REP_STRING_ARRAY) {
      if (std::string(oc_string(rep->name)) == "rts") {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          data.rts.push_back(oc_string_array_get_item(rep->value.array, i));
        }
        continue;
      }
      if (std::string(oc_string(rep->name)) == "rts-m") {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          data.rts_m.push_back(oc_string_array_get_item(rep->value.array, i));
        }
        continue;
      }
    }
    if (rep->type == OC_REP_OBJECT_ARRAY) {
      if (std::string(oc_string(rep->name)) == "links") {
        for (auto link = rep->value.object_array; link != nullptr;
             link = link->next) {
          auto linkData = Link::ParsePayload(link->value.object);
          if (linkData) {
            data.links.push_back(*linkData);
          }
        }
        continue;
      }
    }
    // custom property
    data.properties[oc_string(rep->name)] = rep;
  }

  if (!data.baseline && data.rts.empty() && data.rts_m.empty() &&
      data.links.empty() && data.properties.empty()) {
    return std::nullopt;
  }
  return data;
}

} // namespace oc

#endif // OC_COLLECTIONS
