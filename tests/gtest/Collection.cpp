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

std::optional<Collection::Links>
Collection::ParseLinksPayload(const oc_rep_t *rep)
{
  Collection::Links links;
  for (auto link = rep; link != nullptr; link = link->next) {
    auto linkData = Link::ParsePayload(link->value.object);
    if (linkData) {
      links[linkData->href] = *linkData;
    }
  }
  if (links.empty()) {
    return std::nullopt;
  }
  return links;
}

std::optional<Collection::Data>
Collection::ParsePayload(const oc_rep_t *rep)
{
  Collection::Data data{};
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
            data.links[linkData->href] = *linkData;
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

Collection::BatchData
Collection::ParseBatchPayload(const oc_rep_t *rep)
{
  Collection::BatchData data{};
  for (; rep != nullptr; rep = rep->next) {
    const oc_rep_t *obj = rep->value.object;
    Collection::BatchItem bi{};
    char *str;
    size_t str_len;
    // href: string
    if (oc_rep_get_string(obj, "href", &str, &str_len)) {
      bi.href = std::string(str, str_len);
    }

#ifdef OC_HAS_FEATURE_ETAG
    // etag: byte string
    if (oc_rep_get_byte_string(obj, "etag", &str, &str_len)) {
      bi.etag.resize(str_len);
      std::copy(&str[0], &str[str_len], std::begin(bi.etag));
    }
#endif /* OC_HAS_FEATURE_ETAG */

    if (!bi.href.empty()) {
      data[bi.href] = bi;
    }
  }

  return data;
}

} // namespace oc

#endif // OC_COLLECTIONS
