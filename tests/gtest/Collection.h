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

#include "api/oc_collection_internal.h"
#include "oc_rep.h"
#include "tests/gtest/Link.h"
#include "tests/gtest/Resource.h"
#include "util/oc_features.h"

#include <memory>
#include <optional>
#include <stdint.h>
#include <string>
#include <unordered_map>

#ifdef OC_COLLECTIONS

namespace oc {

using oc_collection_unique_ptr =
  std::unique_ptr<oc_collection_t, decltype(&oc_collection_free)>;

class Collection {
public:
  using Links = std::unordered_map<std::string, oc::LinkData>;

  struct Data
  {
    std::optional<BaselineData> baseline;
    std::vector<std::string> rts;
    std::vector<std::string> rts_m;
    Links links;
    std::unordered_map<std::string, const oc_rep_t *> properties;
  };

  struct BatchItem
  {
    std::string href;
#ifdef OC_HAS_FEATURE_ETAG
    std::vector<uint8_t> etag;
#endif /* OC_HAS_FEATURE_ETAG */
  };

  using BatchData = std::unordered_map<std::string, BatchItem>;

  static std::optional<Data> ParsePayload(const oc_rep_t *rep);
  static std::optional<Links> ParseLinksPayload(const oc_rep_t *rep);
  static BatchData ParseBatchPayload(const oc_rep_t *rep);
};

template<typename... Ts>
oc::oc_collection_unique_ptr
NewCollection(const std::string &name, const std::string &uri, size_t deviceID,
              const Ts &...resourceTypes)
{
  oc_resource_t *res = oc_new_collection(name.c_str(), uri.c_str(),
                                         sizeof...(resourceTypes), deviceID);
  (oc_resource_bind_resource_type(res, resourceTypes), ...);
  return oc::oc_collection_unique_ptr(reinterpret_cast<oc_collection_t *>(res),
                                      &oc_collection_free);
}
}

#endif // OC_COLLECTIONS
