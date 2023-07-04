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

#include "api/oc_link_internal.h"
#include "oc_rep.h"
#include "oc_ri.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace oc {

using oc_link_unique_ptr =
  std::unique_ptr<oc_link_t, decltype(&oc_delete_link)>;

struct LinkParamData
{
  std::string key;
  std::string value;
};

struct LinkData
{
  std::string href;
  std::vector<std::string> rts;
  std::vector<oc_interface_mask_t> ifs;
  std::vector<std::string> rels;
  int64_t ins;
  std::vector<LinkParamData> params;
  oc_resource_properties_t bm;
  std::string tag_pos_desc;
  std::string tag_func_desc;
  std::vector<double> tag_pos_rel;
  std::vector<std::string> eps;
};

class Link {
public:
  Link(oc_resource_t *resource)
    : link_(oc_new_link(resource), oc_delete_link)
  {
  }

  ~Link() = default;

  static std::optional<LinkData> ParsePayload(const oc_rep_t *rep);

private:
  oc_link_unique_ptr link_;
};

} // namespace oc
