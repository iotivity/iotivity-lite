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

#include "Link.h"
#include "port/oc_log_internal.h"

#include <optional>

namespace oc {

namespace {

std::optional<oc_resource_properties_t>
parseProperties(const oc_rep_t *rep)
{
  for (; rep != nullptr; rep = rep->next) {
    if (rep->type == OC_REP_INT && std::string(oc_string(rep->name)) == "bm") {
      return static_cast<oc_resource_properties_t>(rep->value.integer);
    }
  }
  return std::nullopt;
}

std::vector<std::string>
parseEndpoints(const oc_rep_t *rep)
{
  std::vector<std::string> eps{};
  for (; rep != nullptr; rep = rep->next) {
    for (const oc_rep_t *ep_rep = rep->value.object; ep_rep != nullptr;
         ep_rep = ep_rep->next) {
      if (ep_rep->type == OC_REP_STRING &&
          std::string(oc_string(ep_rep->name)) == "ep") {
        eps.push_back(oc_string(ep_rep->value.string));
      }
    }
  }
  return eps;
}

}

std::optional<LinkData>
Link::ParsePayload(const oc_rep_t *rep)
{
  LinkData ld{};
  for (; rep != nullptr; rep = rep->next) {
    if (rep->type == OC_REP_STRING) {
      if (std::string(oc_string(rep->name)) == "href") {
        ld.href = oc_string(rep->value.string);
        continue;
      }
      if (std::string(oc_string(rep->name)) == "tag-pos-desc") {
        ld.tag_pos_desc = oc_string(rep->value.string);
        continue;
      }
      if (std::string(oc_string(rep->name)) == "tag-func-desc") {
        ld.tag_func_desc = oc_string(rep->value.string);
        continue;
      }

      ld.params.emplace_back(
        LinkParamData{ oc_string(rep->name), oc_string(rep->value.string) });
      continue;
    }

    if (rep->type == OC_REP_INT) {
      if (std::string(oc_string(rep->name)) == "ins") {
        ld.ins = rep->value.integer;
        continue;
      }
    }

    if (rep->type == OC_REP_DOUBLE_ARRAY) {
      if (std::string(oc_string(rep->name)) == "tag-pos-rel") {
        for (size_t i = 0; i < oc_double_array_size(rep->value.array); ++i) {
          ld.tag_pos_rel.push_back(oc_double_array(rep->value.array)[i]);
        }
        continue;
      }
    }

    if (rep->type == OC_REP_STRING_ARRAY) {
      if (std::string(oc_string(rep->name)) == "rt") {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          ld.rts.emplace_back(oc_string_array_get_item(rep->value.array, i));
        }
        continue;
      }
      if (std::string(oc_string(rep->name)) == "rel") {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          ld.rels.emplace_back(oc_string_array_get_item(rep->value.array, i));
        }
        continue;
      }
      if (std::string(oc_string(rep->name)) == "if") {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          const char *ifname = oc_string_array_get_item(rep->value.array, i);
          size_t ifname_len = strlen(ifname);
          oc_interface_mask_t ifmask =
            oc_ri_get_interface_mask(ifname, ifname_len);
          if (0 != ifmask) {
            ld.ifs.emplace_back(ifmask);
          }
        }
        continue;
      }
    }

    if (rep->type == OC_REP_OBJECT) {
      if (std::string(oc_string(rep->name)) == "p") {
        auto bm = parseProperties(rep->value.object);
        if (bm) {
          ld.bm = *bm;
        }
      }
    }

    if (rep->type == OC_REP_OBJECT_ARRAY) {
      if (std::string(oc_string(rep->name)) == "eps") {
        ld.eps = parseEndpoints(rep->value.object_array);
        continue;
      }
    }

    OC_DBG("unparsed: (name:%s type:%d)", oc_string(rep->name), rep->type);
  }

  return ld;
}

} // namespace oc
