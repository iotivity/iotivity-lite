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

#include "Resource.h"

#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_ri.h"
#include "util/oc_features.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS */

#include <gtest/gtest.h>

namespace oc {

void
IterateAllResources(const std::function<void(oc_resource_t *)> &fn)
{
  // platform resources
  for (int type = 0; type < OCF_CON; ++type) {
    fn(oc_core_get_resource_by_index(type, 0));
  }

  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    // core resources
    for (int type = OCF_CON; type <= OCF_D; ++type) {
      fn(oc_core_get_resource_by_index(type, i));
    }
  }

#ifdef OC_SERVER
  // app resources
  for (oc_resource_t *app_res = oc_ri_get_app_resources(); app_res != nullptr;
       app_res = app_res->next) {
    fn(app_res);
  }

#ifdef OC_COLLECTIONS
  // collections
  for (oc_collection_t *col = oc_collection_get_all(); col != nullptr;
       col = (oc_collection_t *)col->res.next) {
    fn(&col->res);
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
}

void
IterateDeviceResources(size_t device, bool includePlatformResources,
                       const std::function<void(oc_resource_t *)> &fn)
{
  if (includePlatformResources) {
    // platform resources
    for (int type = 0; type < OCF_CON; ++type) {
      fn(oc_core_get_resource_by_index(type, 0));
    }
  }

  // core resources
  for (int type = OCF_CON; type <= OCF_D; ++type) {
    fn(oc_core_get_resource_by_index(type, device));
  }

#ifdef OC_SERVER
  // app resources
  for (oc_resource_t *app_res = oc_ri_get_app_resources(); app_res != nullptr;
       app_res = app_res->next) {
    if (app_res->device == device) {
      fn(app_res);
    }
  }

#ifdef OC_COLLECTIONS
  // collections
  for (oc_collection_t *col = oc_collection_get_all(); col != nullptr;
       col = (oc_collection_t *)col->res.next) {
    if (col->res.device == device) {
      fn(&col->res);
    }
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
}

std::optional<BaselineData>
ParseBaselineData(const oc_rep_t *rep)
{
  BaselineData data{};
  for (; rep != nullptr; rep = rep->next) {
    if (rep->type == OC_REP_STRING) {
      if (std::string(oc_string(rep->name)) == "n") {
        data.name = std::string(oc_string(rep->value.string));
        continue;
      }
      if (std::string(oc_string(rep->name)) == "tag-locn") {
        data.tag_locn = std::string(oc_string(rep->value.string));
        continue;
      }
      if (std::string(oc_string(rep->name)) == "tag-pos-desc") {
        data.tag_pos_desc = std::string(oc_string(rep->value.string));
        continue;
      }
      if (std::string(oc_string(rep->name)) == "tag-func-desc") {
        data.tag_func_desc = std::string(oc_string(rep->value.string));
        continue;
      }
      continue;
    }
    if (rep->type == OC_REP_DOUBLE_ARRAY) {
      if (std::string(oc_string(rep->name)) == "tag-pos-rel") {
        for (size_t i = 0; i < oc_double_array_size(rep->value.array); ++i) {
          data.tag_pos_rel.push_back(oc_double_array(rep->value.array)[i]);
        }
        continue;
      }
      continue;
    }
    if (rep->type == OC_REP_STRING_ARRAY) {
      if (std::string(oc_string(rep->name)) == "rt") {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          data.rts.push_back(
            std::string(oc_string_array_get_item(rep->value.array, i)));
        }
        continue;
      }
      if (std::string(oc_string(rep->name)) == "if") {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          data.ifs.push_back(
            std::string(oc_string_array_get_item(rep->value.array, i)));
        }
        continue;
      }
      continue;
    }
  }

  if (data.name.empty() && data.tag_locn.empty() && data.tag_pos_desc.empty() &&
      data.tag_func_desc.empty() && data.tag_pos_rel.empty() &&
      data.rts.empty() && data.ifs.empty()) {
    return std::nullopt;
  }

  return data;
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

bool
SetAccessInRFOTM(oc_resource_t *resource, bool make_public,
                 unsigned permissions)
{
  if (resource == nullptr) {
    return false;
  }
  if (make_public) {
    oc_resource_make_public(resource);
  }
  oc_resource_set_access_in_RFOTM(
    resource, true, static_cast<oc_ace_permissions_t>(permissions));
  return true;
}

bool
SetAccessInRFOTM(oc_core_resource_t index, size_t device, bool make_public,
                 unsigned permissions)
{
  return SetAccessInRFOTM(oc_core_get_resource_by_index(index, device),
                          make_public, permissions);
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#ifdef OC_HAS_FEATURE_ETAG

void
AssertETag(oc_coap_etag_t etag1, uint64_t etag2)
{
  ASSERT_EQ(sizeof(etag2), etag1.length);
  std::array<uint8_t, sizeof(etag2)> etag2_buf{};
  memcpy(&etag2_buf[0], &etag2, etag2_buf.size());
  ASSERT_EQ(0, memcmp(&etag1.value[0], &etag2_buf[0], etag1.length));
}

void
AssertResourceETag(oc_coap_etag_t etag, const oc_resource_t *resource)
{
  ASSERT_NE(nullptr, resource);
  AssertETag(etag, resource->etag);
}

#endif /* OC_HAS_FEATURE_ETAG */

} // namespace oc
