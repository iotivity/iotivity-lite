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

#ifndef OC_LINK_INTERNAL_H
#define OC_LINK_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_link.h"
#include "oc_ri.h"
#include "oc_helpers.h"
#include "util/oc_list.h"
#include "util/oc_compiler.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_link_params_t
{
  struct oc_link_params_t *next;
  oc_string_t key;
  oc_string_t value;
} oc_link_params_t;

enum {
  OC_LINK_PARAM_COUNT_MAX =
    1, ///< maximal number allowed of statically allocated link params
};

/**
 * @brief Allocate a new link parameter
 *
 * @param key key (cannot be empty)
 * @param value value (cannot be empty)
 * @return oc_link_params_t* on success
 * @return NULL on failure
 */
oc_link_params_t *oc_link_param_allocate(oc_string_view_t key,
                                         oc_string_view_t value);

// @brief Deallocated a link parameter
void oc_link_param_free(oc_link_params_t *params) OC_NONNULL();

struct oc_link_s
{
  struct oc_link_s *next;
  oc_resource_t *resource;
  oc_interface_mask_t interfaces;
  int64_t ins;
  oc_string_array_t rel;
  OC_LIST_STRUCT(params);
};

enum {
  OC_LINK_RELATIONS_ARRAY_SIZE =
    3, ///< number of allocated items in oc_link_s::rel array
};

#ifdef __cplusplus
}
#endif

#endif /* OC_LINK_INTERNAL_H */
