
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

#ifndef OC_COLLECTION_INTERNAL_H
#define OC_COLLECTION_INTERNAL_H

#include "oc_helpers.h"
#include "oc_ri.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_rt_t
{
  struct oc_rt_t *next;
  oc_string_t rt;
} oc_rt_t;

struct oc_collection_s
{
  struct oc_resource_s res;
  OC_LIST_STRUCT(mandatory_rts);
  OC_LIST_STRUCT(supported_rts);
  OC_LIST_STRUCT(links); ///< list of links ordered by href length and value
};

#ifdef __cplusplus
}
#endif

#endif /* OC_COLLECTION_INTERNAL_H */
