/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_resource_internal.h"
#include "oc_ri.h"
#include "port/oc_log_internal.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS */

#include <assert.h>

bool
oc_resource_is_initialized(const oc_resource_t *resource)
{
  assert(resource != NULL);
  return oc_string(resource->uri) != NULL;
}

void
oc_resources_iterate_platform(oc_resource_iterate_fn_t fn, void *data)
{
  for (int type = 0; type < OCF_CON; ++type) {
    oc_resource_t *res = oc_core_get_resource_by_index(type, 0);
    if (res != NULL && !fn(res, data)) {
      return;
    }
  }
}

void
oc_resources_iterate_core(size_t device, oc_resource_iterate_fn_t fn,
                          void *data)
{
  for (int type = OCF_CON; type <= OCF_D; ++type) {
    if (type == OCF_CON && !oc_get_con_res_announced()) {
      continue;
    }
    oc_resource_t *core_res = oc_core_get_resource_by_index(type, device);
    if (core_res != NULL && !fn(core_res, data)) {
      return;
    }
  }
}

#ifdef OC_SERVER

void
oc_resources_iterate_dynamic(size_t device, oc_resource_iterate_fn_t fn,
                             void *data)
{
  for (oc_resource_t *app_res = oc_ri_get_app_resources(); app_res != NULL;
       app_res = app_res->next) {
    if (app_res->device != device) {
      continue;
    }
    if (!fn(app_res, data)) {
      return;
    }
  }
}

#ifdef OC_COLLECTIONS

void
oc_resources_iterate_collections(size_t device, oc_resource_iterate_fn_t fn,
                                 void *data)
{
  for (oc_collection_t *col = oc_collection_get_all(); col != NULL;
       col = (oc_collection_t *)col->res.next) {
    if (col->res.device != device) {
      continue;
    }
    if (!fn(&col->res, data)) {
      return;
    }
  }
}

#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

void
oc_resources_iterate(size_t device, bool includePlatform, bool includeCore,
                     bool includeDynamic, bool includeCollections,
                     oc_resource_iterate_fn_t fn, void *data)
{
  if (includePlatform) {
    oc_resources_iterate_platform(fn, data);
  }

  // core resources
  if (includeCore) {
    oc_resources_iterate_core(device, fn, data);
  }

#ifdef OC_SERVER
  // app resources
  if (includeDynamic) {
    oc_resources_iterate_dynamic(device, fn, data);
  }

#ifdef OC_COLLECTIONS
  // collections
  if (includeCollections) {
    oc_resources_iterate_collections(device, fn, data);
  }
#else  /* OC_COLLECTIONS */
  (void)includeCollections;
#endif /* OC_COLLECTIONS */
#else  /* OC_SERVER */
  (void)includeDynamic;
  (void)includeCollections;
#endif /* OC_SERVER */
}
