/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
 ***************************************************************************/

#include "oc_config.h"

#ifdef OC_SERVER

#include "oc_ri_server_internal.h"
#include "port/oc_log_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

OC_LIST(g_on_delete_resource_cb_list);
OC_MEMB(g_on_delete_resource_cb_s, oc_ri_on_delete_resource_t,
        OC_MAX_ON_DELETE_RESOURCE_CBS);

bool
oc_ri_on_delete_resource_add_callback(oc_ri_delete_resource_cb_t cb)
{
  if (oc_ri_on_delete_resource_find_callback(cb) != NULL) {
    OC_ERR("delete resource callback already exists");
    return false;
  }
  oc_ri_on_delete_resource_t *item = oc_memb_alloc(&g_on_delete_resource_cb_s);
  if (item == NULL) {
    OC_ERR("delete resource callback item alloc failed");
    return false;
  }
  item->cb = cb;
  oc_list_add(g_on_delete_resource_cb_list, item);
  return true;
}

oc_ri_on_delete_resource_t *
oc_ri_on_delete_resource_find_callback(oc_ri_delete_resource_cb_t cb)
{
  oc_ri_on_delete_resource_t *item = oc_list_head(g_on_delete_resource_cb_list);
  for (; item != NULL; item = item->next) {
    if (cb == item->cb) {
      return item;
    }
    continue;
  }
  return NULL;
}

bool
oc_ri_on_delete_resource_remove_callback(oc_ri_delete_resource_cb_t cb)
{
  oc_ri_on_delete_resource_t *on_delete =
    oc_ri_on_delete_resource_find_callback(cb);
  if (on_delete == NULL) {
    return false;
  }
  oc_list_remove(g_on_delete_resource_cb_list, on_delete);
  oc_memb_free(&g_on_delete_resource_cb_s, on_delete);
  return true;
}

void
oc_ri_on_delete_resource_remove_all(void)
{
  oc_ri_on_delete_resource_t *on_delete =
    oc_list_pop(g_on_delete_resource_cb_list);
  while (on_delete != NULL) {
    oc_list_remove(g_on_delete_resource_cb_list, on_delete);
    oc_memb_free(&g_on_delete_resource_cb_s, on_delete);

    on_delete = oc_list_pop(g_on_delete_resource_cb_list);
  }
}

void
oc_ri_on_delete_resource_invoke(oc_resource_t *resource)
{
  for (oc_ri_on_delete_resource_t *on_delete =
         oc_list_head(g_on_delete_resource_cb_list);
       on_delete != NULL; on_delete = on_delete->next) {
    on_delete->cb(resource);
  }
}

#endif /* OC_SERVER */
