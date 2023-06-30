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

#include "oc_config.h"

#ifdef OC_SERVER

#include "oc_collection.h"
#include "oc_link_internal.h"
#include "oc_ri.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"

#include <assert.h>

/* Allocator for links */
OC_MEMB(g_links_s, oc_link_t, OC_MAX_APP_RESOURCES);
/* Allocator for link parameters */
OC_MEMB(g_params_s, oc_link_params_t, OC_LINK_PARAM_COUNT_MAX);

oc_link_params_t *
oc_link_param_allocate(oc_string_view_t key, oc_string_view_t value)
{
  assert(key.data != NULL);
  assert(value.data != NULL);
  oc_link_params_t *p = oc_memb_alloc(&g_params_s);
  if (p == NULL) {
    OC_ERR("insufficient memory to add link param");
    return NULL;
  }
  oc_new_string(&p->key, key.data, key.length);
  oc_new_string(&p->value, value.data, value.length);
  return p;
}

void
oc_link_param_free(oc_link_params_t *params)
{
  oc_free_string(&params->key);
  oc_free_string(&params->value);
  oc_memb_free(&g_params_s, params);
}

oc_link_t *
oc_new_link(oc_resource_t *resource)
{
  assert(resource != NULL);
  oc_link_t *link = (oc_link_t *)oc_memb_alloc(&g_links_s);
  if (link == NULL) {
    OC_ERR("insufficient memory to create new link");
    return NULL;
  }
  oc_new_string_array(&link->rel, OC_LINK_RELATIONS_ARRAY_SIZE);
  oc_string_array_add_item(link->rel, "hosts");
  link->resource = resource;
  link->interfaces = resource->interfaces;
#ifdef OC_COLLECTIONS
  resource->num_links++;
#endif /* OC_COLLECTIONS */
  link->next = NULL;
  link->ins = (int64_t)oc_random_value();
  OC_LIST_STRUCT_INIT(link, params);
  return link;
}

void
oc_delete_link(oc_link_t *link)
{
  if (link == NULL) {
    return;
  }
  oc_link_params_t *p = (oc_link_params_t *)oc_list_pop(link->params);
  while (p != NULL) {
    oc_link_param_free(p);
    p = (oc_link_params_t *)oc_list_pop(link->params);
  }
#ifdef OC_COLLECTIONS
  if (oc_ri_is_app_resource_valid(link->resource) ||
      oc_check_if_collection(link->resource)) {
    link->resource->num_links--;
  }
#endif /* OC_COLLECTIONS */
  oc_free_string_array(&(link->rel));
  oc_memb_free(&g_links_s, link);
}

bool
oc_link_add_rel(oc_link_t *link, const char *rel)
{
  assert(link != NULL);
  assert(rel != NULL);
  return oc_string_array_add_item(link->rel, rel);
}

void
oc_link_clear_rels(oc_link_t *link)
{
  assert(link != NULL);
  memset(oc_string(link->rel), 0, link->rel.size);
}

bool
oc_link_add_link_param(oc_link_t *link, const char *key, const char *value)
{
  assert(link != NULL);
  assert(key != NULL);
  assert(value != NULL);

  oc_link_params_t *p = oc_link_param_allocate(
    oc_string_view(key, strlen(key)), oc_string_view(value, strlen(value)));
  if (p == NULL) {
    return false;
  }
  oc_list_add(link->params, p);
  return true;
}

void
oc_link_clear_link_params(oc_link_t *link)
{
  assert(link != NULL);

  oc_link_params_t *p = (oc_link_params_t *)oc_list_pop(link->params);
  while (p != NULL) {
    oc_link_param_free(p);
    p = (oc_link_params_t *)oc_list_pop(link->params);
  }
}

void
oc_link_set_interfaces(oc_link_t *link, oc_interface_mask_t new_interfaces)
{
  assert(link != NULL);

  link->interfaces = new_interfaces;
}

#endif /* OC_SERVER */
