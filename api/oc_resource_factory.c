/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "oc_collection.h"

#if defined(OC_SERVER) && defined(OC_COLLECTIONS) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
#include "api/oc_resource_factory.h"

OC_MEMB(rtc_s, oc_rt_created_t, 1);
OC_LIST(created_res);

void
gen_random_uri(char *uri, size_t uri_length)
{
  const char *alpha =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  uri[0] = '/';
  size_t i = 1;
  while (i < uri_length-1) {
    unsigned int r = oc_random_value() % strlen(alpha);
    uri[i++] = alpha[r];
  }
  uri[uri_length-1] = '\0';
}

oc_rt_created_t *
oc_rt_factory_create_resource(oc_collection_t *collection,
                              oc_string_array_t *rtypes,
                              oc_resource_properties_t bm,
                              oc_interface_mask_t interfaces,
                              oc_rt_factory_t *rf, size_t device)
{
  char href[32];
  gen_random_uri(href, sizeof(href));

  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_memb_alloc(&rtc_s);

  if (!rtc) {
    return NULL;
  }

  oc_resource_t *resource =
    rf->get_instance(href, rtypes, bm, interfaces, device);

  if (!resource) {
    oc_memb_free(&rtc_s, rtc);
    return NULL;
  }

  rtc->resource = resource;
  rtc->rf = rf;
  rtc->collection = collection;
  oc_list_add(created_res, rtc);

  if (!resource->set_properties.cb.set_props ||
      !resource->get_properties.cb.get_props) {
    oc_rt_factory_free_created_resource(rtc, rf);
    return NULL;
  }

  return rtc;
}

void
oc_rt_factory_free_created_resource(oc_rt_created_t *rtc, oc_rt_factory_t *rf)
{
  oc_list_remove(created_res, rtc);
  oc_link_t *link =
    oc_get_link_by_uri(rtc->collection, oc_string(rtc->resource->uri),
                       oc_string_len(rtc->resource->uri));
  if (link) {
    oc_collection_remove_link((oc_resource_t *)rtc->collection, link);
    oc_delete_link(link);
  }
  rf->free_instance(rtc->resource);
  oc_memb_free(&rtc_s, rtc);
}

void
oc_fi_factory_free_all_created_resources(void)
{
  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_list_pop(created_res);
  while (rtc) {
    oc_rt_factory_free_created_resource(rtc, rtc->rf);
    rtc = (oc_rt_created_t *)oc_list_pop(created_res);
  }
}

oc_rt_created_t*
oc_rt_get_factory_create_for_resource(oc_resource_t* resource)
{
  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_list_head(created_res);
  while(rtc) {
    if (rtc->resource == resource) {
      return rtc;
    }
    rtc = rtc->next;
  }

  return NULL;
}

void
oc_rt_factory_free_created_resources(size_t device)
{
  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_list_head(created_res), *next;
  while (rtc) {
    next = rtc->next;
    if (rtc->resource->device == device) {
      oc_rt_factory_free_created_resource(rtc, rtc->rf);
    }
    rtc = next;
  }
}
#else  /* OC_SERVER && OC_COLLECTIONS */
typedef int dummy_declaration;
#endif /* OC_SERVER && OC_COLLECTIONS && OC_COLLECTIONS_IF_CREATE */
