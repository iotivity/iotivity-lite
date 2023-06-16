/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#include "oc_collection.h"

#if defined(OC_SERVER) && defined(OC_COLLECTIONS) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
#include "api/oc_collection_internal.h"
#include "api/oc_link_internal.h"
#include "api/oc_resource_factory_internal.h"
#include "port/oc_random.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

OC_MEMB(g_rtc_s, oc_rt_created_t, 1);
OC_LIST(g_created_res);

#ifndef OC_MAX_COLLECTIONS_INSTANCE_URI_SIZE
#define OC_MAX_COLLECTIONS_INSTANCE_URI_SIZE (64)
#endif

static void
gen_random_uri(char *uri, size_t uri_length)
{
  static const char alpha[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const size_t alpha_len = sizeof(alpha) - 1;
  uri[0] = '/';
  size_t i = 1;
  while (i < uri_length - 1) {
    unsigned int r = oc_random_value() % alpha_len;
    uri[i++] = alpha[r];
  }
  uri[uri_length - 1] = '\0';
}

/**
 * @brief Find lowest possible unused index value for link in collection.
 *
 * Links in collection have default uris in the format
 * "{$collection uri}/${index}", where index is an integer value >= 1.
 * Collection keeps a list of its links and the list is ordered by the link uri
 * (primarily by length and secondarily by value). With this ordering only a
 * single iteration through the list is required to find the lowest unused index
 * value.
 *
 * @param collection collection with links
 *
 * @return 0            on failure
 *         1..UINT_MAX  on success
 */
static unsigned
find_collection_unique_instance_index(oc_collection_t *collection)
{
  // 2 = "/" and at least one char for index
  const size_t max_collection_uri_len =
    OC_MAX_COLLECTIONS_INSTANCE_URI_SIZE - 2;
  const size_t collection_uri_len = oc_string_len(collection->res.uri);
  if ((collection_uri_len == 0) ||
      (collection_uri_len >= max_collection_uri_len)) {
    return 0;
  }
  const char *collection_uri = oc_string(collection->res.uri);

  unsigned index = 1;
  for (oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
       link != NULL; link = link->next) {
    if ((link->resource == NULL) || (oc_string_len(link->resource->uri) == 0)) {
      continue;
    }

    const size_t link_uri_len = oc_string_len(link->resource->uri);
    // default uri is in the form "${collection href}/${index}" -> length must
    // be at least len(${collection href}) + 2
    if (link_uri_len < collection_uri_len + 2) {
      continue;
    }

    const char *link_uri = oc_string(link->resource->uri);
    // default uri is prefixed by "${collection href}/"
    if ((strncmp(link_uri, collection_uri, collection_uri_len) != 0) ||
        (link_uri[collection_uri_len] != '/')) {
      continue;
    }

    // move past the "${collection href}/" prefix to the part with numeric index
    const char *link_index_str = link_uri + collection_uri_len + 1;
    char *end;
    long link_index = strtol(link_index_str, &end, 10);
    if (end[0] != '\0' || link_index == LONG_MAX || link_index == LONG_MIN) {
      continue;
    }

    // index should have been next value but it is not, since collection->links
    // is ordered it means that it was skipped and we can use it
    if (link_index != (long)index) {
      return index;
    }

    // overflow
    if (index == UINT_MAX) {
      return 0;
    }
    ++index;
  }

  return index;
}

/**
 * @brief Write default uri for the newly created resource.
 *
 * Function tries to create uri for the newly created resource in collection
 * in the format ${collection uri}/${index}, where ${index} is the lowest
 * numerical value not used by some other resource in the collection.
 *
 * @param collection collection of the resource
 * @param uri output buffer for the uri
 * @param uri_size size of the output buffer
 *
 * @return true  uri was successfully generated
 *         false otherwise
 */
static bool
get_collection_instance_uri(oc_collection_t *collection, char *uri,
                            size_t uri_size)
{
  unsigned index = find_collection_unique_instance_index(collection);
  if (index == 0) {
    return false;
  }
  size_t len = oc_string_len(collection->res.uri) + 1;
  if (len > uri_size) {
    // uri too long for output buffer
    return false;
  }
  if (oc_string_len(collection->res.uri) > 0) {
    strncpy(uri, oc_string(collection->res.uri),
            oc_string_len(collection->res.uri));
  }
  uri[oc_string_len(collection->res.uri)] = '/';

  int written = snprintf(NULL, 0, "%d", index);
  if ((written <= 0) || (len + (size_t)written + 1 > uri_size)) {
    // cannot fit the index converted to string into uri
    return false;
  }

  written = snprintf(uri + len, uri_size - len, "%d", index);
  // check for truncation by snprintf
  return (written > 0) && ((size_t)written <= uri_size - len);
}

oc_rt_created_t *
oc_rt_factory_create_resource(oc_collection_t *collection,
                              const oc_string_array_t *rtypes,
                              oc_resource_properties_t bm,
                              oc_interface_mask_t interfaces,
                              oc_rt_factory_t *rf, size_t device)
{
  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_memb_alloc(&g_rtc_s);

  if (!rtc) {
    return NULL;
  }

  char href[OC_MAX_COLLECTIONS_INSTANCE_URI_SIZE];
  bool ok = get_collection_instance_uri(collection, href, sizeof(href));
  if (!ok) {
    // fallback to max 32 char long random uri
    gen_random_uri(href, sizeof(href) > 32 ? 32 : sizeof(href));
  }

  oc_resource_t *resource =
    rf->get_instance(href, rtypes, bm, interfaces, device);

  if (!resource) {
    oc_memb_free(&g_rtc_s, rtc);
    return NULL;
  }

  rtc->resource = resource;
  rtc->rf = rf;
  rtc->collection = collection;
  oc_list_add(g_created_res, rtc);

  if (!resource->set_properties.cb.set_props ||
      !resource->get_properties.cb.get_props) {
    oc_rt_factory_free_created_resource(rtc, rf);
    return NULL;
  }

  return rtc;
}

void
oc_rt_factory_free_created_resource(oc_rt_created_t *rtc,
                                    const oc_rt_factory_t *rf)
{
  if (oc_list_remove2(g_created_res, rtc) == NULL) {
    /* protection against cyclical call of oc_rt_factory_free_created_resource
     * from rf->free_instance */
    return;
  }
  rf->free_instance(rtc->resource);
  oc_memb_free(&g_rtc_s, rtc);
}

void
oc_fi_factory_free_all_created_resources(void)
{
  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_list_head(g_created_res);
  while (rtc != NULL) {
    oc_rt_created_t *next = rtc->next;
    oc_rt_factory_free_created_resource(rtc, rtc->rf);
    rtc = next;
  }
}

oc_rt_created_t *
oc_rt_get_factory_create_for_resource(const oc_resource_t *resource)
{
  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_list_head(g_created_res);
  while (rtc) {
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
  oc_rt_created_t *rtc = (oc_rt_created_t *)oc_list_head(g_created_res);
  while (rtc) {
    oc_rt_created_t *next = rtc->next;
    if (rtc->resource->device == device) {
      oc_rt_factory_free_created_resource(rtc, rtc->rf);
    }
    rtc = next;
  }
}

#endif /* OC_SERVER && OC_COLLECTIONS && OC_COLLECTIONS_IF_CREATE */
