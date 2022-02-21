/*
// Copyright (c) 2016-2019 Intel Corporation
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
/**
  @file
*/
#ifndef OC_COLLECTION_H
#define OC_COLLECTION_H

#include "oc_ri.h"
#include "util/oc_compiler.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_link_params_t
{
  struct oc_link_params_t *next;
  oc_string_t key;
  oc_string_t value;
} oc_link_params_t;

struct oc_link_s
{
  struct oc_link_s *next;
  oc_resource_t *resource;
  oc_interface_mask_t interfaces;
  int64_t ins;
  oc_string_array_t rel;
  OC_LIST_STRUCT(params);
};

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

void oc_link_set_interfaces(oc_link_t *link,
                            oc_interface_mask_t new_interfaces);

OC_NO_DISCARD_RETURN
bool oc_handle_collection_request(oc_method_t method, oc_request_t *request,
                                  oc_interface_mask_t iface_mask,
                                  oc_resource_t *notify_resource);
oc_collection_t *oc_collection_alloc(void);
void oc_collection_free(oc_collection_t *collection);

oc_collection_t *oc_get_next_collection_with_link(oc_resource_t *resource,
                                                  oc_collection_t *start);
oc_collection_t *oc_get_collection_by_uri(const char *uri_path,
                                          size_t uri_path_len, size_t device);
oc_collection_t *oc_collection_get_all(void);
oc_link_t *oc_get_link_by_uri(oc_collection_t *collection, const char *uri_path,
                              int uri_path_len);

bool oc_check_if_collection(oc_resource_t *resource);
void oc_collection_add(oc_collection_t *collection);
#ifdef OC_COLLECTIONS_IF_CREATE
void oc_collections_free_rt_factories(void);
#endif /* OC_COLLECTIONS_IF_CREATE */

#ifdef __cplusplus
}
#endif

#endif /* OC_COLLECTION_H */
