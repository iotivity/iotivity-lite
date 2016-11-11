/*
// Copyright (c) 2016 Intel Corporation
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

#ifndef OC_COLLECTION_H
#define OC_COLLECTION_H

#include "oc_ri.h"
#include "util/oc_list.h"

struct oc_link_s
{
  struct oc_link_s *next;
  oc_resource_t *resource;
  oc_string_t href;
  oc_string_array_t types;
  oc_interface_mask_t interfaces;
  oc_string_t bp_key;
  oc_string_t bp_value;
  oc_string_array_t rel;
};

struct oc_collection_s
{
  struct oc_collection_s *next;
  int device;
  oc_string_t uri;
  oc_string_array_t types;
  oc_interface_mask_t interfaces;
  oc_interface_mask_t default_interface;
  oc_resource_properties_t properties;
  OC_LIST_STRUCT(links);
};

bool oc_handle_collection_request(oc_method_t method, oc_request_t *request,
                                  oc_interface_mask_t interface);
oc_collection_t *oc_collection_alloc();
oc_collection_t *oc_get_collection_by_uri(const char *uri_path,
                                          int uri_path_len);
oc_collection_t *oc_collection_get_all();
bool oc_collection_add(oc_collection_t *collection);

#endif /* OC_COLLECTION_H */
