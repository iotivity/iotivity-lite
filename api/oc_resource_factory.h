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

#ifndef OC_RESOURCE_FACTORY_H
#define OC_RESOURCE_FACTORY_H

#include "oc_api.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct oc_rt_factory_t
{
  struct oc_rt_factory_t *next;
  oc_string_t rt;
  oc_resource_get_instance_t get_instance;
  oc_resource_free_instance_t free_instance;
} oc_rt_factory_t;

typedef struct oc_rt_created_t
{
  struct oc_rt_created_t *next;
  oc_resource_t *resource;
  oc_collection_t *collection;
  oc_rt_factory_t *rf;
} oc_rt_created_t;

oc_rt_created_t *oc_rt_factory_create_resource(oc_collection_t *collection,
                                               oc_string_array_t *rtypes,
                                               oc_resource_properties_t bm,
                                               oc_interface_mask_t interfaces,
                                               oc_rt_factory_t *rf,
                                               size_t device);

void oc_rt_factory_free_created_resource(oc_rt_created_t *rtc,
                                         oc_rt_factory_t *rf);

void oc_rt_factory_free_created_resources(size_t device);

oc_rt_created_t* oc_rt_get_factory_create_for_resource(oc_resource_t* resource);

void oc_fi_factory_free_all_created_resources(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_RESOURCE_FACTORY_H */
