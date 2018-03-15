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

#ifndef OC_CORE_RES_H
#define OC_CORE_RES_H

#include "oc_ri.h"

typedef void (*oc_core_init_platform_cb_t)(void *data);
typedef void (*oc_core_add_device_cb_t)(void *data);

typedef struct
{
  oc_uuid_t pi;
  oc_string_t mfg_name;
  oc_core_init_platform_cb_t init_platform_cb;
  void *data;
} oc_platform_info_t;

typedef struct
{
  oc_uuid_t di;
  oc_uuid_t piid;
  oc_string_t name;
  oc_string_t icv;
  oc_string_t dmv;
  oc_core_add_device_cb_t add_device_cb;
  void *data;
} oc_device_info_t;

void oc_core_init(void);

oc_platform_info_t *oc_core_init_platform(const char *mfg_name,
                                          oc_core_init_platform_cb_t init_cb,
                                          void *data);

oc_device_info_t *oc_core_add_new_device(const char *uri, const char *rt,
                                         const char *name,
                                         const char *spec_version,
                                         const char *data_model_version,
                                         oc_core_add_device_cb_t add_device_cb,
                                         void *data);

int oc_core_get_num_devices(void);

oc_uuid_t *oc_core_get_device_id(int device);

oc_device_info_t *oc_core_get_device_info(int device);

oc_platform_info_t *oc_core_get_platform_info(void);

void oc_core_encode_interfaces_mask(CborEncoder *parent,
                                    oc_interface_mask_t interface);

oc_resource_t *oc_core_get_resource_by_index(int type, int device);

oc_resource_t *oc_core_get_resource_by_uri(const char *uri, int device);

void oc_store_uri(const char *s_uri, oc_string_t *d_uri);

void oc_core_populate_resource(
  int core_resource, int device_index, const char *uri,
  oc_interface_mask_t interfaces, oc_interface_mask_t default_interface,
  oc_resource_properties_t properties, oc_request_callback_t get,
  oc_request_callback_t put, oc_request_callback_t post,
  oc_request_callback_t delete, int num_resource_types, ...);

void oc_core_regen_unique_ids(int device);

bool oc_filter_resource_by_rt(oc_resource_t *resource, oc_request_t *request);

#endif /* OC_CORE_RES_H */
