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
/**
  @file
*/
#ifndef OC_CORE_RES_H
#define OC_CORE_RES_H

#include "oc_ri.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*oc_core_init_platform_cb_t)(void *data);
typedef void (*oc_core_add_device_cb_t)(void *data);

typedef struct oc_platform_info_t
{
  oc_uuid_t pi;
  oc_string_t mfg_name;
  oc_core_init_platform_cb_t init_platform_cb;
  void *data;
} oc_platform_info_t;

typedef struct oc_device_info_t
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
void oc_core_shutdown(void);

oc_platform_info_t *oc_core_init_platform(const char *mfg_name,
                                          oc_core_init_platform_cb_t init_cb,
                                          void *data);

oc_device_info_t *oc_core_add_new_device(const char *uri, const char *rt,
                                         const char *name,
                                         const char *spec_version,
                                         const char *data_model_version,
                                         oc_core_add_device_cb_t add_device_cb,
                                         void *data);

size_t oc_core_get_num_devices(void);

oc_uuid_t *oc_core_get_device_id(size_t device);

oc_device_info_t *oc_core_get_device_info(size_t device);

oc_platform_info_t *oc_core_get_platform_info(void);

void oc_core_encode_interfaces_mask(CborEncoder *parent,
                                    oc_interface_mask_t iface_mask);

oc_resource_t *oc_core_get_resource_by_index(int type, size_t device);

oc_resource_t *oc_core_get_resource_by_uri(const char *uri, size_t device);

void oc_store_uri(const char *s_uri, oc_string_t *d_uri);

void oc_core_populate_resource(int core_resource, size_t device_index,
                               const char *uri, oc_interface_mask_t iface_mask,
                               oc_interface_mask_t default_interface,
                               int properties, oc_request_callback_t get_cb,
                               oc_request_callback_t put_cb,
                               oc_request_callback_t post_cb,
                               oc_request_callback_t delete_cb,
                               int num_resource_types, ...);

bool oc_filter_resource_by_rt(oc_resource_t *resource, oc_request_t *request);

bool oc_core_is_DCR(oc_resource_t *resource, size_t device);

/**
 * set the latency (lat) property in eps of oic.wk.res resource.
 * The latency is implemented globally e.g. for all the resource instances.
 * The default behaviour is that if nothing is set (e.g. value is 0) the lat
 * property will not be framed in the eps property. Setting the value on 0 will
 * cause that the lat property will not be framed in the eps property.
 * @param[in] latency the latency in seconds
 */
void oc_core_set_latency(int latency);

/**
 * retrieves the latency (lat) property in eps of the oic.wk.res resource.
 * the lat value is implemented globally for the stack
 * @return
 *  - the latency in seconds
 */
int oc_core_get_latency(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_CORE_RES_H */
