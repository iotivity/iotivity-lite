/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef ST_DATA_MANAGER_H
#define ST_DATA_MANAGER_H

#include "oc_helpers.h"

typedef struct st_device_info
{
  oc_string_t device_type;
  oc_string_t device_name;
  oc_string_t spec_version;
  oc_string_t data_model_version;
} st_device_info_t;

typedef struct st_platform_info
{
  oc_string_t manufacturer_name;
  oc_string_t manufacturer_uri;
  oc_string_t manufacturing_date;
  oc_string_t model_number;
  oc_string_t platform_version;
  oc_string_t os_version;
  oc_string_t hardware_version;
  oc_string_t firmware_version;
  oc_string_t vendor_id;
} st_platform_info_t;

typedef struct st_specification
{
  struct st_specification *next;
  st_device_info_t device;
  st_platform_info_t platform;
  int device_idx;
} st_specification_t;

typedef struct st_resource
{
  struct st_resource *next;
  oc_string_t uri;
  oc_string_array_t types;
  uint8_t interfaces;
  uint8_t default_interface;
  uint8_t policy;
  int device_idx;
} st_resource_info_t;

typedef enum {
  ST_PROP_TYPE_BOOL,
  ST_PROP_TYPE_INT,
  ST_PROP_TYPE_DOUBLE,
  ST_PROP_TYPE_STRING,
  ST_PROP_TYPE_OBJECT,
  ST_PROP_TYPE_BYTE,
  ST_PROP_TYPE_INT_ARRAY,
  ST_PROP_TYPE_DOUBLE_ARRAY,
  ST_PROP_TYPE_STRING_ARRAY,
  ST_PROP_TYPE_OBJECT_ARRAY,
} st_property_type_t;

typedef struct st_property
{
  struct st_property *next;
  oc_string_t key;
  int type;
  bool mandatory;
  int rw;
} st_property_t;

#define MAX_NUM_PROPERTIES 3

typedef struct st_resource_type
{
  struct st_resource_type *next;
  oc_string_t type;

#ifdef OC_DYNAMIC_ALLOCATION
  OC_LIST_STRUCT(properties);
#else  /* OC_DYNAMIC_ALLOCATION */
  st_property_t properties[MAX_NUM_PROPERTIES];
  int properties_cnt;
#endif /* !OC_DYNAMIC_ALLOCATION */
} st_resource_type_t;

int st_data_mgr_info_load(void);
void st_data_mgr_info_free(void);
void st_free_device_profile(void);

st_specification_t *st_data_mgr_get_spec_info(void);
st_resource_info_t *st_data_mgr_get_resource_info(void);
st_resource_type_t *st_data_mgr_get_rsc_type_info(const char *rt);

#endif /* ST_DATA_MANAGER_H */
