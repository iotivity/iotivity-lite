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

typedef struct st_specification
{
  struct st_specification *next;
  struct st_device_info_t
  {
    oc_string_t device_type;
    oc_string_t device_name;
    oc_string_t spec_version;
    oc_string_t data_model_version;
  } device;
  struct st_platform_info_t
  {
    oc_string_t manufacturer_name;
    oc_string_t manufacturer_uri;
    oc_string_t manufacturing_date;
    oc_string_t model_number;
    oc_string_t platform_version;
    oc_string_t os_version;
    oc_string_t hardware_version;
    oc_string_t firmware_version;
    oc_string_t verdor_id;
  } platform;
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
} st_resource_t;

typedef struct st_resource_type
{
  struct st_resource_type *next;
  oc_string_t type;
  struct st_data_property_t
  {
    oc_string_t key;
    int type;
    bool mandatory;
    int rw;
  } properties;
} st_resource_type_t;

int st_device_data_load(void);

#endif /* ST_DATA_MANAGER_H */