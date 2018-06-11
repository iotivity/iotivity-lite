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

#include "st_data_manager.h"
#include "oc_rep.h"
#include "port/oc_storage.h"
#include "util/oc_mem.h"

#define ST_MAX_DATA_SIZE (1024)
#define ST_MAX_STR_LEN (100)
#define ST_DATA_MANAGER_NAME "st_device_info"

#define ST_DEVICE_KEY "device"

#define ST_SPECIFICATION_KEY "specification"
#define ST_SPEC_DEVICE_KEY "device"
#define ST_SPEC_PLATFORM_KEY "platform"
#define ST_SPEC_DEVICE_TYPE_KEY "deviceType"
#define ST_SPEC_DEVICE_NAME_KEY "deviceName"
#define ST_SPEC_SPEC_VER_KEY "specVersion"
#define ST_SPEC_DATA_MODEL_VER_KEY "dataModelVersion"
#define ST_SPEC_MF_NAME_KEY "manufacturerName"
#define ST_SPEC_MF_URL_KEY "manufacturerUrl"
#define ST_SPEC_MF_DATE_KEY "manufacturingDate"
#define ST_SPEC_MODEL_NUMBER_KEY "modelNumber"
#define ST_SPEC_PLATFORM_VER_KEY "platformVersion"
#define ST_SPEC_OS_VER_KEY "osVersion"
#define ST_SPEC_HARD_VER_KEY "hardwareVersion"
#define ST_SPEC_FIRM_VER_KEY "firmwareVersion"
#define ST_SPEC_VENDER_ID_KEY "vendorId"

#define ST_RESOURCES_KEY "resources"
#define ST_RSC_SINGLE_KEY "single"
#define ST_RSC_URI_KEY "uri"
#define ST_RSC_TYPES_KEY "types"
#define ST_RSC_INTERFACES_KEY "interfaces"
#define ST_RSC_POLICY_KEY "policy"

#define ST_RESOURCE_TYPES_KEY "resourceTypes"

#define ST_RSC_TYPES_TYPE_KEY "type"
#define ST_RSC_TYPES_PROPS_KEY "properties"
#define ST_PROPS_KEY_KEY "key"
#define ST_PROPS_TYPE_KEY "type"
#define ST_PROPS_MANDATORY_KEY "mandatory"
#define ST_PROPS_RW_KEY "rw"

#define st_rep_set_string_with_chk(object, key, value)                         \
  if (value)                                                                   \
    oc_rep_set_text_string(object, key, value);

#define st_string_check_free(str)                                              \
  if (oc_string(*str))                                                         \
  oc_free_string(str)

#define st_string_check_new(str, value, size)                                  \
  if (value && size > 0)                                                       \
  oc_new_string(str, value, size)

OC_LIST(st_specification_list);
OC_MEMB(st_specification_s, st_specification_t, OC_MAX_NUM_DEVICES);

OC_LIST(st_resource_list);
OC_MEMB(st_resource_s, st_resource_t, OC_MAX_APP_RESOURCES *OC_MAX_NUM_DEVICES);

OC_LIST(st_resource_type_list);
OC_MEMB(st_resource_type_s, st_resource_type_t,
        OC_MAX_APP_RESOURCES *OC_MAX_NUM_DEVICES);

static int st_decode_device_data_info(oc_rep_t *rep);

int
st_device_data_load(void)
{
  int ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf) {
    st_print_log("[ST_DATA_MGR] alloc failed!\n");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = 0;
#ifdef OC_SECURITY
  size = oc_storage_read(ST_DATA_MANAGER_NAME, buf, ST_MAX_DATA_SIZE);
#endif
  if (size > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
    oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
    memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
    struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                   rep_objects_alloc, (void *)rep_objects_pool,
                                   0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(buf, (uint16_t)size, &rep);
    ret = st_decode_device_data_info(rep);
    oc_free_rep(rep);
  } else {
    st_store_info_initialize();
  }
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  return ret;
}

static void
remove_all_specifications(void)
{
  st_specification_t *item = oc_list_head(st_specification_list), *next;
  while (item != NULL) {
    next = item->next;
    oc_list_remove(st_specification_list, item);
    st_string_check_free(&item->device.device_type);
    st_string_check_free(&item->device.device_name);
    st_string_check_free(&item->device.spec_version);
    st_string_check_free(&item->device.data_model_version);
    st_string_check_free(&item->platform.manufacturer_name);
    st_string_check_free(&item->platform.manufacturer_uri);
    st_string_check_free(&item->platform.manufacturing_date);
    st_string_check_free(&item->platform.model_number);
    st_string_check_free(&item->platform.platform_version);
    st_string_check_free(&item->platform.os_version);
    st_string_check_free(&item->platform.hardware_version);
    st_string_check_free(&item->platform.firmware_version);
    st_string_check_free(&item->platform.verdor_id);
    oc_memb_free(&st_specification_s, item);
    item = next;
  }
}

static void
remove_all_resources(void)
{
  st_resource_t *item = oc_list_head(st_resource_list), *next;
  while (item != NULL) {
    next = item->next;
    oc_list_remove(st_resource_list, item);
    st_string_check_free(&item->uri);
    if (oc_string_array_get_allocated_size(item->types) > 0) {
      oc_free_string_array(&item->types);
    }
    oc_memb_free(&st_resource_s, item);
    item = next;
  }
}

static void
remove_all_resource_types(void)
{
  st_resource_type_t *item = oc_list_head(st_resource_type_list), *next;
  while (item != NULL) {
    next = item->next;
    oc_list_remove(st_resource_type_list, item);
    st_string_check_free(&item->type);
    st_string_check_free(&item->properties.key);
    oc_memb_free(&st_resource_type_s, item);
    item = next;
  }
}

void
st_device_info_remove(void)
{
  remove_all_specifications();
  remove_all_resources();
  remove_all_resource_types();
}

static int
st_decode_ap_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 4 && memcmp(oc_string(t->name), "ssid", 4) == 0) {
        oc_new_string(&g_store_info.accesspoint.ssid,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "pwd", 3) == 0) {
        oc_new_string(&g_store_info.accesspoint.pwd, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }

  return 0;
}

static int
st_decode_cloud_access_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 9 && memcmp(oc_string(t->name), "ci_server", 9) == 0) {
        oc_new_string(&g_store_info.cloudinfo.ci_server,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "auth_provider", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.auth_provider,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "uid", 3) == 0) {
        oc_new_string(&g_store_info.cloudinfo.uid, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 12 &&
                 memcmp(oc_string(t->name), "access_token", 12) == 0) {
        oc_new_string(&g_store_info.cloudinfo.access_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "refresh_token", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.refresh_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    case OC_REP_INT:
      if (len == 6 && memcmp(oc_string(t->name), "status", 6) == 0) {
        g_store_info.cloudinfo.status = t->value.integer;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }

  return 0;
}

static int
st_decode_spec(int device_index, oc_rep_t *spec_rep)
{
  st_specification_t *spec_info = oc_memb_alloc(&st_specification_s);
  spec_info->device_idx = device_index;

  char *value = NULL;
  int size = 0;
  oc_rep_t *spec_device_rep = NULL;
  if (oc_rep_get_object(spec_rep, ST_SPEC_DEVICE_KEY, &spec_device_rep)) {
    if (oc_rep_get_string(spec_device_rep, ST_SPEC_DEVICE_TYPE_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->device.device_type, value, size);
    }
    if (oc_rep_get_string(spec_device_rep, ST_SPEC_DEVICE_NAME_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->device.device_name, value, size);
    }
    if (oc_rep_get_string(spec_device_rep, ST_SPEC_SPEC_VER_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->device.spec_version, value, size);
    }
    if (oc_rep_get_string(spec_device_rep, ST_SPEC_DATA_MODEL_VER_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->device.data_model_version, value, size);
    }
  } else {
    st_print_log("[ST_DATA_MGR] can't get specification device data\n");
    return -1;
  }

  oc_rep_t *spec_platform_rep = NULL;
  if (oc_rep_get_object(spec_rep, ST_SPEC_PLATFORM_KEY, &spec_platform_rep)) {
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_MF_NAME_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.manufacturer_name, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_MF_URL_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.manufacturer_uri, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_MF_DATE_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.manufacturing_date, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_MODEL_NUMBER_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.model_number, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_PLATFORM_VER_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.platform_version, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_OS_VER_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.os_version, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_HARD_VER_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.hardware_version, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_FIRM_VER_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.firmware_version, value, size);
    }
    if (oc_rep_get_string(spec_platform_rep, ST_SPEC_VENDER_ID_KEY, &value,
                          size)) {
      st_string_check_new(&spec_info->platform.verdor_id, value, size);
    }
  } else {
    st_print_log("[ST_DATA_MGR] can't get specification platform data\n");
    return -1;
  }

  oc_list_add(st_specification_list, spec_info);

  return 0;
}

static int
st_decode_resources(int device_index, oc_rep_t *resources_rep)
{
  oc_rep_t *single_rep;
  if (oc_rep_get_object_array(resources_rep, ST_RSC_SINGLE_KEY, &single_rep)) {
    oc_rep_t *cur = NULL;
    while (cur) {
      st_resource_t *resource_info = oc_memb_alloc(&st_resource_s);
      resource_info->device_idx = device_index;

      char *value = NULL;
      int size = 0;
      if (oc_rep_get_string(cur, ST_RSC_URI_KEY, &value, size)) {
        st_string_check_new(&resource_info->uri, value, size);
      }

      oc_string_array_t array_value;
      if (oc_rep_get_string_array(cur, ST_RSC_TYPES_KEY, &array_value, size)) {
        oc_new_string_array(&resource_info->types, size);
        int i = 0;
        for (i = 0; i < size; i++) {
          value = oc_string_array_get_item(array_value, i);
          oc_string_array_add_item(resource_info->types, value);
        }
      }

      if (oc_rep_get_string_array(cur, ST_RSC_INTERFACES_KEY, &array_value,
                                  size)) {
        int i = 0;
        resource_info->interfaces = 0;
        resource_info->default_interface = 0;
        for (i = 0; i < size; i++) {
          value = oc_string_array_get_item(array_value, i);
          resource_info->interfaces |= oc_ri_get_interface_mask(
            oc_string_array_get_item(array_value, i),
            oc_string_array_get_item_size(array_value, i));
          if (i == 0) {
            resource_info->default_interface = resource_info->interfaces;
          }
        }
      }

      int policy = 0;
      if (oc_rep_get_int(cur, ST_RSC_POLICY_KEY, &policy)) {
        resource_info->policy = policy;
      }

      oc_list_add(st_resource_list, resource_info);
      cur = cur->next;
    }
  } else {
    st_print_log("[ST_DATA_MGR] don't have exist resources\n");
    return -1;
  }

  return 0;
}

static int
st_decode_device(int device_idx, oc_rep_t *device_rep)
{
  oc_rep_t *spec_rep = NULL;
  if (oc_rep_get_object(device_rep, ST_SPECIFICATION_KEY, &spec_rep)) {
    if (st_decode_spec(device_idx, spec_rep) != 0) {
      st_print_log("[ST_DATA_MGR] st_decode_spec failed\n");
      return -1;
    }
  } else {
    st_print_log("[ST_DATA_MGR] can't get specification data\n");
    return -1;
  }

  oc_rep_t *resources_rep = NULL;
  if (oc_rep_get_object(device_rep, ST_RESOURCES_KEY, &resources_rep)) {
    if (st_decode_resources(device_idx, resources_rep) != 0) {
      st_print_log("[ST_DATA_MGR] st_decode_resources failed\n");
      return -1;
    }
  } else {
    st_print_log("[ST_DATA_MGR] can't get resources data\n");
    return -1;
  }

  return 0;
}

static int
st_decode_resource_types(oc_rep_t *rsc_type_rep)
{
  // TODO

  reutnr 0;
}

static int
st_decode_device_data_info(oc_rep_t *rep)
{
  oc_rep_t *device_rep = NULL;
  if (oc_rep_get_object_array(rep, ST_DEVICE_KEY, &device_rep)) {
    oc_rep_t *cur = device_rep;
    int i;
    for (i = 0; cur != NULL; cur = cur->next, i++) {
      st_decode_device(i, cur);
    }
  } else {
    st_print_log("[ST_DATA_MGR] can't get device data\n");
    return -1;
  }

  oc_rep_t *rsc_type_rep = NULL;
  if (oc_rep_get_object_array(rep, ST_RESOURCE_TYPES_KEY, &rsc_type_rep)) {
    oc_rep_t *cur = rsc_type_rep;
    while (cur) {
      st_decode_resource_types(cur);
      cur = cur->next;
    }
  } else {
    st_print_log("[ST_DATA_MGR] can't get device data\n");
    return -1;
  }

  return 0;
}