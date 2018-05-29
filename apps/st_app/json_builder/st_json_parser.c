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

#include "device_specification.h"
#include "st_hashmap.h"
#include "json/cJSON.h"
#include "util/oc_mem.h"
#include "../st_port.h"
#include "port/oc_assert.h"

/* device define JSON */
#define KEY_DEVICE                                              "device"
#define KEY_DEVICE_SPECIFICATION                                "specification"

/* oic.d */
#define KEY_DEVICE_SPECIFICATION_DEVICE                         "device"
#define KEY_DEVICE_SPECIFICATION_DEVICE_DEVICETYPE              "deviceType"
#define KEY_DEVICE_SPECIFICATION_DEVICE_DEVICENAME              "deviceName"

/* oic.p */
#define KEY_DEVICE_SPECIFICATION_PLATFORM                       "platform"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_MANUFACTURERNAME      "manufacturerName"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_MANUFACTURERURL       "manufacturerUrl"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_MANUFACTURINGDATE     "manufacturingDate"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_MODELNUMBER           "modelNumber"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_PLATFORMVERSION       "platformVersion"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_OSVERSION             "osVersion"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_HARDWAREVERSION       "hardwareVersion"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_FIRMWAREVERSION       "firmwareVersion"
#define KEY_DEVICE_SPECIFICATION_PLATFORM_VENDORID              "vendorId"

/* resources */
#define KEY_RESOURCES                                           "resources"
#define KEY_RESOURCES_SIG                                       "single"
#define KEY_DEVICE_RESOURCE_URI                                 "uri"
#define KEY_DEVICE_RESOURCE_TYPES                               "types"
#define KEY_DEVICE_RESOURCE_INTERFACES                          "interfaces"
#define KEY_DEVICE_RESOURCE_POLICY                              "policy"

/* resourceTypes */
#define KEY_RESOURCES_TYPE                                      "resourceTypes"
#define KEY_DEVICE_RESOURCETYPE_TYPE                            "type"
#define KEY_DEVICE_RESOURCETYPE_PROPERTIES                      "properties"
#define KEY_DEVICE_RESOURCETYPE_PROPERTIES_KEY                  "key"
#define KEY_DEVICE_RESOURCETYPE_PROPERTIES_TYPE                 "type"
#define KEY_DEVICE_RESOURCETYPE_PROPERTIES_MANDATORY            "mandatory"
#define KEY_DEVICE_RESOURCETYPE_PROPERTIES_RW                   "rw"

/* configuration */
#define KEY_CONFIGURATION                                       "configuration"
#define KEY_CONFIGURATION_EASYSETUP                             "easySetup"
#define KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY                "connectivity"
#define KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_TYPE           "type"
#define KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_SOFTAP         "softAP"
#define KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_SOFTAP_SETUPID "setupId"
#define KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_SOFTAP_ARTIK   "artik"
#define KEY_CONFIGURATION_EASYSETUP_OWNERSHIP                   "ownershipTransferMethod"
#define KEY_CONFIGURATION_WIFI                                  "wifi"
#define KEY_CONFIGURATION_WIFI_INTERFACES                       "interfaces"
#define KEY_CONFIGURATION_WIFI_FREQUENCY                        "frequency"
#define KEY_CONFIGURATION_FILEPATH                              "filePath"
#define KEY_CONFIGURATION_FILEPATH_SVRDB                        "svrdb"
#define KEY_CONFIGURATION_FILEPATH_PROVISIONING                 "provisioning"
#define KEY_CONFIGURATION_FILEPATH_CERTIFICATE                  "certificate"
#define KEY_CONFIGURATION_FILEPATH_PRIVATEKEY                   "privateKey"

/* validate_attribute_in_request */
#define CHECK_BIT(var, pos)         (((var)>>(pos)) & 1)

#define CHECK_READABLE(var)         CHECK_BIT(var, 0)
#define CHECK_WRITABLE(var)         CHECK_BIT(var, 1)

#define CHECK_DISCOVERABLE(var)     CHECK_BIT(var, 0)
#define CHECK_OBSERVABLE(var)       CHECK_BIT(var, 1)
#define CHECK_SECURE(var)           CHECK_BIT(var, 2)

/* etc */
#define MAX_ATTRIBUTE_LENGTH        (64)
#define MAX_FILE_PATH_LENGTH            (33)
#define MAX_PROPERTY_CNT                (20)
#define MAX_PROPERTY_LENGTH_OCF         (64)

#define MAX_RID_LENGTH        10
#define MAX_IT_CNT            5
#define MAX_RT_CNT            10
#define MAX_URI_LEN           128

#define MAX_KEY_LENGTH        50
#define MAX_SPEC_LENGTH       7

typedef enum {
	WiFi_24G = 0,
	WiFi_5G,
	WiFi_BOTH,
	WiFi_FREQ_EOF
} wifi_freq_e;

typedef int8_t INT8;

static volatile int resource_type_cnt = 0;

static char g_things_cloud_file_path[MAX_FILE_PATH_LENGTH + 1] = { 0 };
static char g_svrdb_file_path[MAX_FILE_PATH_LENGTH + 1] = { 0 };
static char g_certificate_file_path[MAX_FILE_PATH_LENGTH + 1] = { 0 };
static char g_private_key_file_path[MAX_FILE_PATH_LENGTH + 1] = { 0 };

static char *g_firmware_version;
static char *g_vendor_id;
static char *g_model_number;

static char *g_manufacturer_name;
static char *g_setup_id;
static bool is_artik;

static int g_wifi_interface;
static wifi_freq_e g_wifi_freq;

static int g_ownership_transfer_method = 0;

static struct hashmap_s *g_resource_type_hmap = NULL;	// map for resource types
static struct hashmap_s *g_device_hmap = NULL;

typedef enum {
	es_conn_type_none = 0,
	es_conn_type_softap = 1,
	es_conn_type_ble = 2,
} easysetup_connectivity_type_e;

static easysetup_connectivity_type_e es_conn_type = es_conn_type_none;

typedef struct things_attribute_info_s {
	char key[MAX_KEY_LENGTH];
	char spec[MAX_SPEC_LENGTH];
	int type;
	bool mandatory;
	int rw;
} things_attribute_info_s;

typedef struct st_resource_type_s {
	char rt[MAX_PROPERTY_LENGTH_OCF];
	int prop_cnt;
	struct things_attribute_info_s *prop[MAX_PROPERTY_CNT];
} st_resource_type_s;

typedef struct things_resource_info_s {
	char rid[MAX_RID_LENGTH];
	char uri[MAX_URI_LEN];
	char *interface_types[MAX_IT_CNT];
	char *resource_types[MAX_RT_CNT];

	int if_cnt;
	int rt_cnt;
	bool observable;
	int policy;
} things_resource_info_s;

typedef struct st_device_s {
	int no;
	char *type;
	char *name;
	char *manufacturer_name;
	char *manufacturer_url;
	char *manufacturing_date;
	char *model_num;
	char *ver_p;	// mnpv
	char *ver_os;	// mnhw
	char *ver_hw;	// mnhw
	char *ver_fw;	// mnfv
	char *device_id;	// mnfv
	char *vender_id;	// mnfv
	things_resource_info_s *single;

	int capa_cnt;
	int col_cnt;
	int sig_cnt;
	int is_physical;

} st_device_s;

static struct things_attribute_info_s *create_property()
{
	struct things_attribute_info_s *property = oc_mem_malloc(sizeof(things_attribute_info_s));

	memset(property->key, 0, (size_t) MAX_KEY_LENGTH);
	property->type = 0;
	property->mandatory = false;
	property->rw = 0;

	return property;
}

static struct st_resource_type_s *create_resource_type()
{
	struct st_resource_type_s *type = oc_mem_malloc(sizeof(st_resource_type_s));

	if (type == NULL) {
		st_print_log("[ST_APP] Failed to create_resource_type\n");
		return NULL;
	}

	memset(type->rt, 0, (size_t) MAX_ATTRIBUTE_LENGTH);
	memset(type->prop, 0, (size_t)(sizeof(things_attribute_info_s*) * MAX_PROPERTY_CNT));
	type->prop_cnt = 0;

	return type;
}

static st_device_s *create_device()
{
	st_device_s *device = oc_mem_malloc(sizeof(st_device_s));

	if (device == NULL) {
		st_print_log("[ST_APP] Failed to create_device\n");
		return NULL;
	}

	device->type = NULL;
	device->name = NULL;
	device->manufacturer_name = NULL;
	device->manufacturer_url = NULL;
	device->manufacturing_date = NULL;
	device->model_num = NULL;
	device->ver_p = NULL;
	device->ver_os = NULL;
	device->ver_hw = NULL;
	device->ver_fw = NULL;
	device->device_id = NULL;
	device->vender_id = NULL;

	device->no = -1;
	device->capa_cnt = 0;
	device->col_cnt = 0;
	device->sig_cnt = 0;
	device->is_physical = 0;
	device->single = NULL;

	return device;
}
/*
static void delete_resource_type(st_resource_type_s *type)
{
	oc_mem_free(type);
}

static struct things_resource_info_s *create_resource()
{
	struct things_resource_info_s *resource = oc_mem_malloc(sizeof(things_resource_info_s));

	if (resource == NULL) {
		st_print_log("[ST_APP] Failed to create_resource\n");
		return NULL;
	}

	memset(resource->uri, 0, sizeof(resource->uri));
	memset(resource->interface_types, 0, sizeof(resource->interface_types));
	memset(resource->resource_types, 0, sizeof(resource->resource_types));
	resource->policy = 0;
	resource->if_cnt = 0;
	resource->rt_cnt = 0;

	return resource;
}

static void delete_device(st_device_s *device)
{
    if (device != NULL) {
        oc_mem_free(device->type);
        oc_mem_free(device->name);
        oc_mem_free(device->manufacturer_name);
        oc_mem_free(device->manufacturer_url);
        oc_mem_free(device->manufacturing_date);
        oc_mem_free(device->model_num);
        oc_mem_free(device->ver_p);
        oc_mem_free(device->ver_os);
        oc_mem_free(device->ver_hw);
        oc_mem_free(device->ver_fw);
        oc_mem_free(device->device_id);
        oc_mem_free(device->vender_id);
        oc_mem_free(device->single);
        oc_mem_free(device);
    }
}
*/

int st_manager_json_parse(void)
{
    int ret = 0;
    cJSON *root = NULL;

    // Parse the JSON device specification
    root = cJSON_Parse((const char *)device_specification);
    oc_assert(root != NULL);

    st_device_s *node = NULL;

    // Device Items
    cJSON *devices = cJSON_GetObjectItem(root, KEY_DEVICE);
    if (devices == NULL) {
        st_print_log("[ST_APP] device is NULL\n");
        ret = __LINE__;
        goto JSON_ERROR;
    }

    int device_cnt = cJSON_GetArraySize(devices);
    st_print_log("[ST_APP] device_cnt = %d\n", device_cnt);
    if (g_device_hmap == NULL) {
        g_device_hmap = hashmap_create(device_cnt);
    }

    if (g_device_hmap == NULL) {
        st_print_log("[ST_APP] g_device_hmap is NULL\n");
        ret = __LINE__;
        goto JSON_ERROR;
    }

    st_print_log("[ST_APP] device_cnt of hashmap = %d\n", hashmap_count(g_device_hmap));

    for (int device_num = 0; device_num < device_cnt; device_num++) {
        st_print_log("[ST_APP] [DEVICE] ============================================\n");

        node = create_device();
        node->no = device_num;
        node->is_physical = 1;

        cJSON *device = cJSON_GetArrayItem(devices, device_num);
        cJSON *specification = cJSON_GetObjectItem(device, KEY_DEVICE_SPECIFICATION);
        if (specification != NULL) {
            cJSON *spec_device = cJSON_GetObjectItem(specification, KEY_DEVICE_SPECIFICATION_DEVICE);
            if (spec_device != NULL) {
                cJSON *device_type = cJSON_GetObjectItem(spec_device, KEY_DEVICE_SPECIFICATION_DEVICE_DEVICETYPE);
                cJSON *device_name = cJSON_GetObjectItem(spec_device, KEY_DEVICE_SPECIFICATION_DEVICE_DEVICENAME);
                /* spec_ver & data_model_ver is not supported */

                if (device_type != NULL) {
                    node->type = (char *) oc_mem_malloc(sizeof(char) * (strlen(device_type->valuestring) + 1));
                    strncpy(node->type, device_type->valuestring, strlen(device_type->valuestring) + 1);
                }

                if (device_name != NULL) {
                    node->name = (char *) oc_mem_malloc(sizeof(char) * (strlen(device_name->valuestring) + 1));
                    strncpy(node->name, device_name->valuestring, strlen(device_name->valuestring) + 1);
                }
            }

            cJSON *spec_platform = cJSON_GetObjectItem(specification, KEY_DEVICE_SPECIFICATION_PLATFORM);
            if (spec_platform != NULL) {
                cJSON *manufacturer_name = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_MANUFACTURERNAME);
                cJSON *manufacturer_url = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_MANUFACTURERURL);
                cJSON *manufacturing_date = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_MANUFACTURINGDATE);
                cJSON *model_number = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_MODELNUMBER);
                cJSON *platform_version = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_PLATFORMVERSION);
                cJSON *os_version = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_OSVERSION);
                cJSON *hardware_version = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_HARDWAREVERSION);
                cJSON *firmware_version = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_FIRMWAREVERSION);
                cJSON *vendor_id = cJSON_GetObjectItem(spec_platform, KEY_DEVICE_SPECIFICATION_PLATFORM_VENDORID);

                if (manufacturer_name != NULL) {
                    if (strlen(manufacturer_name->valuestring) != 4) {
                        st_print_log("[ST_APP] manufacturer_name exceeds 4 bytes. please check (4 bytes are fixed sizes.)\n");
                        ret = __LINE__;
                        goto JSON_ERROR;
                    }
                    node->manufacturer_name = (char *) oc_mem_malloc(sizeof(char) * (strlen(manufacturer_name->valuestring) + 1));
                    strncpy(node->manufacturer_name, manufacturer_name->valuestring, strlen(manufacturer_name->valuestring) + 1);
                }
                if (manufacturer_url != NULL) {
                    node->manufacturer_url = (char *) oc_mem_malloc(sizeof(char) * (strlen(manufacturer_url->valuestring) + 1));
                    strncpy(node->manufacturer_url, manufacturer_url->valuestring, strlen(manufacturer_url->valuestring) + 1);
                }
                if (manufacturing_date != NULL) {
                    node->manufacturing_date = (char *) oc_mem_malloc(sizeof(char) * (strlen(manufacturing_date->valuestring) + 1));
                    strncpy(node->manufacturing_date, manufacturing_date->valuestring, strlen(manufacturing_date->valuestring) + 1);
                }
                if (model_number != NULL) {
                    node->model_num = (char *) oc_mem_malloc(sizeof(char) * (strlen(model_number->valuestring) + 1));
                    strncpy(node->model_num, model_number->valuestring, strlen(model_number->valuestring) + 1);

                    g_model_number = (char *) oc_mem_malloc(sizeof(char) * strlen(model_number->valuestring) + 1);
                    strncpy(g_model_number, model_number->valuestring, strlen(model_number->valuestring) + 1);
                }
                if (platform_version != NULL) {
                    node->ver_p = (char *) oc_mem_malloc(sizeof(char) * (strlen(platform_version->valuestring) + 1));
                    strncpy(node->ver_p, platform_version->valuestring, strlen(platform_version->valuestring) + 1);
                }
                if (os_version != NULL) {
                    node->ver_os = (char *) oc_mem_malloc(sizeof(char) + (strlen(os_version->valuestring) + 1));
                    strncpy(node->ver_os, os_version->valuestring, strlen(os_version->valuestring) + 1);
                }
                if (hardware_version != NULL) {
                    node->ver_hw = (char *) oc_mem_malloc(sizeof(char) * (strlen(hardware_version->valuestring) + 1));
                    strncpy(node->ver_hw, hardware_version->valuestring, strlen(hardware_version->valuestring) + 1);
                }
                if (firmware_version != NULL) {
                    node->ver_fw = (char *) oc_mem_malloc(sizeof(char) * (strlen(firmware_version->valuestring) + 1));
                    strncpy(node->ver_fw, firmware_version->valuestring, strlen(firmware_version->valuestring) + 1);

                    g_firmware_version = (char *) oc_mem_malloc(sizeof(char) * strlen(firmware_version->valuestring) + 1);
                    strncpy(g_firmware_version, firmware_version->valuestring, strlen(firmware_version->valuestring) + 1);
                }
                if (vendor_id != NULL) {
                    node->vender_id = (char *) oc_mem_malloc(sizeof(char) * (strlen(vendor_id->valuestring) + 1));
                    strncpy(node->vender_id, vendor_id->valuestring, strlen(vendor_id->valuestring) + 1);

                    g_vendor_id = (char *) oc_mem_malloc(sizeof(char) * strlen(vendor_id->valuestring) + 1);
                    strncpy(g_vendor_id, vendor_id->valuestring, strlen(vendor_id->valuestring) + 1);
                }
            }
        }
        st_print_log("[ST_APP] [DEVICE] No. : %d\n", (node->no));
        st_print_log("[ST_APP] [DEVICE] type : %s\n", (node->type));
        st_print_log("[ST_APP] [DEVICE] name : %s\n", (node->name));
        st_print_log("[ST_APP] [DEVICE] mf_name : %s\n", (node->manufacturer_name));
        st_print_log("[ST_APP] [DEVICE] mf_url : %s\n", (node->manufacturer_url));
        st_print_log("[ST_APP] [DEVICE] mf_date : %s\n", (node->manufacturing_date));
        st_print_log("[ST_APP] [DEVICE] model num : %s\n", (node->model_num));
        st_print_log("[ST_APP] [DEVICE] plat. ver : %s\n", (node->ver_p));
        st_print_log("[ST_APP] [DEVICE] os version : %s\n", (node->ver_os));
        st_print_log("[ST_APP] [DEVICE] hw version : %s\n", (node->ver_hw));
        st_print_log("[ST_APP] [DEVICE] fw version : %s\n", (node->ver_fw));
        st_print_log("[ST_APP] [DEVICE] vender id : %s\n", (node->vender_id));

        cJSON *resources = cJSON_GetObjectItem(device, KEY_RESOURCES);
        if (resources != NULL) {
            cJSON *single = cJSON_GetObjectItem(resources, KEY_RESOURCES_SIG);
            if (single != NULL) {
                node->sig_cnt = cJSON_GetArraySize(single);
                st_print_log("[ST_APP] [DEVICE] Resources for Single Usage Cnt : %d\n", node->sig_cnt);

                node->single = (things_resource_info_s *)oc_mem_malloc(sizeof(things_resource_info_s) * (node->sig_cnt));
                if (node->single == NULL) {
                    st_print_log("[ST_APP] [SINGLE] resource is NULL\n");
                    ret = __LINE__;
                    goto JSON_ERROR;
                }

                for (int iter = 0; iter < node->sig_cnt; iter++) {
                    cJSON *res = cJSON_GetArrayItem(single, iter);
                    if (res != NULL) {
                        cJSON *uri = cJSON_GetObjectItem(res, KEY_DEVICE_RESOURCE_URI);
                        if (uri != NULL) {
                            memcpy(node->single[iter].uri, uri->valuestring, strlen(uri->valuestring) + 1);
                        }

                        cJSON *types = cJSON_GetObjectItem(res, KEY_DEVICE_RESOURCE_TYPES);
                        if (types != NULL) {
                            int type_cnt = cJSON_GetArraySize(types);
                            node->single[iter].rt_cnt = type_cnt;
                            for (int typeiter = 0; typeiter < type_cnt; typeiter++) {
                                cJSON *type = cJSON_GetArrayItem(types, typeiter);
                                node->single[iter].resource_types[typeiter] = oc_mem_malloc(sizeof(char) * strlen(type->valuestring) + 1);
                                memcpy(node->single[iter].resource_types[typeiter], type->valuestring, strlen(type->valuestring) + 1);
                            }
                        } else {
                            st_print_log("[ST_APP] [SINGLE] resource type is NULL\n");
                            ret = __LINE__;
                            goto JSON_ERROR;
                        }
                        cJSON *interfaces = cJSON_GetObjectItem(res, KEY_DEVICE_RESOURCE_INTERFACES);
                        if (interfaces != NULL) {
                            int if_cnt = cJSON_GetArraySize(interfaces);
                            node->single[iter].if_cnt = if_cnt;
                            for (int ifiter = 0; ifiter < if_cnt; ifiter++) {
                                cJSON *interface = cJSON_GetArrayItem(interfaces, ifiter);
                                node->single[iter].interface_types[ifiter] = oc_mem_malloc(sizeof(char) * strlen(interface->valuestring) + 1);
                                memcpy(node->single[iter].interface_types[ifiter], interface->valuestring, strlen(interface->valuestring) + 1);
                            }
                        } else {
                            st_print_log("[ST_APP] [SINGLE] resource interface is NULL\n");
                            ret = __LINE__;
                            goto JSON_ERROR;
                        }
                        cJSON *policy = cJSON_GetObjectItem(res, KEY_DEVICE_RESOURCE_POLICY);
                        if (policy != NULL) {
                            node->single[iter].policy = policy->valueint;
                        } else {
                            st_print_log("[ST_APP] [SINGLE] resource policy is NULL\n");
                            ret = __LINE__;
                            goto JSON_ERROR;
                        }

                    }
                }
                st_print_log("[ST_APP] [SINGLE] Resources for Single Usage Cnt : %d\n", node->sig_cnt);
            } else {
                st_print_log("[ST_APP] [SINGLE] Reosurces Not Exist\n");
            }
        } else {
            st_print_log("[ST_APP] Reosurces Not Exist\n");
        }
        hashmap_insert(g_device_hmap, node, (unsigned long)device_num);
    }

    st_print_log("[ST_APP] [DEVICE] ============================================\n");
    st_print_log("[ST_APP] [DEVICE] Total Device Num : %d\n", (int)hashmap_count(g_device_hmap));

    // for resourceType
    struct st_resource_type_s *restype = NULL;
    cJSON *resource_types = cJSON_GetObjectItem(root, KEY_RESOURCES_TYPE);
    if (resource_types != NULL) {
        resource_type_cnt = cJSON_GetArraySize(resource_types);
        g_resource_type_hmap = hashmap_create(resource_type_cnt);

        st_print_log("[ST_APP] Resource Types Cnt : %d\n", resource_type_cnt);
        for (int i = 0; i < resource_type_cnt; i++) {
            int index = 0;

            restype = create_resource_type();

            cJSON *cj_rt = cJSON_GetArrayItem(resource_types, i);
            cJSON *rtype = cJSON_GetObjectItem(cj_rt, KEY_DEVICE_RESOURCETYPE_TYPE);
            cJSON *properties = cJSON_GetObjectItem(cj_rt, KEY_DEVICE_RESOURCETYPE_PROPERTIES);

            if (rtype != NULL) {
                index = hashmap_get_hashval((unsigned char *)rtype->valuestring);
                memcpy(restype->rt, rtype->valuestring, strlen(rtype->valuestring) + 1);

                if (properties != NULL) {
                    restype->prop_cnt = cJSON_GetArraySize(properties);

                    for (int iter2 = 0; iter2 < (restype->prop_cnt); iter2++) {
                        cJSON *attr = cJSON_GetArrayItem(properties, iter2);
                        cJSON *key = cJSON_GetObjectItem(attr, KEY_DEVICE_RESOURCETYPE_PROPERTIES_KEY);
                        cJSON *type = cJSON_GetObjectItem(attr, KEY_DEVICE_RESOURCETYPE_PROPERTIES_TYPE);
                        cJSON *mandatory = cJSON_GetObjectItem(attr, KEY_DEVICE_RESOURCETYPE_PROPERTIES_MANDATORY);
                        cJSON *rw = cJSON_GetObjectItem(attr, KEY_DEVICE_RESOURCETYPE_PROPERTIES_RW);
                        restype->prop[iter2] = create_property();
                        if (key->valuestring != NULL) {
                            memcpy(restype->prop[iter2]->key, key->valuestring, strlen(key->valuestring) + 1);
                        }
                        if (type != NULL && type->type == cJSON_Number) {
                            restype->prop[iter2]->type = type->valueint;
                        }

                        if (mandatory->type == cJSON_True) {
                            restype->prop[iter2]->mandatory = true;
                        } else {
                            restype->prop[iter2]->mandatory = false;
                        }

                        restype->prop[iter2]->rw = rw->valueint;
                    }
                } else {
                    st_print_log("[ST_APP] Not Attribute Exist~!!!! \n");
                }
                hashmap_insert(g_resource_type_hmap, restype, index);
            }
        }
    }

    //for configuration
    cJSON *configuration = cJSON_GetObjectItem(root, KEY_CONFIGURATION);
    if (configuration != NULL) {
        int connectivity_type = 0;

        cJSON *easysetup = cJSON_GetObjectItem(configuration, KEY_CONFIGURATION_EASYSETUP);
        if (easysetup != NULL) {
            cJSON *connectivity = cJSON_GetObjectItem(easysetup, KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY);
            if (connectivity != NULL) {
                cJSON *type = cJSON_GetObjectItem(connectivity, KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_TYPE);
                connectivity_type = type->valueint;
                st_print_log("[ST_APP] [configuration] type       : %d\n", connectivity_type);
                if (connectivity_type == 1) {
                    es_conn_type = es_conn_type_softap;
                    cJSON *softap = cJSON_GetObjectItem(connectivity, KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_SOFTAP);
                    if (softap != NULL) {
                        cJSON *setup_id = cJSON_GetObjectItem(softap, KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_SOFTAP_SETUPID);
                        cJSON *artik = cJSON_GetObjectItem(softap, KEY_CONFIGURATION_EASYSETUP_CONNECTIVITY_SOFTAP_ARTIK);

                        if (setup_id != NULL) {
                            if (strlen(setup_id->valuestring) != 3) {
                                st_print_log("[ST_APP] setup_id exceeds 3 bytes. please check (3 bytes are fixed sizes.)\n");
                                ret = __LINE__;
                                goto JSON_ERROR;
                            }
                            is_artik = false;
                            if (artik->type == cJSON_True) {
                                is_artik = true;
                            }

                            st_print_log("[ST_APP] [configuration] manufature_name : %s / setup_id : %s / artik : %d\n", node->manufacturer_name, setup_id->valuestring, is_artik);

                            g_manufacturer_name = oc_mem_malloc(sizeof(char) * strlen(node->manufacturer_name) + 1);
                            strncpy(g_manufacturer_name, node->manufacturer_name, strlen(node->manufacturer_name) + 1);

                            g_setup_id = oc_mem_malloc(sizeof(char) * strlen(setup_id->valuestring) + 1);
                            strncpy(g_setup_id, setup_id->valuestring, strlen(setup_id->valuestring) + 1);
                        } else {
                            st_print_log("[ST_APP] [configuration] setup_id is NULL\n");
                            ret = __LINE__;
                            goto JSON_ERROR;
                        }
                    }
                } else if (connectivity_type == 2) {
                    //TO DO
                    es_conn_type = es_conn_type_ble;
                } else {
                    st_print_log("[ST_APP] [configuration] connectivity_type is unknown\n");
                    ret = __LINE__;
                    goto JSON_ERROR;
                }
            } else {
                st_print_log("[ST_APP] [configuration] connectivity_type is unknown\n");
                ret = __LINE__;
                goto JSON_ERROR;
            }

            cJSON *ownership_transfer_method = cJSON_GetObjectItem(easysetup, KEY_CONFIGURATION_EASYSETUP_OWNERSHIP);
            if (ownership_transfer_method != NULL) {
                g_ownership_transfer_method = ownership_transfer_method->valueint;
                st_print_log("[ST_APP] [configuration] ownership_transfer_method : %d\n", g_ownership_transfer_method);
            } else {
                st_print_log("[ST_APP] connectivity is NULL\n");
                ret = __LINE__;
                goto JSON_ERROR;
            }

        }
        cJSON *wifi = cJSON_GetObjectItem(configuration, KEY_CONFIGURATION_WIFI);
        if (wifi != NULL) {
            cJSON *wifi_interfaces = cJSON_GetObjectItem(wifi, KEY_CONFIGURATION_WIFI_INTERFACES);
            cJSON *wifi_frequency = cJSON_GetObjectItem(wifi, KEY_CONFIGURATION_WIFI_FREQUENCY);
            if (wifi_interfaces != NULL && wifi_frequency != NULL) {
                st_print_log("[ST_APP] [configuration] wifi_interfaces : %d / wifi_frequency : %d\n", wifi_interfaces->valueint, wifi_frequency->valueint);
                g_wifi_interface = wifi_interfaces->valueint;

                if (wifi_frequency->valueint == 1) {
                    g_wifi_freq = WiFi_24G;
                } else if (wifi_frequency->valueint == 2) {
                    g_wifi_freq = WiFi_5G;
                } else if (wifi_frequency->valueint == 3) {
                    g_wifi_freq = WiFi_BOTH;
                } else {
                    st_print_log("[ST_APP] unknown wifi freq value\n");
                }
            } else {
                st_print_log("[ST_APP] [configuration] wifi_interfaces is NULL or wifi_frequency is NULL\n");
                ret = __LINE__;
                goto JSON_ERROR;
            }
        } else {
            st_print_log("[ST_APP] [configuration] wifi is NULL\n");
            ret = __LINE__;
            goto JSON_ERROR;
        }
        cJSON *file_path = cJSON_GetObjectItem(configuration, KEY_CONFIGURATION_FILEPATH);
        if (file_path != NULL) {
            cJSON *svrdb = cJSON_GetObjectItem(file_path, KEY_CONFIGURATION_FILEPATH_SVRDB);
            cJSON *provisioning = cJSON_GetObjectItem(file_path, KEY_CONFIGURATION_FILEPATH_PROVISIONING);
            cJSON *certificate = cJSON_GetObjectItem(file_path, KEY_CONFIGURATION_FILEPATH_CERTIFICATE);
            cJSON *privateKey = cJSON_GetObjectItem(file_path, KEY_CONFIGURATION_FILEPATH_PRIVATEKEY);

            if (svrdb == NULL) {
                st_print_log("[ST_APP] [svrdb] svrdb file not found\n");
                ret = __LINE__;
                goto JSON_ERROR;
            }
            if (provisioning == NULL) {
                st_print_log("[ST_APP] [provisioning] provisioning file not found\n");
                ret = __LINE__;
                goto JSON_ERROR;
            }
            if (certificate == NULL) {
                st_print_log("[ST_APP] [certificate] User certificate file not found\n");
                ret = __LINE__;
                goto JSON_ERROR;
            }
            if (privateKey == NULL) {
                st_print_log("[ST_APP] [privateKey] User certificate file not found\n");
                ret = __LINE__;
                goto JSON_ERROR;
            }

            memcpy(g_svrdb_file_path, svrdb->valuestring, strlen(svrdb->valuestring));
            memcpy(g_certificate_file_path, certificate->valuestring, strlen(certificate->valuestring));
            memcpy(g_private_key_file_path, privateKey->valuestring, strlen(privateKey->valuestring));
            memcpy(g_things_cloud_file_path, provisioning->valuestring, strlen(provisioning->valuestring));

            st_print_log("[ST_APP] Security SVR DB file path : %s\n", g_svrdb_file_path);
            st_print_log("[ST_APP] [configuration] svrdb : %s / provisioning : %s\n", svrdb->valuestring, provisioning->valuestring);
            st_print_log("[ST_APP] [configuration] certificate : %s / privateKey : %s\n", certificate->valuestring, privateKey->valuestring);
        } else {
            st_print_log("[ST_APP] file_path is NULL\n");
            ret = __LINE__;
            goto JSON_ERROR;
        }
    }

JSON_ERROR:
    if (root != NULL) {
        cJSON_Delete(root);
    }

    return ret;
}
