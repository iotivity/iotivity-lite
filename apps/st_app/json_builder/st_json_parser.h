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

#ifndef _ST_JSON_PARSER_H
#define _ST_JSON_PARSER_H

#include "st_hashmap.h"
#include "../st_port.h"

/* device define JSON */
#define KEY_DEVICE                                              "device"
#define KEY_DEVICE_SPECIFICATION                                "specification"

/* oic.d */
#define KEY_DEVICE_SPECIFICATION_DEVICE                         "device"
#define KEY_DEVICE_SPECIFICATION_DEVICE_DEVICETYPE              "deviceType"
#define KEY_DEVICE_SPECIFICATION_DEVICE_DEVICENAME              "deviceName"
#define KEY_DEVICE_SPECIFICATION_DEVICE_SPEC_VERSION            "specVersion"
#define KEY_DEVICE_SPECIFICATION_DEVICE_DATA_MODEL_VERSION      "dataModelVersion"

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

typedef enum {
	es_conn_type_none = 0,
	es_conn_type_softap = 1,
	es_conn_type_ble = 2,
} easysetup_connectivity_type_e;

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
	char *spec_version;
	char *data_model_version;
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

int st_manager_json_parse(void);
#endif //_ST_JSON_PARSER_H
