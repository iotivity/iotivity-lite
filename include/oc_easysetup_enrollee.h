/****************************************************************************
 *
 * Copyright (c) 2019 Samsung Electronics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef _OC_EASYSETUP_ENROLLEE_H_
#define _OC_EASYSETUP_ENROLLEE_H_


/**
 * @file
 *
 * This file contains Enrollee APIs.
 */
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "es_common.h"

/**
 * A function pointer for registering a user-defined function to set
 * user-specific properties to a
 * response going back to a client.
 * @param payload Represents a response. You can set a specific value with
 * specific property key
 * to the payload. If a client receives the response and know the property key,
 * then it can
 * extract the value.
 * @param resource_type Used to distinguish which resource the received property
 * belongs to.
 */
typedef void (*es_write_userdata_cb)(oc_rep_t *payload, char *resource_type);

/**
 * A function pointer for registering a user-defined function to parse
 * user-specific properties
 * from received POST request.
 * @param payload Represents a received POST request. If you know user-specific
 * property key,
 * then you can extract a corresponding value if it exists.
 * @param resource_type Used to distinguish which resource the received property
 * belongs to
 * @param user_data User-specific data you want to deliver to desired users,
 * i.e.
 * application.
 * The user should know a data structure of passed userdata.
 */
typedef void (*es_read_userdata_cb)(oc_rep_t *payload, char *resource_type,
                                    void **user_data);

/**
 * A callback function to clean up user data created in es_wifi_conf_data,
 * es_dev_conf_data and es_coap_cloud_conf_data.
 *
 * @param user_data User-specific data free up it's memory.
 * @param resource_type Used to distinguish which resource user data
 * beongs to.
 */
typedef void (*es_free_userdata)(void *user_data, char *resource_type);

/**
 * This function initializes the EasySetup. This API must be called prior to
 * invoking any other API.
 *
 * @param is_secured        True if the Enrollee is operating in secured mode.
 * @param resource_mask     Easy Setup Resource Type which application wants to
 * create.
 *                          ES_WIFICONF_RESOURCE = 0x01,
 *                          ES_DEVCONF_RESOURCE = 0x02
 *				   ES_RSPCONF_RESOURCE = 0x04,
 *				   ES_RSPCAPCONF_RESOURCE = 0x08 
 * @param callbacks         ESProvisioningCallbacks for updating Easy setup
 * Resources' data to the
 *                          application
 * @return ::ES_OK on success, some other value upon failure.
 */
es_result_e oc_init_enrollee(bool is_secured, es_resource_mask_e resource_mask,
                             es_provisioning_callbacks_s callbacks);

/**
 * This function performs termination of all Easy Setup Resources.
 *
 * @return ::void
 */
void oc_terminate_enrollee(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* _OC_EASYSETUP_ENROLLEE_H_ */

