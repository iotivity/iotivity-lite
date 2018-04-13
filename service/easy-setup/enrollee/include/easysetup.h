/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef EASYSETUP_ENROLLEE_H
#define EASYSETUP_ENROLLEE_H

#include "estypes.h"
#include "esresources.h"
#include "enrolleecommon.h"

/**
 * @file
 *
 * This file contains Enrollee APIs.
 */

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * This function initializes the EasySetup. This API must be called prior to invoking any other API.
 *
 * @param is_secured        True if the Enrollee is operating in secured mode.
 * @param resource_mask     Easy Setup Resource Type which application wants to create.
 *                          ES_WIFICONF_RESOURCE = 0x01,
 *                          ES_COAPCLOUDCONF_RESOURCE = 0x02,
 *                          ES_DEVCONF_RESOURCE = 0x04
 * @param callbacks         ESProvisioningCallbacks for updating Easy setup Resources' data to the
 *                          application
 * @return ::ES_OK on success, some other value upon failure.
 */
es_result_e es_init_enrollee(bool is_secured, es_resource_mask_e resource_mask,
                              es_provisioning_callbacks_s callbacks);

/**
 * This function sets Device information.
 *
 * @param es_device_property Contains device information composed of WiFiConf Structure & DevConf
 *                           Structure
 * @return ::ES_OK on success, some other value upon failure.
 *
 * @see es_device_property
 */
es_result_e es_set_device_property(es_device_property *device_property);

/**
 * This function sets Enrollee's State.
 *
 * @param es_enrollee_state   Contains current enrollee's state.
 * @return ::ES_OK on success, some other value upon failure.
 *
 * @see es_enrollee_state
 */
es_result_e es_set_state(es_enrollee_state es_state);

/**
 * This function Sets Enrollee's Error Code.
 *
 * @param es_err_code Contains Enrollee's error code.
 * @return ::ES_OK on success, some other value upon failure.
 *
 * @see es_error_code_e
 */
es_result_e es_set_error_code(es_error_code es_err_code);

/**
 * This function performs termination of all Easy Setup Resources.
 *
 * @return ::ES_OK on success, some other value upon failure.
 */
es_result_e es_terminate_enrollee(void);

/**
 * This function is to set two function pointer to handle user-specific properties in in-comming
 * POST request and to out-going response for GET or POST request.
 * If you register certain functions with this API, you have to handle oc_rep_t structure to
 * set and get properties you want.
 *
 * @param readcb a callback for parsing properties from POST request
 * @param writecb a callback for putting properties to a response to be sent
 *
 * @return ::ES_OK on success, some other value upon failure.
 *
 * @see es_read_userdata_cb
 * @see es_write_userdata_cb
 */
es_result_e es_set_callback_for_userdata(es_read_userdata_cb readcb, es_write_userdata_cb writecb);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif /* EASYSETUP_ENROLLEE_H */
