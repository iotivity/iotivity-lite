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

/**
  @brief ST application framework manager APIs for managing st-app-fw module.
    calling sequence is supposed to be
    st_manager_initialize()->st_manager_start()->st_manager_stop()->st_manager_deinitialize()
  @file
*/

#ifndef ST_MANAGER_H
#define ST_MANAGER_H

#include "st_types.h"
#include <stdbool.h>

/**
  @brief A function pointer for handling OTM(Ownership Transfer
     Method) confirm function.
  @return true if OTM confirm by user or false.
*/
typedef bool (*st_otm_confirm_cb_t)(void);

/**
  @brief A function pointer for handling the ST application framework status.
  @param status Current status of the ST application framework.
*/
typedef void (*st_status_cb_t)(st_status_t status);

/**
  @brief A function to initialize ST application framework.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_STACK_ALREADY_INITIALIZED
    if st_manager_initialize() is already called.
  @retval ST_ERROR_STACK_RUNNING
    if st_manager_initialize() and st_manager_start() are already called.
  @retval ST_ERROR_OPERATION_FAILED
    if there is an internal failure while excuting this function.
*/
st_error_t st_manager_initialize(void);

/**
  @brief A function to start ST application framework. This function will
    start iotivity-lite stack which include network thread and resources
    registration. Also it will process Easy Setup and Cloud registration
    steps. This function will loop until st_status is ST_STATUS_STOP.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful by st_manager_stop() call.
  @retval ST_ERROR_STACK_NOT_INITIALIZED
    st_manager_initialize() isn't executed.
    this function is supposed to be called right after st_manager_initialize().
  @retval ST_ERROR_STACK_RUNNING st_manager_start() is already called.
  @retval ST_ERROR_OPERATION_FAILED
    if there is an internal failure while excuting this function
    such as cloud connection broken and invalid cloud connection.
*/
st_error_t st_manager_start(void);

/**
  @brief A function to reset ST application framework. This function will
    reset all db files such as security and change into user language
    instead of internal type. After finish this function, ST application
    framework will return to ST_STATUS_INIT status.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_STACK_NOT_INITIALIZED
    st_manager_initialize() isn't executed yet.
*/
st_error_t st_manager_reset(void);

/**
  @brief A function to stop ST application framework. This function will
    change st_manager's status to ST_STATUS_STOP to stop st_manager. This
    will make st_manager_start out of loop and stop iotivity-lite stack
    internally which includes network thread and resources registration.
    Also it will stop Easy Setup and Cloud registration steps, if they
    are under progress.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_STACK_NOT_INITIALIZED
    st_manager_initialize() and st_manager_start() aren't executed yet.
  @retval ST_ERROR_STACK_NOT_STARTED
  st_manager_start() isn't executed yet.
*/
st_error_t st_manager_stop(void);

/**
  @brief A function to deinitialize ST application framework.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_STACK_NOT_INITIALIZED
    st_manager_initialize() isn't executed yet,
    st_manager_deinitialize() is supposed to be called right after
    st_manager_initialize() or st_manager_stop().
  @retval ST_ERROR_STACK_RUNNING
    status under st_manager_start(),
    st_manager_deinitialize() is supposed to be called right after
    st_manager_initialize() or st_manager_stop().
*/
st_error_t st_manager_deinitialize(void);

/**
  @brief A function for registration of the user
     confirm handler for OCF OTM(Ownership Transfer Method).
  @param cb Callback function to require OTM confirm.
  @return bool Description of result.
  @retval true if successful.
  @retval false Input parameter is NULL or it is called under unsecure build.
     unsecure enviroment doesn't support OTM confirm.

*/
bool st_register_otm_confirm_handler(st_otm_confirm_cb_t cb);

/**
  @brief A function for unregistering OTM confirm handler.
*/
void st_unregister_otm_confirm_handler(void);

/**
  @brief A function for registering ST application framework status handler
  @param cb Callback function to return the ST application framework status.
  @return bool Description of result.
  @retval true if successful.
  @retval false Input parameter is NULL or it is already registered.

*/
bool st_register_status_handler(st_status_cb_t cb);

/**
  @brief A function for unregister ST application framework status handler
*/
void st_unregister_status_handler(void);

/**
  @brief A function set device profile.
  @param device_def Unsigned char array showing CBOR info.
  @param device_def_len Total length of device def
  @return bool Description of result.
  @retval true if successful.
  @retval false if params are invalid.
*/
bool st_set_device_profile(unsigned char *device_def,
                           unsigned int device_def_len);

/**
  @brief A function unset device profile.
*/
void st_unset_device_profile(void);

#endif /* ST_MANAGER_H */
