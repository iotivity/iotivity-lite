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
  @brief FOTA Manager API for firmware update.
  @file
*/

#ifndef ST_FOTA_MANAGER_H
#define ST_FOTA_MANAGER_H

#include "fota_types.h"
#include "st_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
  @brief A function pointer for handling the fota command.
  @param cmd Command for firmware update.
  @return true if command confirm by user or false.
*/
typedef bool (*st_fota_cmd_cb_t)(fota_cmd_t cmd);

/**
  @brief Function to set the state of fota progress.
  @param state Desired state of the fota.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_OPERATION_FAILED if changing desired state is not allowed.
*/
st_error_t st_fota_set_state(fota_state_t state);

/**
  @brief Function to set the firmware information.
  @param cur_version The version of current firmware.
  @param new_version The version of the newest firmware.
  @param uri An address of firmware download.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_INVALID_PARAMETER if input parameters are NULL.
*/
st_error_t st_fota_set_fw_info(const char *cur_version, const char *new_version,
                               const char *uri);

/**
  @brief Function to set the result of the fota operation.
    This is usally used in callback handler st_fota_cmd_cb_t
    to return the result of each fota operation request.
  @param result Current result of the fota.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_INVALID_PARAMETER if input parameter is not allowed.
*/
st_error_t st_fota_set_result(fota_result_t result);

/**
  @brief Function to register fota command handler
  @param cb Callback function to return the fota command.
  @return bool Description of result.
  @retval true if successful.
  @retval false Input parameter is NULL or it is already registered.
*/
bool st_register_fota_cmd_handler(st_fota_cmd_cb_t cb);

/**
  @brief Function to unregister fota command handler
*/
void st_unregister_fota_cmd_handler(void);

#ifdef __cplusplus
}
#endif

#endif /* ST_FOTA_MANAGER_H */
