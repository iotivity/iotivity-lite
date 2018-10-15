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
  @brief FOTA API of IoTivity-constrained for firmware update.
  @file
*/

#ifndef FOTA_H
#define FOTA_H

#include "fota_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  @brief A function pointer for handling the fota command.
  @param cmd Command for firmware update.
  @return 0 if command confirm by user or -1.
*/
typedef int (*fota_cmd_cb_t)(fota_cmd_t cmd);

/**
  @brief Function for initialize about the fota.
  @param cb Callback function to return the fota command.
  @return Returns 0 if successful, or -1 otherwise.
*/
int fota_init(fota_cmd_cb_t cb);

/**
  @brief Function for deinitialize about the fota.
*/
void fota_deinit(void);

/**
  @brief Function for set the state of fota progress.
  @param state Current state of the fota.
  @return Returns 0 if successful, or -1 otherwise.
*/
int fota_set_state(fota_state_t state);

/**
  @brief Function for set the firmware information.
  @param cur_version The version of current firmware.
  @param new_version The version of the newest firmware.
  @param uri An address of firmware for download.
  @return Returns 0 if successful, or -1 otherwise.
*/
int fota_set_fw_info(const char *cur_version, const char *new_version,
                     const char *uri);

/**
  @brief Function for set the result of the fota.
  @param result Current result of the fota.
  @return Returns 0 if successful, or -1 otherwise.
*/
int fota_set_result(fota_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* FOTA_H */
