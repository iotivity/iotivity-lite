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

#ifndef ST_FOTA_MANAGER_H
#define ST_FOTA_MANAGER_H

#include "fota.h"
#include <stdbool.h>

/**
  @brief A function pointer for handling the fota command.
  @param cmd Command for firmware update.
  @return true if command confirm by user or false.
*/
typedef bool (*st_fota_cmd_cb_t)(fota_cmd_t cmd);

int st_fota_manager_start(void);
void st_fota_manager_stop(void);

int st_fota_set_state(fota_state_t state);
int st_fota_set_fw_info(const char *ver, const char *uri);
int st_fota_set_result(fota_result_t result);

/**
  @brief Function for register fota command handler
  @param cb Callback function to return the fota command.
  @return Returns true if success.
*/
bool st_register_fota_cmd_handler(st_fota_cmd_cb_t cb);

/**
  @brief Function for unregister fota command handler
*/
void st_unregister_fota_cmd_handler(void);

#endif /* ST_FOTA_MANAGER_H */
