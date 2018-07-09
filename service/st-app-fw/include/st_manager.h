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
  @brief st-app-fw manager API for managing st-app-fw module.
  @file
*/

#ifndef ST_MANAGER_H
#define ST_MANAGER_H

#include "st_types.h"
#include <stdbool.h>

typedef enum {
  ST_STATUS_IDLE,
  ST_STATUS_INIT,
  ST_STATUS_EASY_SETUP_START,
  ST_STATUS_EASY_SETUP_PROGRESSING,
  ST_STATUS_EASY_SETUP_DONE,
  ST_STATUS_WIFI_CONNECTING,
  ST_STATUS_WIFI_CONNECTION_CHECKING,
  ST_STATUS_CLOUD_MANAGER_START,
  ST_STATUS_CLOUD_MANAGER_PROGRESSING,
  ST_STATUS_CLOUD_MANAGER_DONE,
  ST_STATUS_DONE,
  ST_STATUS_RESET,
  ST_STATUS_QUIT
} st_status_t;

/**
  @brief A function pointer for handling otm confirm function.
  @return true if otm confirm by user or false.
*/
typedef bool (*st_otm_confirm_cb_t)(void);

/**
  @brief A function pointer for handling the st manager status.
  @param status Current status of the st manager.
*/
typedef void (*st_status_cb_t)(st_status_t status);

/**
  @brief A function to initialize st_app_fw module.
  @return ST_ERROR_NONE if initilaize success or return regarding errors.
*/
st_error_t st_manager_initialize(void);

/**
  @brief A function to start st_app_fw module. This function will
     start iotivity-lite stack which include network thread and
     resources registration. Also it will process Easy Setup pro-
     cedure and cloud access logics. This function will loop until
     st_status is ST_STATUS_QUIT.
  @return ST_ERROR_NONE if start success or return regarding errors.
*/
st_error_t st_manager_start(void);

/**
  @brief A function to reset st_app_fw module. This function will
     reset all db files such as security and st_info. After finish
     this function, st-app-fw will return to ST_STATUS_INIT status.
  @return ST_ERROR_NONE if reset success or return regarding errors.
*/
st_error_t st_manager_reset(void);

/**
  @brief A function to start st_app_fw module. This function will
     stop iotivity-lite stack which include network thread and
     resources registration. Also it will stop Easy Setup pro-
     cedure and cloud access logics if it is progressing.
  @return ST_ERROR_NONE if stop success or return regarding errors.
*/
st_error_t st_manager_stop(void);

/**
  @brief A function to deinitialize st_app_fw module.
  @return ST_ERROR_NONE if de-initialize success or return regarding errors.
*/
st_error_t st_manager_deinitialize(void);

/**
  @brief A function for register otm confirm handler
  @param cb Callback function to require otm confirm.
  @return Returns true if success.
*/
bool st_register_otm_confirm_handler(st_otm_confirm_cb_t cb);

/**
  @brief A function for unregister otm confirm handler
*/
void st_unregister_otm_confirm_handler(void);

/**
  @brief A function for register st status handler
  @param cb Callback function to return the st manager status.
  @return Returns true if success.
*/
bool st_register_status_handler(st_status_cb_t cb);

/**
  @brief A function for unregister st status handler
*/
void st_unregister_status_handler(void);

#endif /* ST_MANAGER_H */
