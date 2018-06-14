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

#ifndef ST_MANAGER_H
#define ST_MANAGER_H

#include <stdbool.h>

typedef enum {
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

int st_manager_initialize(void);
int st_manager_start(void);
void st_manager_reset(void);
void st_manager_stop(void);
void st_manager_deinitialize(void);

/**
  @brief Function for register otm confirm handler
  @param cb callback function to require otm confirm.
*/
void st_register_otm_confirm_handler(st_otm_confirm_cb_t cb);

/**
  @brief Function for register st status handler
  @param cb Callback function to return the st manager status.
*/
void st_register_status_handler(st_status_cb_t cb);

/**
  @brief Function for unregister st status handler
*/
void st_unregister_status_handler(void);

#endif /* ST_MANAGER_H */
