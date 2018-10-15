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
  @brief Cloud Manager API for cloud connect and register.
  @file
*/

#ifndef ST_CLOUD_MANAGER_H
#define ST_CLOUD_MANAGER_H

#include "st_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  CLOUD_MANAGER_INITIALIZE = 0,
  CLOUD_MANAGER_SIGNED_UP = 1 << 0,
  CLOUD_MANAGER_SIGNED_IN = 1 << 1,
  CLOUD_MANAGER_PUBLISHED = 1 << 2,
  CLOUD_MANAGER_FINISH = 1 << 3,
  CLOUD_MANAGER_FAIL = 1 << 4,
  CLOUD_MANAGER_RE_CONNECTING = 1 << 5,
  CLOUD_MANAGER_RESET = 1 << 6
} st_cloud_manager_status_t;

/**
  @brief A function pointer for handling the st cloud manager status.
  @param status Current status of the st cloud manager.
*/
typedef void (*st_cloud_manager_cb_t)(st_cloud_manager_status_t status);

/**
  @brief Function for start that connect and register to the cloud.
  @param cloud_info The information for connect to the cloud.
  @param device_index Index of the device for an unique identifier.
  @param cb Callback function to return the st cloud manager status.
  @return Returns 0 if successful, or -1 otherwise.
*/
int st_cloud_manager_start(st_store_t *cloud_info, size_t device_index,
                           st_cloud_manager_cb_t cb);

/**
  @brief Function for stop about cloud manager.
  @param device_index Index of the device for an unique identifier.
*/
void st_cloud_manager_stop(size_t device_index);

/**
  @brief Function for check that connection of an internet.
  @param ci_server The url for check the connection.
  @return Returns 0 if successful, or -1 otherwise.
*/
int st_cloud_manager_check_connection(oc_string_t *ci_server);

#ifdef __cplusplus
}
#endif

#endif /* ST_CLOUD_MANAGER_H */
