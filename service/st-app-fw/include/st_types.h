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
  @brief Enumeration of possible outcomes from ST App Framework APIs
  @file
*/

#ifndef ST_TYPES_H
#define ST_TYPES_H

typedef enum {
  ST_ERROR_NONE = 0,                  /**< Successful*/
  ST_ERROR_INVALID_PARAMETER,         /**<Invalid parameter
                                        (If parameter is null or empty)*/
  ST_ERROR_OPERATION_FAILED,          /**< Operation Failed*/
  ST_ERROR_STACK_NOT_INITIALIZED,     /**< Stack is not yet initialized*/
  ST_ERROR_STACK_ALREADY_INITIALIZED, /**< Stack is already initialized*/
  ST_ERROR_STACK_NOT_STARTED,         /**< Stack is not yet started*/
  ST_ERROR_STACK_RUNNING              /**< Stack is currently running*/
} st_error_t;

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
  ST_STATUS_DONE,
  ST_STATUS_RESET,
  ST_STATUS_STOP
} st_status_t;

#endif