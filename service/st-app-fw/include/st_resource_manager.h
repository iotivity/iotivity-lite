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

#ifndef ST_RECOURCE_MGR_H
#define ST_RECOURCE_MGR_H

#include "oc_ri.h"
#include <stdbool.h>

/**
  @brief A function pointer to handle resources requests.
  @param request request info that include endpoint information,
     resource information and request payloads.
  @return true if request is handled succesfully by app or false.
*/
typedef bool (*st_resource_handler)(oc_request_t *request);

/**
  @brief A function for register resource handlers regarding
     get/set requests.
  @param get_handler callback handler when called in case
     GET request is comming.
  @param get_handler callback handler when called in case
     POST request is comming.
  @return 0 if register success or -1.
*/
int st_register_resource_handler(st_resource_handler get_handler,
                                 st_resource_handler set_handler);

/**
  @brief A function to notify observed clients regarding uri.
  @param uri The uri of the resource that need to notify.
  @return if success, count of observing clients(0<=) or -1.
*/
int st_notify_back(const char *uri);

#endif /* ST_RECOURCE_MGR_H */