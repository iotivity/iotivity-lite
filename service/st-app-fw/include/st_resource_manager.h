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
  @brief Resource manager APIs for resource control & management.
  @file
*/

#ifndef ST_RECOURCE_MGR_H
#define ST_RECOURCE_MGR_H

#include "oc_rep.h"
#include "st_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
  @brief A data structure to Provide request from clients which
     include resource informations and request payloads.
*/
typedef struct
{
  const char *uri;           /* Resource uri related to the request */
  int uri_len;               /* Resource uri length */
  const char *query;         /* Query value regarding request */
  int query_len;             /* Query length */
  oc_rep_t *request_payload; /* Request payload containing properties */
} st_request_t;

/**
  @brief A function pointer to handle resources requests.
  @param request request info that include resource informations
     (uri, query) and request payloads.
  @return true if request is handled succesfully by app or false.
*/
typedef bool (*st_resource_handler)(st_request_t *request);

/**
  @brief A function for register resource handlers regarding
     get/set requests.
  @param get_handler callback handler when called in case
     GET request is comming.
  @param set_handler callback handler when called in case
     POST request is comming.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_INVALID_PARAMETER if input parameters are NULL.

*/
st_error_t st_register_resource_handler(st_resource_handler get_handler,
                                        st_resource_handler set_handler);

/**
  @brief A function to notify observed clients regarding uri.
  @param uri The uri of the resource that need to notify.
  @return st_error_t An enumeration of possible outcomes.
  @retval ST_ERROR_NONE if successful.
  @retval ST_ERROR_INVALID_PARAMETER if input parameter is NULL.
  @retval ST_ERROR_OPERATION_FAILED if internal operation is failed
    such as failure to get the resource info. of input parameter.
*/
st_error_t st_notify_back(const char *uri);

#ifdef __cplusplus
}
#endif

#endif /* ST_RECOURCE_MGR_H */
