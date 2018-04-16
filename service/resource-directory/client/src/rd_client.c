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

#include "rd_client.h"
#include "oc_api.h"
#include "oc_log.h"

bool
rd_publish(oc_endpoint_t *endpoint, oc_resource_t *resource,
           oc_response_handler_t handler, void *user_data)
{
  if (!endpoint) {
    OC_ERR("Error of input parameters");
    return false;
  }
  (void)resource;
  (void)handler;
  (void)user_data;
  return true;
}

bool
rd_delete(oc_endpoint_t *endpoint, oc_resource_t *resource,
          oc_response_handler_t handler, void *user_data)
{
  if (!endpoint) {
    OC_ERR("Error of input parameters");
    return false;
  }
  (void)resource;
  (void)handler;
  (void)user_data;
  return true;
}