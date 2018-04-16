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

#ifndef RD_CLIENT_H
#define RD_CLIENT_H

/**
  @brief Resource Directory API of IoTivity-constrained for client.
  @file
*/

#include "oc_client_state.h"
#include "oc_ri.h"

/** Resource Directory URI used to Discover RD and Publish resources.*/
#define OC_RSRVD_RD_URI "/oic/rd"

/** To represent resource type with Publish RD.*/
#define OC_RSRVD_RESOURCE_TYPE_RDPUBLISH "oic.wk.rdpub"

/** To indicate how long RD should publish this item.*/
#define OC_RSRVD_DEVICE_TTL "lt"

#define OIC_RD_PUBLISH_TTL 86400

/**
  @brief Publish RD resource to Resource Directory.
  @param endpoint The endpoint of the RD.
  @param resource This is the resource which we need to register to RD.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns True if success.
*/
bool rd_publish(oc_endpoint_t *endpoint, oc_resource_t *resource,
                oc_response_handler_t handler, void *user_data);

/**
  @brief Delete RD resource from Resource Directory.
  @param endpoint The endpoint of the RD.
  @param resource This is the resource which we need to delete to RD.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns True if success.
*/
bool rd_delete(oc_endpoint_t *endpoint, oc_resource_t *resource,
               oc_response_handler_t handler, void *user_data);

#endif /* RD_CLIENT_H */
