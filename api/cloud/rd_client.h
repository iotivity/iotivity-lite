/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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
  @brief Resource Directory API of IoTivity-Lite for RD clients.
  @file
*/

#ifndef RD_CLIENT_H
#define RD_CLIENT_H

#include "oc_client_state.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Resource Directory URI used to Discover RD and Publish resources.*/
#define OC_RSRVD_RD_URI "/oic/rd"

/**
  @brief Publish RD resource to Resource Directory.
  @param endpoint The endpoint of the RD.
  @param links This is the resource which we need to register to RD.
    If null, oic/p and oic/d resources will be published.
  @param device Index of the device for an unique identifier.
  @param ttl Time in seconds to indicate a RD, i.e. how long to keep this
    published item.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param qos Quality of service.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool rd_publish(oc_endpoint_t *endpoint, oc_link_t *links, size_t device,
                uint32_t ttl, oc_response_handler_t handler, oc_qos_t qos,
                void *user_data);

/**
  @brief Delete RD resource from Resource Directory.
  @param endpoint The endpoint of the RD.
  @param links This is the resource which we need to delete to RD.
  @param device Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param qos Quality of service.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool rd_delete(oc_endpoint_t *endpoint, oc_link_t *links, size_t device,
               oc_response_handler_t handler, oc_qos_t qos, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* RD_CLIENT_H */
