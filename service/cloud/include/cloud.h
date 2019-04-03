/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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
  @brief Cloud API for start cloud service.
  @file
*/

#ifndef CLOUD_H
#define CLOUD_H

#include <oc_api.h>
#include <stdbool.h>
#include <stddef.h>

/**
  @brief Cloud connection status.
*/
typedef enum {
  CLOUD_INITIALIZED = 0,
  CLOUD_SIGNED_UP = 1 << 0,
  CLOUD_SIGNED_IN = 1 << 1,
  CLOUD_REFRESHED_TOKEN = 1 << 2,
  CLOUD_FAILED = 1 << 5,
  CLOUD_RECONNECTING = 1 << 6,
} cloud_status_t;

/**
  @brief A function pointer for handling the cloud status.
  @param status Current status of the cloud.
*/
typedef void (*cloud_cb_t)(cloud_status_t status, void *user_data);

#ifdef __cplusplus
extern "C" {
#endif

/**
  @brief Function for create cloud service.
  @param device_index Index of the device for an unique identifier.
  @param cb Callback function to return the st cloud manager status.
  @return Returns 0 if successful, or -1 otherwise.
*/
int cloud_init(size_t device_index, cloud_cb_t cb, void *user_data);

/**
  @brief Function for stop cloud.
  @param device_index Index of the device for an unique identifier.
*/
void cloud_shutdown(size_t device_index);

/**
  @brief Publish RD resource to Cloud Resource Directory.
  @param res The resource for publish to the Cloud RD.
  @return Returns 0 if success, otherwise error.
*/
int cloud_rd_publish(oc_resource_t *res);

/**
  @brief Delete RD resource from Cloud Resource Directory.
  @param res The resource for delete from the Cloud RD.
*/
void cloud_rd_delete(oc_resource_t *res);

#ifdef __cplusplus
}
#endif

#endif /* CLOUD_H */
