/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 * Functions to aid bridging IoTivity to other eco-systems
 */
#ifndef OC_BRIDGE_H
#define OC_BRIDGE_H

#include "oc_uuid.h"
#include "oc_list.h"
#include "oc_helpers.h"
#include "oc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Perhaps internal struct may want this to be public for clients
 */
typedef struct oc_vods_t
{
  struct oc_vods_t *next;
  oc_string_t name;
  char di[OC_UUID_LEN];
  oc_string_t econame;
} oc_vods_t;

// Perhaps internal list may want this to be public for clients
OC_LIST(oc_vods_list_t);

/**
 * Add an oic.d.bridge device.
 *
 * The oic.r.vodlist resource will be registered to the bridge device.
 *
 * @param[in] name the user readable name of the device
 * @param[in] spec_version The version of the OCF Server.
 *                         This is the "icv" device property
 * @param[in] data_model_version Spec version of the resource and device
 *                               specifications to which this device data model
 *                               is implemented. This is the "dmv" device
 *                               property
 * @param[in] add_device_cb callback function invoked during oc_add_device().
 *                          The purpose is to add additional device properties
 *                          that are not supplied to
 * oc_bridge_add_bridge_device() function call.
 * @param[in] data context pointer that is passed to the oc_add_device_cb_t
 */
int oc_bridge_add_bridge_device(const char *name, const char *spec_version,
                                const char *data_model_version,
                                oc_add_device_cb_t add_device_cb, void *data);

#ifdef __cplusplus
}
#endif
#endif // OC_BRIDGE_H
