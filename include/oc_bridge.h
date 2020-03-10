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
#include "util/oc_list.h"
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

/**
 * Add an oic.d.bridge device.
 *
 * The oic.r.vodlist resource will be registered to the bridge device.
 *
 * @param[in] name the user readable name of the device
 * @param[in] spec_version The version of the OCF Server.
 *                       This is the "icv" device property
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

/**
 * Add a virtual ocf device to the the stack.
 *
 * This function is called to add a newly discovered non-ocf device to a bridge
 * device. This will typically be called in responce to the non-ocf devices
 * discovery mechanism.
 *
 * The `oc_bridge_add_virtual_device` function may be called as many times as
 * needed.  Each call will add a new device to the stack with its own port
 * address. Each device is automatically assigned a number. Unlike
 * oc_add_device() this number is not simply incremented by one but assigned a
 * number based on avalibility and past virtual devices that were added.  After
 * this function returns the oc_bridge_get_virtual_device_index() using the
 * vitual_device_id can be used to get the logical device index number.
 *
 * @param virtual_device_id an string that identifies the virtual device.
 * @param uri the The device URI.  The wellknown default URI "/oic/d" is hosted
 *            by every server. Used to device specific information.
 * @param rt the resource type
 * @param name the user readable name of the device
 * @param spec_version The version of the OCF Server.  This is the "icv" device
 *                     property
 * @param data_model_version Spec version of the resource and device
 * specifications to which this device data model is implemtned. This is the
 * "dmv" device property
 * @param add_device_cb callback function invoked during oc_add_device(). The
 *                      purpose is to add additional device properties that are
 *                      not supplied to oc_add_device() function call.
 * @param data context pointer that is passed to the oc_add_device_cb_t
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see init
 */
int oc_bridge_add_virtual_device(const uint8_t *virtual_device_id,
                                 size_t virtual_device_id_size,
                                 const char *econame, const char *uri,
                                 const char *rt, const char *name,
                                 const char *spec_version,
                                 const char *data_model_version,
                                 oc_add_device_cb_t add_device_cb, void *data);

#ifdef __cplusplus
}
#endif
#endif // OC_BRIDGE_H
