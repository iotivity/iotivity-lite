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

typedef struct oc_virtual_device_t
{
  struct oc_virtual_device_t *next;
  uint8_t *v_id;
  size_t v_id_size;
  oc_string_t econame;
  size_t index;
} oc_virtual_device_t;

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
 *                          oc_bridge_add_bridge_device() function call.
 * @param[in] data context pointer that is passed to the oc_add_device_cb_t
 *
 * @return
 *   `0` on success
 *   `-1` on failure
 */
int oc_bridge_add_bridge_device(const char *name, const char *spec_version,
                                const char *data_model_version,
                                oc_add_device_cb_t add_device_cb, void *data);

/**
 * Add a virtual ocf device to the the stack.
 *
 * This function is called to add a newly discovered non-ocf device to a bridge
 * device. This will typically be called in response to the non-ocf devices
 * discovery mechanism.
 *
 * The `oc_bridge_add_virtual_device()` function may be called as many times as
 * needed.  Each call will add a new device to the stack with its own port
 * address. Each device is automatically assigned a device index number. Unlike
 * the `oc_add_device()` function this number is not incremented by one but
 * assigned an index number based on avalibility.  The index assigned to the
 * virtual device will be returned from the function call. The function
 * `oc_bridge_get_virtual_device_index()` can also be used to get the logical
 * device index number after this function call.
 *
 * The function `oc_bridge_add_bridge_device()` must be called before this
 * function.
 *
 * @param virtual_device_id a unique identifier that identifies the virtual
 *                          device this could be a UUID, serial number or other
 *                          means of uniquely identifying the device
 * @param virtual_device_id_size size in bytes of the virtual_device_id param
 * @param econame ecosystem name of the bridged device which is exposed by this
 *                virtual device
 * @param uri the The device URI.  The wellknown default URI "/oic/d" is hosted
 *            by every server. Used to device specific information.
 * @param rt the resource type
 * @param name the user readable name of the device
 * @param spec_version The version of the OCF Server.  This is the "icv" device
 *                     property
 * @param data_model_version Spec version of the resource and device
 *                           specifications to which this device data model is
 *                           implemented. This is the "dmv" device property
 * @param add_device_cb callback function invoked during oc_add_device(). The
 *                      purpose is to add additional device properties that are
 *                      not supplied to oc_add_device() function call.
 * @param data context pointer that is passed to the oc_add_device_cb_t
 *
 * @return
 *   - the logical index of the virtual device on success
 *   - `0` on failure since a bridge device is required to add virtual devices
           a zero index cannot be assigned to a virtual device.
 *
 * @note device index is cast from size_t to int and may lose information.
 *       The `oc_bridge_add_virtual_device()` function can be used to get
 *       the non-cast device index.
 *
 * @see init
 */
size_t oc_bridge_add_virtual_device(
  const uint8_t *virtual_device_id, size_t virtual_device_id_size,
  const char *econame, const char *uri, const char *rt, const char *name,
  const char *spec_version, const char *data_model_version,
  oc_add_device_cb_t add_device_cb, void *data);

/**
 * If the non-ocf device is no longer reachable this can be used to remove
 * the virtual device from the bridge device.
 *
 * This will shutdown network connectivity for the device and will update
 * the vodslist resource found on the bridge.
 *
 * Any any persistant settings will remain unchanged.  If the virtual device has
 * already been onboarded and permission settings have been modified when the
 * device is added again using `oc_bridge_add_virtual_device` those
 * persistant settings will still be in place.
 *
 * @param device_index the index of the virtual device
 *
 * @return
 *   - `0` on succes
 *   - `-1` on failure
 */
int oc_bridge_remove_virtual_device(size_t device_index);

/**
 * This will remove the virtual device and free memory associated with that
 * device.
 *
 * Delete virtual device will remove all persistant settings. If the virtual
 * device is added again the onboarding and device permissions will need to be
 * setup as if the device were a new device.
 *
 * @param device_index index of teh virtual device
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_bridge_delete_virtual_device(size_t device_index);
/**
 * Get the logical device index for the virtual device
 *
 * @param virtual_device_id a unique identifier that identifies the virtual
 *                          device this could be a UUID, serial number or other
 *                          means of uniquely identifying the device
 * @param virtual_device_id_size size in bytes of the virtual_device_id param
 * @param econame ecosystem name of the bridged virtual device
 *
 * @return
 *   - the logical index of the virtual device on success
 *   - `0` on failure since a bridge device is required to add virtual devices
 *         a zero index cannot be assigned to a virtual device.
 */
size_t oc_bridge_get_virtual_device_index(const uint8_t *virtual_device_id,
                                          size_t virtual_device_id_size,
                                          const char *econame);

/**
 * Use the device index of the virtual device to look up the virtual device
 * info.
 *
 * @param virtual_device_index the logical index of the virtual device
 *
 * @return
 *    - a pointer to the oc_virtual_device_t upon success
 *    - NULL if no virtual device was found using the provided index
 */
oc_virtual_device_t *oc_bridge_get_virtual_device_info(
  size_t virtual_device_index);
#ifdef __cplusplus
}
#endif
#endif // OC_BRIDGE_H
