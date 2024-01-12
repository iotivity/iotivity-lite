/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
 *
 ******************************************************************/
/**
  @file
*/
#ifndef OC_CORE_RES_H
#define OC_CORE_RES_H

#include "oc_ri.h"
#include "util/oc_compiler.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief callback for initializing the platform
 *
 */
typedef void (*oc_core_init_platform_cb_t)(void *data);

/**
 * @brief callback for adding a device
 *
 */
typedef void (*oc_core_add_device_cb_t)(void *data);

/**
 * @brief platform information
 */
typedef struct oc_platform_info_t
{
  oc_uuid_t pi;                                ///< the platform identifier
  oc_string_t mfg_name;                        ///< manufactorer name
  oc_core_init_platform_cb_t init_platform_cb; ///< callback function
  void *data; ///< user data for the callback function
} oc_platform_info_t;

/**
 * @brief device information
 */
typedef struct oc_device_info_t
{
  oc_uuid_t di;                          ///< device indentifier
  oc_uuid_t piid;                        ///< Permanent Immutable ID
  oc_string_t name;                      ///< name of the device
  oc_string_t icv;                       ///< specification version
  oc_string_t dmv;                       ///< data model version
  oc_core_add_device_cb_t add_device_cb; ///< callback when device is changed
  void *data;                            ///< user data

#ifdef OC_HAS_FEATURE_BRIDGE
  oc_string_t
    ecoversion; ///< Version of ecosystem that a Bridged Device belongs to.
                ///< Typical version string format is like n.n (e.g. 5.0)
  bool
    is_removed; ///< true: this device was previously allocated and then removed
#endif
} oc_device_info_t;

/**
 * @brief retrieve the amount of devices
 *
 * @return size_t the amount of devices
 */
size_t oc_core_get_num_devices(void);

/**
 * @brief retrieve the id (uuid) of the device
 *
 * @param device the device index
 * @return oc_uuid_t* the device id
 */
oc_uuid_t *oc_core_get_device_id(size_t device);

/**
 * @brief retrieve the device info from the device index
 *
 * @param device the device index
 * @return oc_device_info_t* the device info
 */
oc_device_info_t *oc_core_get_device_info(size_t device);

#ifdef OC_HAS_FEATURE_BRIDGE
/**
 * @brief retrieve the device whose device is di
 *
 * @param di device id to be used for search
 * @param device device index (index of g_oc_device_info[])
 *        of the device whose device id is di
 * @return 0 if found
 */
int oc_core_get_device_index(oc_uuid_t di, size_t *device);
#endif

/**
 * @brief retrieve the platform information
 *
 * @return oc_platform_info_t* the platform information
 */
oc_platform_info_t *oc_core_get_platform_info(void);

/**
 * @brief retrieve the resource by type (e.g. index) on a specific device
 *
 * @param type the index of the resource
 * @param device the device index
 * @return oc_resource_t* the resource handle
 * @return NULL on failure
 */
oc_resource_t *oc_core_get_resource_by_index(int type, size_t device);

/**
 * @brief retrieve a core resource by uri
 *
 * @param uri the uri (cannot be NULL)
 * @param uri_len the length of the uri
 * @param device the device index
 * @return oc_resource_t* the resource handle
 * @return NULL on failure
 */
oc_resource_t *oc_core_get_resource_by_uri_v1(const char *uri, size_t uri_len,
                                              size_t device) OC_NONNULL();

/**
 * @brief retrieve a core resource by uri
 *
 * @deprecated replaced by replaced by oc_core_get_resource_by_uri_v1 in
 * v2.2.5.7
 */
oc_resource_t *oc_core_get_resource_by_uri(const char *uri, size_t device)
  OC_NONNULL()
    OC_DEPRECATED("replaced by oc_core_get_resource_by_uri_v1 in v2.2.5.7");

/**
 * @brief determine if a resource is a Device Configuration Resource
 *
 * @param resource the resource
 * @param device the device index to which the resource belongs too
 * @return true is DCR resource
 * @return false is not DCR resource
 */
bool oc_core_is_DCR(const oc_resource_t *resource, size_t device);

/**
 * @brief determine if a resource is Security Vertical Resource
 *
 * @param resource the resource
 * @param device the device index to which the resource belongs too
 * @return true is SRV resource
 * @return false is not SVR resource
 */
bool oc_core_is_SVR(const oc_resource_t *resource, size_t device);

/**
 * @brief determine if a resource is a vertical resource
 *
 * @note vertical resources are mostly custom resources specific to a device
 *
 * @param resource the resource
 * @param device the device index to which the resource belongs too
 * @return true : is vertical resource
 * @return false : is not a vertical resource
 */
bool oc_core_is_vertical_resource(const oc_resource_t *resource, size_t device);

/**
 * set the latency (lat) property in eps of oic.wk.res resource.
 * The latency is implemented globally e.g. for all the resource instances.
 * The default behaviour is that if nothing is set (e.g. value is 0) the lat
 * property will not be framed in the eps property. Setting the value on 0 will
 * cause that the lat property will not be framed in the eps property.
 * @param[in] latency the latency in seconds
 */
void oc_core_set_latency(int latency);

/**
 * retrieves the latency (lat) property in eps of the oic.wk.res resource.
 * the lat value is implemented globally for the stack
 * @return
 *  - the latency in seconds
 */
int oc_core_get_latency(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_CORE_RES_H */
