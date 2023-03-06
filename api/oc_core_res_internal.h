/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef OC_CORE_RES_INTERNAL_H
#define OC_CORE_RES_INTERNAL_H

#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_ri.h"

#include <cbor.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief initialize the core functionality
 */
void oc_core_init(void);

/**
 * @brief shutdown the core functionality
 */
void oc_core_shutdown(void);

/**
 * @brief initialize the platform
 *
 * @param mfg_name the manufactorer name
 * @param init_cb the callback
 * @param data  the user data
 * @return oc_platform_info_t* the platform information
 */
oc_platform_info_t *oc_core_init_platform(const char *mfg_name,
                                          oc_core_init_platform_cb_t init_cb,
                                          void *data);

/**
 * @brief Add new devide to the platform
 *
 * @param uri the uri of the device
 * @param rt the device type of the device
 * @param name the friendly name
 * @param spec_version specification version
 * @param data_model_version  data model version
 * @param add_device_cb callback
 * @param data supplied user data
 * @return oc_device_info_t* the device information
 */
oc_device_info_t *oc_core_add_new_device(const char *uri, const char *rt,
                                         const char *name,
                                         const char *spec_version,
                                         const char *data_model_version,
                                         oc_core_add_device_cb_t add_device_cb,
                                         void *data);

/**
 * @brief encode the interfaces with the cbor (payload) encoder
 *
 * @param parent the cbor encoder
 * @param iface_mask the interfaces (as bit mask)
 */
void oc_core_encode_interfaces_mask(CborEncoder *parent, unsigned iface_mask);

/**
 * @brief store the uri as a string
 *
 * @param s_uri source string
 * @param d_uri destination (to be allocated) to store the uri
 */
void oc_store_uri(const char *s_uri, oc_string_t *d_uri);

/**
 * @brief populate resource
 * mainly used for creation of core resources
 *
 * @param core_resource the resource index
 * @param device_index the device index
 * @param uri the uri for the resource
 * @param iface_mask interfaces (as mask) to be implemented on the resource
 * @param default_interface the default interface
 * @param properties the properties (as mask)
 * @param get_cb get callback function
 * @param put_cb put callback function
 * @param post_cb post callback function
 * @param delete_cb delete callback function
 * @param num_resource_types amount of resource types, listed as variable
 * arguments after this argument
 * @param ...
 */
void oc_core_populate_resource(int core_resource, size_t device_index,
                               const char *uri, oc_interface_mask_t iface_mask,
                               oc_interface_mask_t default_interface,
                               int properties, oc_request_callback_t get_cb,
                               oc_request_callback_t put_cb,
                               oc_request_callback_t post_cb,
                               oc_request_callback_t delete_cb,
                               int num_resource_types, ...);

/**
 * @brief filter if the query param of the request contains the resource
 * (determined by resource type "rt")
 *
 * @param resource the resource to look for
 * @param request the request to scan
 * @return true resource is in the request
 * @return false resource is not in the request
 */
bool oc_filter_resource_by_rt(const oc_resource_t *resource,
                              const oc_request_t *request);

/**
 * @brief Convert URI of a core resource to oc_core_resource_t.
 *
 * @param uri URI of a core resource (cannot be NULL)
 * @return oc_core_resource_t on success
 * @return -1 on failure
 */
int oc_core_get_resource_type_by_uri(const char *uri);

#ifdef __cplusplus
}
#endif

#endif /* OC_CORE_RES_INTERNAL_H */
