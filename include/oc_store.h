/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

/**
 * @file
 */

#ifndef OC_STORE_H
#define OC_STORE_H

#include "oc_export.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Load device acls from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_acl(size_t device);

/**
 * @brief Save device acls to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_acl(size_t device);

/**
 * @brief Load credential resource of device from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_cred(size_t device);

/**
 * @brief Save credential resource of device to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_cred(size_t device);

/**
 * @brief Load provisioning status resource of device from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_pstat(size_t device);

/**
 * @brief Save provisioning status resource of device to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_pstat(size_t device);

/**
 * @brief Load device owner transfer resource of device from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_doxm(size_t device);

/**
 * @brief Save device owner transfer resource of device to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_doxm(size_t device);

/**
 * @brief Load device and platform id from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_unique_ids(size_t device);

/**
 * @brief Save device and platform id to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_unique_ids(size_t device);

/**
 * @brief Load security profile resource of device from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_sp(size_t device);
/**
 * @brief Save security profile resource of device to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_sp(size_t device);

/**
 * @brief Load ECDSA keypair of device from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_ecdsa_keypair(size_t device);

/**
 * @brief Save ECDSA keypair of device to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_ecdsa_keypair(size_t device);

/**
 * @brief Load auditable events resource of device from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_ael(size_t device);

/**
 * @brief Save auditable events resource of device to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_ael(size_t device);

/**
 * @brief Load security domain information resource from storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_load_sdi(size_t device);

/**
 * @brief Save security domain information resource to storage.
 *
 * @param device index of the device
 */
OC_API
void oc_sec_dump_sdi(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_STORE_H */
