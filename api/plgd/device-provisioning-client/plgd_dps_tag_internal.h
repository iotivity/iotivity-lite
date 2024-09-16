/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifndef PLGD_DPS_TAG_INTERNAL_H
#define PLGD_DPS_TAG_INTERNAL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// annotation string written to tag of identity certificates or ACLs retrieved
/// from device-provisioning-service
#define DPS_TAG "dps"
#define DPS_TAG_LEN (sizeof(DPS_TAG) - 1)
// annotation string written to tag of identity certificates that have been
// added in a previous step of provisioning
#define DPS_STALE_TAG "dps-stale"
#define DPS_STALE_TAG_LEN (sizeof(DPS_STALE_TAG) - 1)

/**
 * @brief Set stale tag to DPS ACLs.
 *
 * @param device index of the device
 */
void dps_acls_set_stale_tag(size_t device);

/**
 * @brief Remove stale tag from DPS ACLs.
 *
 * @param device index of the device
 */
void dps_acls_remove_stale_tag(size_t device);

/**
 * @brief Set stale tag to DPS credentials.
 *
 * @param device index of the device
 */
void dps_credentials_set_stale_tag(size_t device);

/**
 * @brief Remove stale tag from DPS credentials.
 *
 * @param device index of the device
 */
void dps_credentials_remove_stale_tag(size_t device);

/**
 * @brief Remove acls tagged with the stale tag.
 *
 * @param device index of the device
 */
void dps_remove_stale_acls(size_t device);

/**
 * @brief Remove credentials tagged with the stale tag.
 *
 * @param device index of the device
 * @return the number of removed credentials
 */
int dps_remove_stale_credentials(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_TAG_INTERNAL_H */
