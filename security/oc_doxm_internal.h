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

#ifndef OC_DOXM_INTERNAL_H
#define OC_DOXM_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_api.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_SEC_DOXM_URI "/oic/sec/doxm"
#define OCF_SEC_DOXM_RT "oic.r.doxm"
#define OCF_SEC_DOXM_IF_MASK (OC_IF_BASELINE | OC_IF_RW)
#define OCF_SEC_DOXM_DEFAULT_IF (OC_IF_RW)

typedef enum oc_sec_doxmtype_t {
  OC_OXMTYPE_JW = 0,
  OC_OXMTYPE_RDP = 1,
  OC_OXMTYPE_MFG_CERT = 2
} oc_sec_oxmtype_t;

/// Device Owner Transfer Resource representation
typedef struct
{
  int oxmsel;             ///< OTM Selection
  int oxms[3];            ///< OTM Supported Methods
  int num_oxms;           ///< Number of OTM Supported Methods
  int sct;                ///< Supported Credential Types
  bool owned;             ///< Device Ownership Status
  oc_uuid_t deviceuuid;   ///< Device UUID
  oc_uuid_t devowneruuid; ///< Device Owner ID
  oc_uuid_t rowneruuid;   ///< Resource Owner ID
} oc_sec_doxm_t;

/** @brief Allocate and initialize global variables */
void oc_sec_doxm_init(void);

/** @brief Deallocate global variables */
void oc_sec_doxm_free(void);

/**
 * @brief Get doxm resource representation for given device
 *
 * @note Only valid after oc_sec_doxm_init has been called
 *
 * @see oc_sec_doxm_init
 */
oc_sec_doxm_t *oc_sec_get_doxm(size_t device) OC_RETURNS_NONNULL;

/** @brief Set the doxm resource representation to default values. */
void oc_sec_doxm_set_default(oc_sec_doxm_t *doxm) OC_NONNULL();

/** @brief Reset the doxm resource for given device to default values. */
void oc_sec_doxm_default(size_t device);

/** @brief Decode the representation to the doxm resource. */
bool oc_sec_decode_doxm(const oc_rep_t *rep, bool from_storage, bool doc,
                        size_t device);

/** @brief Encode the doxm resource to root encoder. */
CborError oc_sec_encode_doxm(size_t device, oc_interface_mask_t iface_mask,
                             bool to_storage);

/**
 * @brief Create roles (/oic/sec/doxm) resource for given device.
 *
 * @param device device index
 */
void oc_sec_doxm_create_resource(size_t device);

/** @brief Check if the URI matches the doxm resource URI (with or without
 * the leading slash */
bool oc_sec_is_doxm_resource_uri(oc_string_view_t uri);

#ifdef OC_TEST

/** @brief Configure the delay of sending separate response */
void oc_test_set_doxm_separate_response_delay_ms(uint64_t delay_ms);

#endif /* OC_TEST */

typedef struct oc_doxm_owned_cb_s
{
  struct oc_doxm_owned_cb_s *next;
  oc_ownership_status_cb_t cb;
  void *user_data;
} oc_doxm_owned_cb_t;

/** @brief Add ownership changed callback */
int oc_add_ownership_status_cb_v1(oc_ownership_status_cb_t cb, void *user_data)
  OC_NONNULL(1);

/** @brief Get ownership changed callback */
oc_doxm_owned_cb_t *oc_ownership_status_get_cb(oc_ownership_status_cb_t cb,
                                               const void *user_data);

/** @brief Free all ownership changed callbacks */
void oc_ownership_status_free_all_cbs(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_DOXM_INTERNAL_H */
