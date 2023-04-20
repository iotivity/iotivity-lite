/****************************************************************************
 *
 * Copyright (c) 2020, Beijing OPPO telecommunications corp., ltd.
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

#ifndef OC_SDI_INTERAL_H
#define OC_SDI_INTERAL_H

#include "oc_ri.h"
#include "oc_uuid.h"
#include "oc_pstat.h"

#ifdef __cplusplus
extern "C" {
#endif

// Security Domain Information (SDI) Resource

// Data of a SDI resource
typedef struct
{
  bool priv; // privacy flag, indicates whether the SDI is copied to "/oic/res",
             // and thus whether it is publicly visible or private.
  oc_uuid_t uuid;   // UUID that identifies the Security Domain
  oc_string_t name; // human-friendly name for the Security Domain
} oc_sec_sdi_t;

#define OCF_SEC_SDI_URI "/oic/sec/sdi"
#define OCF_SEC_SDI_RT "oic.r.sdi"
#define OCF_SEC_SDI_IF_MASK (OC_IF_BASELINE | OC_IF_RW)
#define OCF_SEC_SDI_DEFAULT_IF (OC_IF_RW)
#define OCF_SEC_SDI_STORE_NAME "sdi"

/**
 * @brief Allocate sdi resource data for all devices.
 */
void oc_sec_sdi_init(void);

/**
 * @brief Deallocate all sdi resource data.
 */
void oc_sec_sdi_free(void);

/**
 * @brief Reset sdi resource data to empty values.
 *
 * @param device device index
 */
void oc_sec_sdi_default(size_t device);

/**
 * @brief Get pointer to the sdi representation of given device
 *
 * @param device device index
 * @return oc_sec_sdi_t* sdi data for given device
 */
oc_sec_sdi_t *oc_sec_sdi_get(size_t device);

/**
 * @brief Copy SDI data from source to destination
 *
 * @param dst destination (cannot be NULL)
 * @param src source (cannot be NULL)
 */
void oc_sec_sdi_copy(oc_sec_sdi_t *dst, const oc_sec_sdi_t *src);

/**
 * @brief Deallocate all data and set them to zero.
 *
 * @param sdi sdi to clear (cannot be NULL)
 */
void oc_sec_sdi_clear(oc_sec_sdi_t *sdi);

/**
 * @brief Encode sdi to global encoder
 *
 * @param sdi sdi to encode
 * @param sdi_res resource with baseline properties (only used when iface_mask
 * contains OC_IF_BASELINE)
 * @param iface_mask encoding interface
 * @return 0 on success
 * @return <0 on error
 */
int oc_sec_sdi_encode_with_resource(const oc_sec_sdi_t *sdi,
                                    const oc_resource_t *sdi_res,
                                    oc_interface_mask_t iface_mask);

/**
 * @brief Convenience wrapper for oc_sec_sdi_encode_with_resource. Will encode
 * global sdi data and resource associated with given device.
 */
int oc_sec_sdi_encode(size_t device, oc_interface_mask_t iface_mask);

/**
 * @brief Decode representation to structure.
 *
 * @param rep representation to decode (cannot be NULL)
 * @param state device state (some properties are only modifiable in selected
 * state, otherwise an error is returned)
 * @param from_storage data is loaded from storage (device state checks are
 * disabled if true)
 * @param[out] sdi output structure to store the decoded data (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool oc_sec_sdi_decode_with_state(const oc_rep_t *rep, oc_dostype_t state,
                                  bool from_storage, oc_sec_sdi_t *sdi);

/**
 * @brief Convenience wrapper for oc_sec_sdi_decode_with_state. Will encode
 * global sdi data associated with given device.
 */
bool oc_sec_sdi_decode(size_t device, const oc_rep_t *rep, bool from_storage);

/**
 * @brief Create sdi (/oic/sec/sdi) resource for given device
 *
 * @param device device index
 */
void oc_sec_sdi_create_resource(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_SDI_INTERAL_H */
