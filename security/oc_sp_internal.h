/****************************************************************************
 *
 * Copyright (c) 2018-2019 Intel Corporation
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

#ifndef OC_SP_INTERNAL_H
#define OC_SP_INTERNAL_H

#include "oc_ri.h"
#include "oc_sp.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  unsigned supported_profiles;   ///< mask of supported oc_sp_types_t
  oc_sp_types_t current_profile; ///< selected security profile
  int credid;                    ///< credid of manufacturers certificate
} oc_sec_sp_t;

#define OCF_SEC_SP_URI "/oic/sec/sp"
#define OCF_SEC_SP_RT "oic.r.sp"
#define OCF_SEC_SP_IF_MASK (OC_IF_BASELINE | OC_IF_RW)
#define OCF_SEC_SP_DEFAULT_IF (OC_IF_RW)
#define OCF_SEC_SP_STORE_NAME "sp"

#define OC_SP_BASELINE_OID "1.3.6.1.4.1.51414.0.0.1.0"
#define OC_SP_BLACK_OID "1.3.6.1.4.1.51414.0.0.2.0"
#define OC_SP_BLUE_OID "1.3.6.1.4.1.51414.0.0.3.0"
#define OC_SP_PURPLE_OID "1.3.6.1.4.1.51414.0.0.4.0"

/** @brief Allocate and initialize global variables */
void oc_sec_sp_init(void);

#ifdef OC_HAS_FEATURE_BRIDGE
void oc_sec_sp_new_device(size_t device_index, bool need_realloc);
#endif /* OC_HAS_FEATURE_BRIDGE */

/** @brief Deallocate global variables */
void oc_sec_sp_free(void);

/** @brief Get security profile for given device */
oc_sec_sp_t *oc_sec_sp_get(size_t device);

/** @brief Reset security profile of given device to default values */
void oc_sec_sp_default(size_t device);

/**
 * @brief Copy security profile
 *
 * @param[out] dst destination (cannot be NULL)
 * @param src source (cannot be NULL)
 */
void oc_sec_sp_copy(oc_sec_sp_t *dst, const oc_sec_sp_t *src) OC_NONNULL();

/**
 * @brief Clear security profile
 *
 * @param sp security profile to clear (cannot be NULL)
 */
void oc_sec_sp_clear(oc_sec_sp_t *sp) OC_NONNULL();

typedef enum {
  OC_SEC_SP_ENCODE_INCLUDE_BASELINE = 1 << 0, // include baseline properties
} oc_sec_sp_encode_flag_t;

/**
 * @brief Encode security profile to global encoder
 *
 * @param sp security profile to encode (cannot be NULL)
 * @param sp_res resource with baseline properties (only used when flags contain
 * OC_SEC_SP_ENCODE_INCLUDE_BASELINE)
 * @param flags encoding flags
 * @return 0 on success
 * @return <0 on error
 */
int oc_sec_sp_encode_with_resource(const oc_sec_sp_t *sp,
                                   const oc_resource_t *sp_res, int flags)
  OC_NONNULL(1);

/**
 * @brief Convenience wrapper for oc_sec_sp_encode_with_resource. Will encode
 * global security profile data and resource associated with given device.
 */
bool oc_sec_sp_encode_for_device(size_t device, int flags);

typedef enum {
  OC_SEC_SP_DECODE_FLAG_IGNORE_UNKNOWN_PROPERTIES = 1 << 0,
} oc_sec_sp_decode_flag_t;

/**
 * @brief Decode security profile payload.
 *
 * @param rep representation to decode
 * @param flags mask of decoding flags
 * @param dst output variable to store decoded data (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool oc_sec_sp_decode(const oc_rep_t *rep, int flags, oc_sec_sp_t *dst)
  OC_NONNULL(3);

/**
 * @brief Decode payload and update security profile for given device
 *
 * @note device cannot be in OC_DOS_RFNOP state
 *
 * @param rep representation to decode
 * @param device device index
 * @return true on success, payload was decoded and data for device were updated
 * @return false on failure
 */
bool oc_sec_sp_decode_for_device(const oc_rep_t *rep, size_t device);

/**
 * @brief Parse security profile type from string
 *
 * @param str string to parse (cannot be NULL)
 * @param str_len length of \p str
 *
 * @return oc_sp_types_t on success
 * @return 0 on failure
 */
oc_sp_types_t oc_sec_sp_type_from_string(const char *str, size_t str_len)
  OC_NONNULL();

/**
 * @brief Encode security profile type to string
 *
 * @param sp_type type to encode
 * @return encoded C-string on success
 * @return NULL on failure
 */
const char *oc_sec_sp_type_to_string(oc_sp_types_t sp_type);

/**
 * @brief Create security profile (/oic/sec/sp) resource for given device
 *
 * @param device device index
 */
void oc_sec_sp_create_resource(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_SP_INTERNAL_H */
