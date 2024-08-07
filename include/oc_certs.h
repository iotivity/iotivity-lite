/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
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
#ifndef OC_CERTS_H
#define OC_CERTS_H

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "oc_export.h"

#include "mbedtls/build_info.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/x509_crt.h"

#include <stdbool.h>

// mask of OCF-supported message digests
#define OCF_CERTS_SUPPORTED_MDS                                                \
  (MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |                                   \
   MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384))

// mask of OCF-supported elliptic curves
#define OCF_CERTS_SUPPORTED_ELLIPTIC_CURVES                                    \
  (MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1) |                            \
   MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set message digest to use when generating certificates or certificate
 * signing requests.
 *
 * @param md message digest to use in signatures
 */
OC_API
void oc_sec_certs_md_set_signature_algorithm(mbedtls_md_type_t md);

/**
 * @brief Get message digest to use when generating certificates or certificate
 * signing requests.
 *
 * @return message digest to use in signatures
 */
OC_API
mbedtls_md_type_t oc_sec_certs_md_signature_algorithm(void);

/**
 * @brief Set the bitmask of globally allowed message digest types.
 *
 * @param md_mask bitmask of globally allowed message digest types
 */
OC_API
void oc_sec_certs_md_set_algorithms_allowed(unsigned md_mask);

/**
 * @brief Return bitmask of globally allowed message digest types.
 *
 * @return bitmask of globally allowed message digest types
 *
 * @see oc_sec_certs_md_set_algorithms_allowed
 */
OC_API
unsigned oc_sec_certs_md_algorithms_allowed(void);

/**
 * @brief Check if the message digest is allowed globally by IoTivity-lite.
 *
 * @param md message digest to check
 * @return true md is allowed
 * @return false md is not allowed
 *
 * @see oc_sec_certs_md_set_algorithms_allowed
 */
OC_API
bool oc_sec_certs_md_algorithm_is_allowed(mbedtls_md_type_t md);

/**
 * @brief Set elliptic curve to be used when generating keys for CSRs or
 * certificates.
 *
 * @param gid group identifier of the curve to be used
 */
OC_API
void oc_sec_certs_ecp_set_group_id(mbedtls_ecp_group_id gid);

/**
 * @brief Get elliptic curve to be used when generating keys for CSRs or
 * certificates.
 *
 * @return group identifier of the curve used in signatures
 */
OC_API
mbedtls_ecp_group_id oc_sec_certs_ecp_group_id(void);

/**
 * @brief Set the bitmask of globally allowed elliptic curves.
 *
 * @param gid_mask bitmask of globally allowed elliptic curve groupids
 */
OC_API
void oc_sec_certs_ecp_set_group_ids_allowed(unsigned gid_mask);

/**
 * @brief Return bitmask of globally allowed elliptic curves.
 *
 * @return bitmask of globally allowed elliptic curve groupids
 *
 * @see oc_sec_certs_ecp_set_group_ids_allowed
 */
OC_API
unsigned oc_sec_certs_ecp_group_ids_allowed(void);

/**
 * @brief Check if the elliptic curve is allowed globally by IoTivity-lite.
 *
 * @param gid group id of the elliptic curve to check
 * @return true elliptic curve is allowed
 * @return false elliptic curve is not allowed
 *
 * @see oc_sec_certs_ecp_set_group_ids_allowed
 */
OC_API
bool oc_sec_certs_ecp_group_id_is_allowed(mbedtls_ecp_group_id gid);

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY & OC_PKI */

#endif /* OC_CERTS_H */
