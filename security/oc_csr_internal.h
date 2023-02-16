/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
 *               2018-2019 Intel Corporation
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

#ifndef OC_CSR_INTERNAL_H
#define OC_CSR_INTERNAL_H

#include "oc_helpers.h"
#include "oc_ri.h"

#include <mbedtls/build_info.h>
#include <mbedtls/x509_csr.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verify CSR signature
 *
 * @param csr parsed CSR to check (cannot be NULL)
 * @param md_flags bitmask of allowed signatures (if 0 then signature is not
 * checked)
 * @return true on success
 * @return false on failure
 */
bool oc_sec_csr_verify_signature(mbedtls_x509_csr *csr, int md_flags);

/**
 * @brief Verify CSR and optionally extract data from the request.
 *
 * @param[in] csr CSR in PEM string format
 * @param[in] csr_len length of the CSR PEM string
 * @param[in] pk_type expected public key type of the CSR
 * @param[in] md_flags bitmask of allowed signatures (if 0 then signature is not
 * checked)
 * @param[out] subject_DN store subject parsed from a Distinguished Name of the
 * CSR, must be then freed by the caller (if NULL the subject won't be parsed)
 * @param[out] public_key buffer to store the parsed public key (if NULL then
 * public key won't be parsed)
 * @param[in] public_key_size size of the public key buffer
 * @return 0 on success
 * @return -1 on error
 */
int oc_sec_csr_validate(const unsigned char *csr, size_t csr_len,
                        mbedtls_pk_type_t pk_type, int md_flags,
                        oc_string_t *subject_DN, uint8_t *public_key,
                        size_t public_key_size);

/// Get request handler for /oic/sec/csr
void get_csr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_CSR_INTERNAL_H */
