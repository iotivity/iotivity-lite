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
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verify a CSR.
 *
 * @param csr certificate signing request (cannot be NULL)
 * @param pk_type expected public key type of the CSR
 * @param md_flags bitmask of allowed signatures (if 0 then signature is not
 * checked)
 * @return true CSR is valid
 * @return false otherwise
 */
bool oc_sec_csr_validate(mbedtls_x509_csr *csr, mbedtls_pk_type_t pk_type,
                         int md_flags);

/**
 * @brief Extract subject from a CSR.
 *
 * @param csr certificate signing request (cannot be NULL)
 * @param[out] buffer output buffer to store the subject
 * @param buffer_size size of the output buffer
 * @return >=0 on success, length of the extracted subject (without the
 * terminating NUL)
 * @return -1 on error
 */
int oc_sec_csr_extract_subject_DN(const mbedtls_x509_csr *csr, char *buffer,
                                  size_t buffer_size);

/**
 * @brief Extract public key from a CSR.
 *
 * @param csr certificate signing request (cannot be NULL)
 * @param[out] buffer output buffer to store the subject
 * @param buffer_size size of the output buffer
 * @return >=0 size of the extracted public key
 * @return -1 on error
 */
int oc_sec_csr_extract_public_key(const mbedtls_x509_csr *csr, uint8_t *buffer,
                                  size_t buffer_size);

/**
 * @brief Create CSR (/oic/sec/csr) resource for given device.
 *
 * @param device device index
 */
void oc_sec_csr_create_resource(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_CSR_INTERNAL_H */
