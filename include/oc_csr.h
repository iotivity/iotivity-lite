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

#ifndef OC_CSR_H
#define OC_CSR_H

#ifdef OC_SECURITY

#include "oc_export.h"

#include <mbedtls/build_info.h>
#include <mbedtls/md.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_SEC_CSR_URI "/oic/sec/csr"
#define OCF_SEC_CSR_RT "oic.r.csr"

#ifdef OC_PKI

/**
 * @brief Generate certificate signing request for given device in a PEM string
 * format.
 *
 * @param[in] device device index
 * @param[in] md message digests to use
 * @param[out] csr buffer to store the csr string
 * @param[in] csr_size size of the buffer
 * @return 0 on success
 * @return -1 on error
 */
OC_API
int oc_sec_csr_generate(size_t device, mbedtls_md_type_t md, unsigned char *csr,
                        size_t csr_size);

#endif /* OC_PKI */

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY */
#endif /* OC_CSR_H */
