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

#ifndef OC_CERTS_VALIDATE_INTERNAL_H
#define OC_CERTS_VALIDATE_INTERNAL_H

#if defined(OC_SECURITY) && defined(OC_PKI)

#include <mbedtls/build_info.h>
#include <mbedtls/x509_crt.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Validate a non-leaf certificate (root or intermediate)
 *
 * @param cert certificate to validate (cannot be NULL)
 * @param is_root is a root certificate (root certificates must be self-issues,
 * others must not)
 * @param is_otm device is in RFOTM state
 * @param depth certificate depth
 * @param[out] flags flags representing current flags for that specific
 * certificate (cannot be NULL)
 * @return 0 on success
 * @return -1 on failure
 */
int oc_certs_validate_non_end_entity_cert(const mbedtls_x509_crt *cert,
                                          bool is_root, bool is_otm, int depth,
                                          uint32_t *flags);

/**
 * @brief Validate a leaf certificate.
 *
 * @param ee_cert certificate to validate (cannot be NULL)
 * @param[out] flags flags representing current flags for that specific
 * certificate (cannot be NULL)
 * @return 0 on success
 * @return -1 on failure
 */
int oc_certs_validate_end_entity_cert(const mbedtls_x509_crt *ee_cert,
                                      uint32_t *flags);

/**
 * @brief Validate a role certificate.
 *
 * @param role_cert certificate to validate (cannot be NULL)
 * @param[out] flags flags representing current flags for that specific
 * certificate (cannot be NULL)
 * @return 0 on success
 * @return -1 on failure
 */
int oc_certs_validate_role_cert(const mbedtls_x509_crt *role_cert,
                                uint32_t *flags);

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY & OC_PKI */

#endif /* OC_CERTS_VALIDATE_INTERNAL_H */
