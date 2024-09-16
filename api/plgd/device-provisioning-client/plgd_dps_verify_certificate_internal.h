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

#ifndef PLGD_DPS_VERIFY_CERTIFICATE_INTERNAL_H
#define PLGD_DPS_VERIFY_CERTIFICATE_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "plgd_dps_log_internal.h"

#include "oc_pki.h"
#include "security/oc_tls_internal.h" // oc_tls_peer_t
#include "util/oc_compiler.h"

#include "mbedtls/build_info.h"
#include "mbedtls/md.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief User data for custom certificate verification function that stores the
 * original verification function with data
 */
typedef struct
{
  oc_tls_pki_verification_params_t orig_verify;
  bool fingerprint_verified;
} dps_verify_certificate_data_t;

/**
 * @brief Allocate and initialize custom user data for dps_verify_certificate
 *
 * @param orig_verify original vertification parameters
 * @return dps_verify_certificate_data_t* on success allocated and initialized
 * data
 * @return NULL on failure
 */
dps_verify_certificate_data_t *dps_verify_certificate_data_new(
  oc_tls_pki_verification_params_t orig_verify);

/**
 * @brief Free previously allocated dps_verify_certificate_data_t
 *
 * @note void* is used to match oc_pki_user_data_t::free signature
 *
 * @param data dps_verify_certificate_data_t*
 */
void dps_verify_certificate_data_free(void *data);

/**
 * @brief Certificate verification function that invokes the original
 * verification function stored in the peers user data. If the original
 * verification fails then fingerprint verification runs if is enabled.
 *
 * @param peer (D)TLS peer (cannot be NULL)
 * @param crt certificate (cannot be NULL)
 * @param depth depth of the certificate within the certificate chain
 * @param[out] flags verification flags
 * @return 0 on success
 * @return != 0 on failure
 */
int dps_verify_certificate(oc_tls_peer_t *peer, const mbedtls_x509_crt *crt,
                           int depth, uint32_t *flags) OC_NONNULL(1, 2);

#if DPS_DBG_IS_ENABLED

/// @brief Print fingerprint.
void dps_print_fingerprint(mbedtls_md_type_t md_type,
                           const unsigned char *fingerprint,
                           size_t fingerprint_size);

#endif /* DPS_DBG_IS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_VERIFY_CERTIFICATE_INTERNAL_H */
