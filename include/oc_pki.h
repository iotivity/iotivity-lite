/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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
 *
 * OCF public key infrastructure (PKI) functions
 *
 * Collection of functions used to add public key infrastructure (PKI)
 * support to devices.
 */
#ifndef OC_PKI_H
#define OC_PKI_H
#ifdef OC_PKI

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "oc_sp.h"
#include <mbedtls/build_info.h>
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/x509_crt.h>

/**
 * Add a PKI identity certificate.
 *
 * @param[in] device index of the logical device the identity certificate
 *                   belongs to
 * @param[in] cert pointer to a string containing a PEM encoded identity
 *                 certificate
 * @param[in] cert_size the size of the `cert` string
 * @param[in] key the PEM encoded private key associated with this certificate
 * @param[in] key_size the size of the `key` string
 *
 * @return
 *  - the credential ID of the /oic/sec/cred entry containing the certificate
 *    chain
 *  - `-1` on failure
 */
int oc_pki_add_identity_cert(size_t device, const unsigned char *cert,
                             size_t cert_size, const unsigned char *key,
                             size_t key_size);

/**
 * Add the manufacturer's PKI identity certificate.
 *
 * @param[in] device index of the logical device the identity certificate
 *                   belongs to
 * @param[in] cert pointer to a string containing a PEM encoded identity
 *                 certificate
 * @param[in] cert_size the size of the `cert` string
 * @param[in] key the PEM encoded private key associated with this certificate
 * @param[in] key_size the size of the `key` string
 *
 * @return
 *  - the credential ID of the /oic/sec/cred entry containing the certificate
 *    chain
 *  - `-1` on failure
 */
int oc_pki_add_mfg_cert(size_t device, const unsigned char *cert,
                        size_t cert_size, const unsigned char *key,
                        size_t key_size);

/**
 * Add an intermediate manufacture CA certificate.
 *
 * @param[in] device index of the logical device the certificate chain belongs
 * to
 * @param[in] credid the credential ID of the /oic/sec/cred entry containing the
 *                   end-entity certificate
 * @param[in] cert pointer to a string containing a PEM encoded certificate
 * @param[in] cert_size the size of the `cert` string
 *
 * @return
 *   - the credential ID of the /oic/sec/cred entry containing the certificate
 *     chain
 *   - `-1` on failure
 */
int oc_pki_add_mfg_intermediate_cert(size_t device, int credid,
                                     const unsigned char *cert,
                                     size_t cert_size);

/**
 * Add manufacture trust anchor CA
 *
 * @param[in] device index of the logical device the trust anchor CA belongs to
 * @param[in] cert pointer to a string containing a PEM encoded certificate
 * @param[in] cert_size the size of the `cert` string
 *
 * @return
 *  - the credential ID of the /oic/sec/cred entry containing the certificate
 *    chain
 *  - `-1` on failure
 */
int oc_pki_add_mfg_trust_anchor(size_t device, const unsigned char *cert,
                                size_t cert_size);

/**
 * Add trust anchor CA
 *
 * @param[in] device index of the logical device the trust anchor CA belongs to
 * @param[in] cert pointer to a string containing a PEM encoded certificate
 * @param[in] cert_size the size of the `cert` strung
 *
 * @return
 *  - the credential ID of the /oic/sec/cred entry containing the certificate
 *    chain
 *  - `-1` on failure
 */
int oc_pki_add_trust_anchor(size_t device, const unsigned char *cert,
                            size_t cert_size);

/**
 * @brief TLS peer connection
 *
 */
struct oc_tls_peer_t;

/**
 * @brief Callback invoked after ocf verifies the certificate chain. For each
 * certificate in the chain, the callback is invoked with the depth of the
 * certificate in the chain.
 *
 * @param peer TLS peer connection
 * @param crt Certificate
 * @param depth Depth of the certificate chain, 0 is the leaf certificate.
 * @param flags Verification flags from mbedtls_x509_crt_verify(), see
 * https://github.com/Mbed-TLS/mbedtls/blob/10ada3501975e7abab25a7fa28e9e8e0f6b4259f/include/mbedtls/x509.h#L99
 *
 * @return 0 if the certificate is valid, otherwise -1
 */
typedef int (*oc_pki_verify_certificate_cb_t)(struct oc_tls_peer_t *peer,
                                              const mbedtls_x509_crt *crt,
                                              int depth, uint32_t *flags);

/**
 * Set the verification callback for the certificate chain. It is invoked after
 * ocf verifies the certificate chain.
 * @param[in] cb the callback function
 */
void oc_pki_set_verify_certificate_cb(oc_pki_verify_certificate_cb_t cb);

/**
 * Get the verification callback for the certificate chain.
 * @return the callback function
 */
oc_pki_verify_certificate_cb_t oc_pki_get_verify_certificate_cb(void);

#ifdef __cplusplus
}
#endif
#endif /* OC_PKI */
#endif /* OC_PKI_H */
