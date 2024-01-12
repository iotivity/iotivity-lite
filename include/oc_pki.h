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

#include "oc_export.h"
#include "oc_sp.h"
#include <mbedtls/build_info.h>
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/x509_crt.h>

#include <stddef.h>
#include <stdbool.h>

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
OC_API
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
OC_API
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
OC_API
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
OC_API
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
OC_API
int oc_pki_add_trust_anchor(size_t device, const unsigned char *cert,
                            size_t cert_size);

typedef struct
{
  void *data;           ///< pointer to custom user data
  void (*free)(void *); ///< function to deallocate custom user data (set to
                        ///< NULL if the data shouldn't be deallocated)
} oc_pki_user_data_t;

/**
 * @brief TLS peer connection
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
OC_API
void oc_pki_set_verify_certificate_cb(oc_pki_verify_certificate_cb_t cb);

/**
 * Get the verification callback for the certificate chain.
 * @return the callback function
 */
OC_API
oc_pki_verify_certificate_cb_t oc_pki_get_verify_certificate_cb(void);

/**
 * @brief           This function loads a private key for use with identity or
 * manufacturer certificates stored in the credential resource of a device. The
 * private key can be provided in either PEM or DER format, or by reference to a
 * previously stored private key in TPM. The function parses the provided
 * private key and returns a loaded private key object, which can then be used
 * in cryptographic operations.
 *
 * @param device    The device index the key belongs to.
 * @param pk       The PK context to fill. It must have been initialized
 *                  but not set up.
 * @param key       Input buffer to parse.
 *                  The buffer must contain the input exactly, with no
 *                  extra trailing material. For PEM, the buffer must
 *                  contain a null-terminated string. It could be PEM, DER or
 *                  the reference key (eg in TPM).
 * @param keylen    Size of \b key in bytes.
 *                  For PEM data, this includes the terminating null byte,
 *                  so \p keylen must be equal to `strlen(key) + 1`.
 * @param pwd       Optional password for decryption.
 *                  Pass \c NULL if expecting a non-encrypted key.
 *                  Pass a string of \p pwdlen bytes if expecting an encrypted
 *                  key; a non-encrypted key will also be accepted.
 *                  The empty password is not supported.
 * @param pwdlen    Size of the password in bytes.
 *                  Ignored if \p pwd is \c NULL.
 * @param f_rng     RNG function, must not be \c NULL. Used for blinding.
 * @param p_rng     RNG parameter
 *
 * @note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If
 * you need a specific key type, check the result with mbedtls_pk_can_do().
 *
 * @note            The key is also checked for correctness.
 *
 * @return          0 if successful, or a specific PK or PEM error code
 * @see
 * https://arm-software.github.io/CMSIS-mbedTLS/latest/pk_8h.html#aad02107b63f2a47020e6e1ef328e4393
 */
typedef int (*mbedtls_pk_parse_key_cb_t)(
  size_t device, mbedtls_pk_context *pk, const unsigned char *key,
  size_t keylen, const unsigned char *pwd, size_t pwdlen,
  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

/**
 * @brief            This function writes a private key to the credential
 * resource for storage. The private key can be provided as an object and will
 * be written in either PKCS#1 or SEC1 DER structure, depending on the specified
 * format. Alternatively, a reference to a private key stored in TPM can be
 * provided, and the function will write the reference to the credential
 * resource. Once the private key is written, it can be used with identity or
 * manufacturer certificates for cryptographic operations. Note: data is written
 * at the end of the buffer! Use the return value to determine where you should
 * start using the buffer
 *
 * @param device    The device index the key belongs to.
 * @param ctx       PK context which must contain a valid private key.
 * @param buf       buffer to write to
 * @param size      size of the buffer
 *
 * @return          length of data written if successful, or a specific
 *                  error code
 * @see
 * https://arm-software.github.io/CMSIS-mbedTLS/latest/pk_8h.html#a2cf4ebaa430cc90954c9556ace2d4dc0
 */
typedef int (*mbedtls_pk_write_key_der_cb_t)(size_t device,
                                             const mbedtls_pk_context *ctx,
                                             unsigned char *buf, size_t size);

/**
 * @brief           This function generates the ECP key for the identity
 * certificate of the device. If the device has a TPM, the function will
 * generate a private key within the TPM and store it there. The generated key
 * is returned as an object that can be used to create an identity certificate.
 *
 * @param device    The device index the key belongs to.
 * @param grp_id    The ECP group identifier.
 * @param pk       The destination key. The key is initialized by
 * MBEDTLS_PK_ECKEY.
 * @param f_rng     The RNG function to use. This must not be \c NULL.
 * @param p_rng     The RNG context to be passed to \p f_rng. This may
 *                  be \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX error code
 *                  on failure.
 * @see
 * https://arm-software.github.io/CMSIS-mbedTLS/latest/ecp_8h.html#a0c9a407214f019493ba5d7bc27fa57dc
 */
typedef int (*mbedtls_pk_ecp_gen_key_cb_t)(
  size_t device, mbedtls_ecp_group_id grp_id, mbedtls_pk_context *pk,
  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

/**
 * @brief          This function frees the private key of the device generated
 * by mbedtls_pk_ecp_gen_key_cb_t. It is called when factory reset is performed
 * or during generating csr when the key-pair is not valid.
 *
 * @param device   The device index the key belongs to.
 * @param key      The private key to free.
 * @param keylen   The length of the private key.
 *
 * @return         true, the key is invalid and needs to be regenerated
 * @return         false, the key is still valid
 *
 * @note default implementation returns false, so the key is same as before.
 *
 * @see oc_mbedtls_pk_ecp_gen_key
 */
typedef bool (*pk_free_key_cb_t)(size_t device, const unsigned char *key,
                                 size_t keylen);

typedef struct oc_pki_pk_functions_s
{
  mbedtls_pk_parse_key_cb_t mbedtls_pk_parse_key;
  mbedtls_pk_write_key_der_cb_t mbedtls_pk_write_key_der;
  mbedtls_pk_ecp_gen_key_cb_t mbedtls_pk_ecp_gen_key;
  pk_free_key_cb_t pk_free_key;
} oc_pki_pk_functions_t;

/**
 * Set the PK functions for the identity certificate or the manufacturer
 * certificate.
 * @param[in] pk_functions the PK functions, if NULL, the default mbedtls
 * functions will be used.
 * @return true if the PK functions have been set.
 * @return false when any of the functions is NULL.
 */
OC_API
bool oc_pki_set_pk_functions(const oc_pki_pk_functions_t *pk_functions);

/**
 * Get the PK functions for the identity certificate or the manufacturer
 * certificate.
 * @param[out] pk_functions the PK functions
 * @return true if the PK functions have been configured through the
 * oc_pki_set_pk_functions function.
 */
OC_API
bool oc_pki_get_pk_functions(oc_pki_pk_functions_t *pk_functions);

#ifdef __cplusplus
}
#endif

#endif /* OC_PKI */

#endif /* OC_PKI_H */
