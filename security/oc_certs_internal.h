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

#ifndef OC_CERTS_INTERNAL_H
#define OC_CERTS_INTERNAL_H

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "api/c-timestamp/timestamp.h"
#include "oc_role.h"
#include "security/oc_cred_internal.h"

#include <mbedtls/build_info.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Fill with serial number of the certificates with random byte string of given
/// size
int oc_certs_generate_serial_number(mbedtls_x509write_cert *crt, size_t size);

/// @brief Check that string is in PEM format.
bool oc_certs_is_PEM(const unsigned char *cert, size_t cert_len);

/**
 * @brief Extract serial number in a printable form from a x509 certificate.
 *
 * @param[in] cert certificate with the serial number (cannot be NULL)
 * @param[out] buffer output buffer to store the serial number
 * @param[in] buffer_size size of the output buffer
 * @return <0 on error
 * @return >=0 on success, length of the string written (not including the
 * terminating nul byte)
 */
int oc_certs_extract_serial_number(const mbedtls_x509_crt *cert, char *buffer,
                                   size_t buffer_size);

/// @brief Parse PEM string into a x509 certificate and extract serial number in
/// a printable form.
/// @see oc_certs_extract_serial_number
int oc_certs_parse_serial_number(const unsigned char *cert, size_t cert_size,
                                 char *buffer, size_t buffer_size);

/**
 * @brief Extract private key from a x509 certificate.
 *
 * @param[in] cert certificate with the private key (cannot be NULL)
 * @param[out] buffer output buffer to store the key (cannot be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return <0 on error
 * @return >=0 on success, length of data written
 */
int oc_certs_extract_private_key(const mbedtls_x509_crt *cert,
                                 unsigned char *buffer, size_t buffer_size);

/// @brief Parse PEM string into a x509 certificate and extract public key
/// @see oc_certs_extract_private_key
int oc_certs_parse_private_key(const unsigned char *cert, size_t cert_size,
                               unsigned char *buffer, size_t buffer_size);

/**
 * @brief Extract public key from a x509 certificate.
 *
 * @param[in] cert certificate with the public key (cannot be NULL)
 * @param[out] buffer output buffer to store the key (cannot be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return <0 on error
 * @return >=0 on success, length of data written
 */
int oc_certs_extract_public_key(const mbedtls_x509_crt *cert,
                                unsigned char *buffer, size_t buffer_size);

/// Extract public key from a x509 certificate to an oc_string_t.
/// @see oc_certs_extract_public_key
int oc_certs_extract_public_key_to_oc_string(const mbedtls_x509_crt *cert,
                                             oc_string_t *buffer);

/// @brief Parse PEM string into a x509 certificate and extract public key.
/// @see oc_certs_extract_public_key.
int oc_certs_parse_public_key(const unsigned char *cert, size_t cert_size,
                              unsigned char *buffer, size_t buffer_size);

/// Parse PEM string into a x509 certificate and extract public key to an
/// oc_string_t.
/// @see oc_certs_parse_public_key
int oc_certs_parse_public_key_to_oc_string(const unsigned char *cert,
                                           size_t cert_size,
                                           oc_string_t *buffer);

/**
 * @brief Encode UUID into a nul-terminated C-String for a Common Name field of
 * a certificate.
 *
 * @param[in] uuid UUID to encode (cannot be NULL)
 * @param[out] buf output buffer to store the encoded UUID
 * @param[in] buf_len size of the output buffer
 * @return true on success
 * @return false on failure
 */
bool oc_certs_encode_CN_with_UUID(const oc_uuid_t *uuid, char *buf,
                                  size_t buf_len);

/**
 * @brief Extract uuid stored in the subject's Common name field in a x509
 * certificate.
 *
 * @param[in] cert the certificate to examine (cannot be NULL)
 * @param[out] buffer output buffer to store the uuid (cannot be NULL)
 * @param[in] buffer_size size of the output buffer (must be >=OC_UUID_LEN)
 * @return <0 on error
 * @return =0 on success
 */
bool oc_certs_extract_CN_for_UUID(const mbedtls_x509_crt *cert, char *buffer,
                                  size_t buffer_size);

/// @brief Parse PEM string into a x509 certificate and extract uuid stored in
/// the subject's Common Name field.
/// @see oc_certs_extract_CN_for_UUID.
bool oc_certs_parse_CN_for_UUID(const unsigned char *cert, size_t cert_size,
                                char *buffer, size_t buffer_size);

/**
 * @brief Encode role and authority into a nul-terminated C-String for a Common
 * Name and Organizational Unit fields of a certificate.
 *
 * The Common Name (CN) component contains the role and the Organizational Unit
 * (OU) component contains the authority.
 *
 * @param[in] role role and authority to encode
 * @param[out] buf output buffer to store the encoded data
 * @param[in] buf_len size of the output buffer
 * @return true on success
 * @return false on failure
 */
bool oc_certs_encode_role(const oc_role_t *role, char *buf, size_t buf_len);

/**
 * @brief Extract the first role and authority pair from Common Name and
 * Organizational Unit fields of a certificate.
 *
 * @param[in] cert the certificate to examine (cannot be NULL)
 * @param[out] role output variable to store the parsed role (cannot be NULL,
 * must be deallocated by the caller)
 * @param[out] authority output variable to store the parsed role (cannot be
 * NULL, must be deallocated by the caller)
 * @return true on success
 * @return false on error
 */
bool oc_certs_extract_first_role(const mbedtls_x509_crt *cert,
                                 oc_string_t *role, oc_string_t *authority);

/// @brief Parse PEM string into a x509 certificate and extract the first role
/// and authority pair from fields of the certificate.
/// @see oc_certs_extract_first_role.
bool oc_certs_parse_first_role(const unsigned char *cert, size_t cert_size,
                               oc_string_t *role, oc_string_t *authority);

/// Get current clocktime encoded as timestamp_t
timestamp_t oc_certs_timestamp_now(void);

/// Convert mbedtls_x509_time to UNIX timestamp
uint64_t oc_certs_time_to_unix_timestamp(mbedtls_x509_time time);

/**
 * @brief Convert timestamp into a UTC timezone string expected by the x509
 * certificate in the notBefore and notAfter fields.
 *
 * @param ts timestamp to convert
 * @param buffer output buffer (cannot be NULL)
 * @param buffer_size size of the output buffer
 * @return true on success
 * @return false on failure
 */
bool oc_certs_timestamp_format(timestamp_t ts, char *buffer,
                               size_t buffer_size);

/// Serialize certificate chain to PEM string
int oc_certs_serialize_chain_to_pem(const mbedtls_x509_crt *cert_chain,
                                    char *output_buffer,
                                    size_t output_buffer_len);

/// Check if the child certificate has been issued by the other certificate
int oc_certs_is_subject_the_issuer(const mbedtls_x509_crt *issuer,
                                   const mbedtls_x509_crt *child);

/**
 * @brief Parse role certificate from a PEM string.
 *
 * @param rcert role certificate in PEM string format
 * @param rcert_size length of the role certificate
 * @param role_cred allocated credential to store the first role-authority pair
 * in the certificate
 * @param roles_resource is the roles resource
 * @return 0 on success
 * @return -1 on failure
 */
int oc_certs_parse_role_certificate(const unsigned char *rcert,
                                    size_t rcert_size, oc_sec_cred_t *role_cred,
                                    bool roles_resource);

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY & OC_PKI */

#endif /* OC_CERTS_INTERNAL_H */
