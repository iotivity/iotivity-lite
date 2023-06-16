/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *               2019 Intel Corporation
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

#ifndef OC_CERTS_GENERATE_INTERNAL_H
#define OC_CERTS_GENERATE_INTERNAL_H

#if defined(OC_SECURITY) && defined(OC_PKI) && defined(OC_DYNAMIC_ALLOCATION)

#include "api/c-timestamp/timestamp.h"
#include "oc_role.h"
#include "util/oc_compiler.h"

#include <mbedtls/build_info.h>
#include <mbedtls/x509_crt.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Fill with serial number of the certificates with random byte string of given
/// size
int oc_certs_generate_serial_number(mbedtls_x509write_cert *crt, size_t size)
  OC_NONNULL();

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
bool oc_certs_timestamp_format(timestamp_t ts, char *buffer, size_t buffer_size)
  OC_NONNULL();

/**
 * @brief Encode role and authority into a nul-terminated C-String for a Common
 * Name and Organizational Unit fields of a certificate.
 *
 * The Common Name (CN) component contains the role and the Organizational Unit
 * (OU) component contains the authority.
 *
 * @param[in] role role and authority to encode (cannot be NULL)
 * @param[out] buf output buffer to store the encoded data (cannot be NULL)
 * @param[in] buf_len size of the output buffer
 * @return true on success
 * @return false on failure
 */
bool oc_certs_encode_role(const oc_role_t *role, char *buf, size_t buf_len)
  OC_NONNULL();

/**
 * @brief Encode linked list of role and authority pairs into linked list of
 * mbedtls_x509_general_names*
 *
 * @param[in] roles linked list of role-authority pairs
 * @param[out] general_names output pointer to store linked list of
 * mbedtls_x509_general_names* (cannot be NULL, must be deallocated by
 * oc_certs_free_encoded_roles)
 * @return >=0 on success, number of encoded roles
 * @return -1 on error
 */
int oc_certs_encode_roles(const oc_role_t *roles,
                          mbedtls_x509_general_names **general_names)
  OC_NONNULL(2);

/// @brief Deallocate a linked list of mbedtls_x509_general_names*
void oc_certs_free_encoded_roles(mbedtls_x509_general_names *general_names);

typedef struct oc_certs_validity_t
{
  timestamp_t not_before;
  timestamp_t not_after;
} oc_certs_validity_t;

typedef struct oc_certs_buffer_t
{
  const uint8_t *value;
  size_t size;
} oc_certs_buffer_t;

typedef oc_certs_buffer_t oc_certs_key_t;

typedef struct oc_certs_subject_t
{
  const char *name; ///< the subject name for a Certificate Subject names should
                    ///< contain a comma-separated list  of OID types and
                    ///< values: e.g."C=UK,O=ARM,CN=mbed TLS Server 1"
  oc_certs_key_t public_key;
  oc_certs_key_t private_key;
} oc_certs_subject_t;

typedef struct oc_certs_issuer_t
{
  const char *name;
  oc_certs_key_t private_key;
} oc_certs_issuer_t;

typedef struct oc_certs_key_usage_t
{
  unsigned int key_usage;
  oc_certs_buffer_t extended_key_usage;
} oc_certs_key_usage_t;

typedef struct oc_certs_generate_t
{
  oc_certs_buffer_t personalization_string; // cannot be empty
  size_t serial_number_size;    // number of bytes in serial number to generate
  oc_certs_validity_t validity; // not before and not after timestamps
  oc_certs_subject_t subject;
  oc_certs_issuer_t issuer;
  oc_certs_key_usage_t key_usage;
  mbedtls_md_type_t signature_md; // MD algorithm to use for the signature
  bool is_CA;                     // is a self-signed CA certificate
  const oc_role_t *roles;         // roles for a Role certificate
} oc_certs_generate_t;

/**
 * @brief Generate a certificate in PEM format.
 *
 * @param[in] data certificate data (cannot be NULL)
 * @param[out] buffer output buffer to store the generated certificate (cannot
 * be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return >=0 on success, size of the generated certificate
 * @return -1 on error
 */
int oc_certs_generate(const oc_certs_generate_t *data, unsigned char *buffer,
                      size_t buffer_size) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY & OC_PKI && OC_DYNAMIC_ALLOCATION */

#endif /* OC_CERTS_GENERATE_INTERNAL_H */
