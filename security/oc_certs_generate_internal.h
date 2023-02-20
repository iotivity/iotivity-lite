/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
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

#if defined(OC_SECURITY) && defined(OC_PKI)

#ifdef __cplusplus
extern "C" {
#endif

#include "api/c-timestamp/timestamp.h"

#include <mbedtls/build_info.h>
#include <mbedtls/x509_crt.h>
#include <stddef.h>

/// Fill with serial number of the certificates with random byte string of given
/// size
int oc_certs_generate_serial_number(mbedtls_x509write_cert *crt, size_t size);

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
} oc_certs_generate_t;

int oc_certs_generate(oc_certs_generate_t data, unsigned char *buffer,
                      size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY & OC_PKI */

#endif /* OC_CERTS_GENERATE_INTERNAL_H */
