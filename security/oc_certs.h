/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_CERTS_H
#define OC_CERTS_H

#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

int oc_certs_parse_CN_for_UUID(const mbedtls_x509_crt *cert,
                               oc_string_t *subjectuuid);

int oc_certs_serialize_chain_to_pem(const mbedtls_x509_crt *cert_chain,
                                    char *output_buffer,
                                    size_t output_buffer_len);

int oc_certs_extract_public_key(const mbedtls_x509_crt *cert,
                                uint8_t *public_key);

int oc_certs_validate_root_cert(mbedtls_x509_crt *root_cert);

int oc_certs_validate_intermediate_cert(mbedtls_x509_crt *int_cert);

int oc_certs_validate_end_entity_cert(mbedtls_x509_crt *ee_cert);

int oc_certs_is_subject_the_issuer(mbedtls_x509_crt *issuer,
                                   mbedtls_x509_crt *child);

#ifdef __cplusplus
}
#endif
#endif /* OC_CERTS_H */
