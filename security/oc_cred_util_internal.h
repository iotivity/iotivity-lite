/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#ifndef OC_CRED_UTIL_INTERNAL_H
#define OC_CRED_UTIL_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_cred.h"
#include "security/oc_cred_internal.h"
#include "util/oc_list.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_ENCODING_BASE64_STR "oic.sec.encoding.base64"
#define OC_ENCODING_RAW_STR "oic.sec.encoding.raw"
#define OC_ENCODING_HANDLE_STR "oic.sec.encoding.handle"
#ifdef OC_PKI
#define OC_ENCODING_PEM_STR "oic.sec.encoding.pem"

#define OC_CREDUSAGE_TRUSTCA_STR "oic.sec.cred.trustca"
#define OC_CREDUSAGE_IDENTITY_CERT_STR "oic.sec.cred.cert"
#define OC_CREDUSAGE_ROLE_CERT_STR "oic.sec.cred.rolecert"
#define OC_CREDUSAGE_MFG_TRUSTCA_STR "oic.sec.cred.mfgtrustca"
#define OC_CREDUSAGE_MFG_CERT_STR "oic.sec.cred.mfgcert"
#endif /* OC_PKI */

#define OC_CREDTYPE_PSK_STR "Symmetric pair-wise key"
#define OC_CREDTYPE_CERT_STR "Asymmetric signing key with certificate"

/** Convert encoding to oc_string_view_t */
oc_string_view_t oc_cred_encoding_to_string(oc_sec_encoding_t encoding);

/**
 * @brief Parse cred encoding from string
 *
 * @param str string (cannot be NULL)
 * @param str_len length of \p str
 * @return oc_sec_encoding_t parsed encoding
 */
oc_sec_encoding_t oc_cred_encoding_from_string(const char *str, size_t str_len)
  OC_NONNULL();

/** Compare cred_data_t and oc_sec_encoded_data_t. */
bool oc_cred_data_is_equal_to_encoded_data(oc_cred_data_t cd,
                                           oc_sec_encoded_data_t sed);

/** Check if the tag of the credential is equal to given value */
bool oc_cred_has_tag(const oc_sec_cred_t *cred, oc_string_view_t tag)
  OC_NONNULL();

/** Check if the input data is duplicate of the credential data */
bool oc_cred_is_duplicate(const oc_sec_cred_t *cred, oc_sec_credtype_t credtype,
                          oc_uuid_t subject, oc_string_view_t tag,
                          oc_sec_encoded_data_t privatedata,
                          oc_sec_encoded_data_t publicdata,
                          oc_sec_credusage_t credusage) OC_NONNULL();

/** @brief Callback invoked for each cred of the device
 *
 * @param cred current credential (cannot be NULL)
 * @param user_data user data passed to oc_cred_iterate
 * @return true to continue iteration
 * @return false to stop iteration
 */
typedef bool (*oc_cred_iterate_fn_t)(const oc_sec_cred_t *cred, void *user_data)
  OC_NONNULL(1);

/**
 * @brief Iterate resources of given device
 *
 * @param creds credentials to iterate (must be oc_list_t of oc_sec_cred_t *)
 * @param iterate iterating function (cannot be NULL)
 * @param iterate_data user data passed from the caller
 */
void oc_cred_iterate(const oc_list_t creds, oc_cred_iterate_fn_t iterate,
                     void *iterate_data) OC_NONNULL(2);

/** Set subject UUID based on the input string and credential usage */
bool oc_sec_cred_set_subject(const char *subjectuuid,
                             oc_sec_credusage_t credusage, oc_uuid_t *subject)
  OC_NONNULL(3);

/** Set private data on the credential */
bool oc_cred_set_privatedata(oc_sec_cred_t *cred, const uint8_t *data,
                             size_t data_size, oc_sec_encoding_t encoding)
  OC_NONNULL();

#ifdef OC_PKI

/** @brief Convert credusage to oc_string_view_t */
oc_string_view_t oc_cred_credusage_to_string(oc_sec_credusage_t credusage);

/**
 * @brief Parse cred usage from string
 *
 * @param str string (cannot be NULL)
 * @param str_len length of \p str
 * @return oc_sec_credusage_t parsed usage
 */
oc_sec_credusage_t oc_cred_usage_from_string(const char *str, size_t str_len)
  OC_NONNULL();

/**
 * @brief Serialize matched certificates credential in PEM format to buffer
 *
 * @param creds credentials to iterate (must be oc_list_t of oc_sec_cred_t *)
 * @param filter credential filtering function (if NULL all credentials will be
 * used)
 * @param filter_data user data passed to \p filter
 * @param buffer buffer to store the output (if NULL the function will only
 * calculate size)
 * @param buffer_size size of the output buffer
 *
 * @return -1 on error
 * @return >= 0 number of written bytes (excluding the null-terminator)
 */
long oc_cred_serialize(const oc_list_t creds, oc_sec_cred_filter_t filter,
                       void *filter_data, char *buffer, size_t buffer_size)
  OC_NONNULL(1);

#endif /* OC_PKI */

#ifdef __cplusplus
}
#endif

#endif /* OC_CRED_INTERNAL_H */
