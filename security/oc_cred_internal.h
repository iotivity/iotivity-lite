/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

#ifndef OC_CRED_INTERNAL_H
#define OC_CRED_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_cred.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct oc_tls_peer_t;

typedef struct
{
  bool created; ///< true if a new credential was created, false otherwise
  oc_sec_cred_t
    *replaced_cred; ///< the original credential if a newly created
                    ///< credential replaced a previously existing one
} oc_sec_add_new_cred_data_t;

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

typedef struct
{
  const uint8_t *data;
  size_t size;
  oc_sec_encoding_t encoding;
} oc_sec_encoded_data_t;

int oc_sec_add_new_cred(size_t device, bool roles_resource,
                        const struct oc_tls_peer_t *client, int credid,
                        oc_sec_credtype_t credtype,
                        oc_sec_credusage_t credusage, const char *subject,
                        oc_sec_encoded_data_t privatedata,
                        oc_sec_encoded_data_t publicdata, oc_string_view_t role,
                        oc_string_view_t authority, oc_string_view_t tag,
                        oc_sec_add_new_cred_data_t *new_cred_data);

void oc_sec_cred_default(size_t device);
void oc_sec_cred_init(void);
void oc_sec_cred_free(void);
void oc_sec_encode_cred(size_t device, oc_interface_mask_t iface_mask,
                        bool to_storage);
bool oc_sec_decode_cred(const oc_rep_t *rep, oc_sec_cred_t **owner,
                        bool from_storage, bool roles_resource,
                        const struct oc_tls_peer_t *client, size_t device,
                        oc_sec_on_apply_cred_cb_t on_apply_cred_cb,
                        void *on_apply_cred_data);

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

/**
 * @brief Allocate and initialize a new credential and append it to global
 * list of device credentials.
 *
 * @param subjectuuid subject uuid (cannot be NULL)
 * @param credtype credential type
 * @param credusage credential usage (only if OC_PKI defined)
 * @param device index of the device
 * @return oc_sec_cred_t* initialized credential on success
 * @return NULL on error
 */
oc_sec_cred_t *oc_sec_allocate_cred(const oc_uuid_t *subjectuuid,
                                    oc_sec_credtype_t credtype,
                                    oc_sec_credusage_t credusage,
                                    size_t device);

/**
 * @brief Remove and deallocate credential with matching subject uuid from the
 * list of credentials for given device.
 *
 * @param subjectuuid subject uuid (cannot be NULL)
 * @param device index of the device
 * @return true credential was found and removed
 * @return false otherwise
 */
bool oc_cred_remove_subject(const char *subjectuuid, size_t device);

/**
 * @brief Find credential with matching subject uuid from the list of
 * credentials for given device.
 *
 * @param start Starting position of the search (if NULL is used then the search
 * starts from the head of the list)
 * @param subjectuuid subject uuid to match (cannot be NULL)
 * @param device index of the device
 * @return oc_sec_cred_t* matching credential
 * @return NULL if no matching credential was found
 */
oc_sec_cred_t *oc_sec_find_creds_for_subject(oc_sec_cred_t *start,
                                             const oc_uuid_t *subjectuuid,
                                             size_t device);

/**
 * @brief Find credential with matching subject uuid, type and usage from the
 * list of credentials for given device.
 *
 * @param start Starting position of the search (if NULL is used then the search
 * starts from the head of the list)
 * @param subjectuuid subject uuid to match (cannot be NULL)
 * @param credtype credential type to match
 * @param credusage credential usage to match
 * @param device index of the device
 * @return oc_sec_cred_t* matching credential
 * @return NULL if no matching credential was found
 */
oc_sec_cred_t *oc_sec_find_cred(oc_sec_cred_t *start,
                                const oc_uuid_t *subjectuuid,
                                oc_sec_credtype_t credtype,
                                oc_sec_credusage_t credusage, size_t device);

/**
 * @brief Find role credential with matching subject uuid, type and usage from
 * the list of credentials for given device.
 *
 * @param start Starting position of the search (if NULL is used then the search
 * starts from the head of the list)
 * @param role role to match (cannot be NULL)
 * @param authority authority to match (if NULL then the authority values won't
 * be compared)
 * @param tag tag to match (if NULL then the tag values won't be
 * compared)
 * @return oc_sec_cred_t* matching credential
 * @return NULL if no matching credential was found
 */
oc_sec_cred_t *oc_sec_find_role_cred(oc_sec_cred_t *start, const char *role,
                                     const char *authority, const char *tag);

/**
 * @brief Create roles (/oic/sec/cred) resource for given device.
 *
 * @param device device index
 */
void oc_sec_cred_create_resource(size_t device);

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

#endif /* OC_PKI */

#ifdef __cplusplus
}
#endif

#endif /* OC_CRED_INTERNAL_H */
