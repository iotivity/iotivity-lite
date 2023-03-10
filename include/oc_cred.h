/****************************************************************************
 *
 * Copyright (c) 2016-2020 Intel Corporation
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
  @file
*/
#ifndef OC_CRED_COMMON_H
#define OC_CRED_COMMON_H

#include "oc_export.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "util/oc_list.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief credential type information
 *
 */
typedef enum oc_sec_credtype_t {
  OC_CREDTYPE_NULL = 0, ///< no credential
  OC_CREDTYPE_PSK = 1,  ///< PSK (personal)
  OC_CREDTYPE_CERT = 8,
  OC_CREDTYPE_OSCORE = 64,
  OC_CREDTYPE_OSCORE_MCAST_CLIENT = 128,
  OC_CREDTYPE_OSCORE_MCAST_SERVER = 256
} oc_sec_credtype_t;

/**
 * @brief credential usage
 *
 */
typedef enum oc_sec_credusage_t {
  OC_CREDUSAGE_NULL = 0,               ///< no usage
  OC_CREDUSAGE_TRUSTCA = 1 << 1,       ///< trust anchor oic.sec.cred.trustca
  OC_CREDUSAGE_IDENTITY_CERT = 1 << 2, ///< Certificate oic.sec.cred.cert
  OC_CREDUSAGE_ROLE_CERT = 1 << 3, ///< Role Certificate oic.sec.cred.rolecert
  OC_CREDUSAGE_MFG_TRUSTCA =
    1 << 4, ///< Manufacturer Trust CA oic.sec.cred.mfgtrustca
  OC_CREDUSAGE_MFG_CERT = 1 << 5 ///< Manufacturer CA oic.sec.cred.mfgcert
} oc_sec_credusage_t;

/**
 * @brief Security encoding information
 *
 */
typedef enum oc_sec_encoding_t {
  OC_ENCODING_UNSUPPORTED = 0, ///< not supported
  OC_ENCODING_BASE64,          ///< oic.sec.encoding.base64
  OC_ENCODING_RAW,             ///< oic.sec.encoding.raw
  OC_ENCODING_PEM,             ///< oic.sec.encoding.pem
  OC_ENCODING_HANDLE ///< oic.sec.encoding.handle – Data is contained in a
                     ///< storage sub-system referenced using a handle
} oc_sec_encoding_t;

/**
 * @brief credential data info
 *
 */
typedef struct oc_cred_data_t
{
  oc_string_t data;           ///< the credential data
  oc_sec_encoding_t encoding; ///< the encoding of the credential data
} oc_cred_data_t;

/**
 * @brief security credential information
 *
 */
typedef struct oc_sec_cred_t
{
  struct oc_sec_cred_t *next; ///< pointer to the next credential
  struct
  {
    oc_string_t role;      ///< role
    oc_string_t authority; ///< authority
  } role;
  oc_cred_data_t privatedata; ///< private data
#ifdef OC_PKI
  oc_cred_data_t publicdata;    ///< public data
  oc_sec_credusage_t credusage; ///< credential usage
  struct oc_sec_cred_t *chain;  ///< chain of credentials
  struct oc_sec_cred_t *child;  ///< credential child
  void *ctx;                    ///< security context
#endif                          /* OC_PKI */
#ifdef OC_OSCORE
  void *oscore_ctx;           ///< oscore security contex
#endif                        /* OC_OSCORE */
  int credid;                 ///< credential id
  oc_sec_credtype_t credtype; ///< credential type
  oc_uuid_t subjectuuid;      ///< subject uuid
  bool owner_cred;            ///< owner
  oc_string_t tag;            ///< custom user tag
} oc_sec_cred_t;

/**
 * @brief credential and rowner information
 *
 */
typedef struct oc_sec_creds_t
{
  OC_LIST_STRUCT(creds); ///< list of credentials
  oc_uuid_t rowneruuid;  ///< row owner uuid
} oc_sec_creds_t;

/**
 * @brief Security credential filtering function.
 *
 * @param cred security credential to check
 * @param user_data user data passed from the caller
 * @return true if security credential matches the filter
 * @return false otherwise
 */
typedef bool (*oc_sec_cred_filter_t)(const oc_sec_cred_t *cred,
                                     void *user_data);

#ifdef OC_PKI

/**
 * @brief Selected certificate data used for verification.
 */
typedef struct oc_sec_certs_data_t
{
  uint64_t valid_from; ///<  UNIX timestamp (UTC +0000) from which the
                       ///<  certificate is valid
  uint64_t valid_to;   ///<  UNIX timestamp (UTC +0000) to which the
                       ///<  certificate is valid
} oc_sec_certs_data_t;

/**
 * @brief Callback function to verify a single certificate. Return true if
 * certificate is valid, return false otherwise.
 */
typedef bool (*oc_verify_sec_certs_data_fn_t)(const oc_sec_certs_data_t *data,
                                              void *user_data);

/**
 * @brief Verify the certificate chain associated with the credential.
 *
 * @param cred credential associated with the certificate chain (cannot be NULL)
 * @param verify_cert function used to verify a single certificate (cannot be
 * NULL)
 * @param user_data user data from the caller passed to the verify_cert callback
 * @return 0 all certificates in the chain are valid
 * @return 1 at least one certificate in the chain is not valid
 * @return -1 on error
 */
OC_API
int oc_cred_verify_certificate_chain(const oc_sec_cred_t *cred,
                                     oc_verify_sec_certs_data_fn_t verify_cert,
                                     void *user_data);

/**
 * @brief read credential usage
 *
 * @param credusage credential usage as type
 * @return const char* credential usage as string
 */
OC_API
const char *oc_cred_read_credusage(oc_sec_credusage_t credusage);

/**
 * @brief parse credential string to type
 *
 * @param credusage_string credential usage as string
 * @return oc_sec_credusage_t credential usage type
 */
OC_API
oc_sec_credusage_t oc_cred_parse_credusage(const oc_string_t *credusage_string);

#endif /* OC_PKI */

/**
 * @brief read credential encoding
 *
 * @param encoding credential encoding as type
 * @return const char* credential encoding as string
 */
OC_API
const char *oc_cred_read_encoding(oc_sec_encoding_t encoding);

/**
 * @brief parse credential encoding string to type
 *
 * @param encoding_string credential encoding string
 * @return oc_sec_encoding_t credential encoding type
 */
OC_API
oc_sec_encoding_t oc_cred_parse_encoding(const oc_string_t *encoding_string);

/**
 * @brief credential type to string
 *
 * @param credtype the credential type as type
 * @return const char* credential type as string
 */
OC_API
const char *oc_cred_credtype_string(oc_sec_credtype_t credtype);

typedef struct oc_sec_on_apply_cred_data_t
{
  oc_sec_cred_t *cred; ///< new or updated credential
  const oc_sec_cred_t
    *replaced;  ///< in case of modification of an existing credential this is
                ///< the original credential that has been replaced; the
                ///< credential will be deallocated after the call of
                ///< oc_sec_on_apply_cred_cb_t from oc_sec_apply_cred
  bool created; ///< true if a new credential was created; false if credential
                ///< replaced an already existing credential or it was a
                ///< duplicate and the operation was skipped
} oc_sec_on_apply_cred_data_t;

/**
 * @brief callback invoked with a created / updated credential
 *
 * @param data data with new/updated credential data
 * @param user_data user data passed from the caller
 */
typedef void (*oc_sec_on_apply_cred_cb_t)(oc_sec_on_apply_cred_data_t data,
                                          void *user_data);

/**
 * @brief parse payload and add/update credentials
 *
 * @param rep payload to parse
 * @param resource resource of the credentials
 * @param endpoint endpoint of the credentials owner
 * @param on_apply_cred_cb callback invoked when a new credential is added or
 * updated
 * @param on_apply_cred_data user data passed to the on_apply_cred_cb function
 * @return int -1 on failure
 * @return int 0 payload was successfully parsed
 */
OC_API
int oc_sec_apply_cred(const oc_rep_t *rep, const oc_resource_t *resource,
                      const oc_endpoint_t *endpoint,
                      oc_sec_on_apply_cred_cb_t on_apply_cred_cb,
                      void *on_apply_cred_data);

/**
 * @brief get all credentials of given device
 *
 * @param device index of the device
 * @return oc_sec_creds_t* list of credentials
 */
OC_API
oc_sec_creds_t *oc_sec_get_creds(size_t device);

/**
 * @brief remove credentials matching filter from given device
 *
 * @param device index of the device
 * @param filter filtering function (if NULL all existing credentials match)
 * @param user_data user data passed from the caller
 */
OC_API
void oc_sec_cred_clear(size_t device, oc_sec_cred_filter_t filter,
                       void *user_data);

/**
 * @brief remove credential from given device
 *
 * @param cred credential to remove
 * @param device index of the device
 */
OC_API
void oc_sec_remove_cred(oc_sec_cred_t *cred, size_t device);

/**
 * @brief get credential by credid from given device
 *
 * @param credid credential id
 * @param device index of the device
 * @return oc_sec_cred_t* found credential or NULL
 */
OC_API
oc_sec_cred_t *oc_sec_get_cred_by_credid(int credid, size_t device);

/**
 * @brief remove credential with credid from given device
 *
 * @param credid credential id
 * @param device index of the device
 * @return bool true credential with given id was found and removed
 * @return bool false otherwise
 */
OC_API
bool oc_sec_remove_cred_by_credid(int credid, size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_CRED_COMMON_H */
