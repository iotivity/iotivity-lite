/*
// Copyright (c) 2016-2020 Intel Corporation
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
 * @brief read credential usaga
 *
 * @param credusage credential usage as type
 * @return const char* credential usage as string
 */
OC_API
const char *oc_cred_read_credusage(oc_sec_credusage_t credusage);

/**
 * @brief read credential encoding
 *
 * @param encoding credential encoding as type
 * @return const char* credential encoding as string
 */
OC_API
const char *oc_cred_read_encoding(oc_sec_encoding_t encoding);

/**
 * @brief parse credential string to type
 *
 * @param credusage_string credential usage as string
 * @return oc_sec_credusage_t credential usage type
 */
OC_API
oc_sec_credusage_t oc_cred_parse_credusage(oc_string_t *credusage_string);

/**
 * @brief parse credential encoding string to type
 *
 * @param encoding_string credential encoding string
 * @return oc_sec_encoding_t credential encoding type
 */
OC_API
oc_sec_encoding_t oc_cred_parse_encoding(oc_string_t *encoding_string);

/**
 * @brief credential type to string
 *
 * @param credtype the credential type as type
 * @return const char* credential type as string
 */
OC_API
const char *oc_cred_credtype_string(oc_sec_credtype_t credtype);

/**
 * @brief Callback invoked with a created / updated credential
 *
 * @param cred New or updated credential
 * @param user_data User data passed from the caller
 */
typedef void (*oc_sec_on_apply_cred_cb_t)(oc_sec_cred_t *cred, void *user_data);

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
int oc_sec_apply_cred(oc_rep_t *rep, oc_resource_t *resource,
                      oc_endpoint_t *endpoint,
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
