/*
// Copyright (c) 2017 Intel Corporation
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

#ifndef OC_CRED_H
#define OC_CRED_H

#include "oc_ri.h"
#include "oc_uuid.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum oc_sec_credtype_t {
  OC_CREDTYPE_NULL = 0,
  OC_CREDTYPE_PSK = 1,
  OC_CREDTYPE_CERT = 8
} oc_sec_credtype_t;

typedef enum oc_sec_credusage_t {
  OC_CREDUSAGE_NULL = 0,
  OC_CREDUSAGE_TRUSTCA = 1 << 1,
  OC_CREDUSAGE_IDENTITY_CERT = 1 << 2,
  OC_CREDUSAGE_ROLE_CERT = 1 << 3,
  OC_CREDUSAGE_MFG_TRUSTCA = 1 << 4,
  OC_CREDUSAGE_MFG_CERT = 1 << 5
} oc_sec_credusage_t;

typedef enum oc_sec_encoding_t {
  OC_ENCODING_UNSUPPORTED = 0,
  OC_ENCODING_BASE64,
  OC_ENCODING_RAW,
  OC_ENCODING_PEM,
  OC_ENCODING_HANDLE
} oc_sec_encoding_t;

typedef struct oc_cred_data_t
{
  oc_string_t data;
  oc_sec_encoding_t encoding;
} oc_cred_data_t;

typedef struct oc_sec_cred_t
{
  struct oc_sec_cred_t *next;
  struct
  {
    oc_string_t role;
    oc_string_t authority;
  } role;
  oc_cred_data_t privatedata;
#ifdef OC_PKI
  oc_cred_data_t publicdata;
  oc_sec_credusage_t credusage;
  struct oc_sec_cred_t *chain;
  struct oc_sec_cred_t *child;
  void *ctx;
#endif /* OC_PKI */
  int credid;
  oc_sec_credtype_t credtype;
  oc_uuid_t subjectuuid;
  bool owner_cred;
} oc_sec_cred_t;

typedef struct
{
  OC_LIST_STRUCT(creds);
  oc_uuid_t rowneruuid;
} oc_sec_creds_t;

struct oc_tls_peer_t;

int oc_sec_add_new_cred(size_t device, bool roles_resource,
                        struct oc_tls_peer_t *client, int credid,
                        oc_sec_credtype_t credtype,
                        oc_sec_credusage_t credusage, const char *subject,
                        oc_sec_encoding_t privatedata_encoding,
                        size_t privatedata_size, const uint8_t *privatedata,
                        oc_sec_encoding_t publicdata_encoding,
                        size_t publicdata_size, const uint8_t *publicdata,
                        const char *role, const char *authority);

void oc_sec_cred_default(size_t device);
void oc_sec_cred_init(void);
void oc_sec_cred_free(void);
void oc_sec_encode_cred(bool persist, size_t device);
bool oc_sec_decode_cred(oc_rep_t *rep, oc_sec_cred_t **owner, bool from_storage,
                        bool roles_resource, struct oc_tls_peer_t *client,
                        size_t device);
bool oc_cred_remove_subject(const char *subjectuuid, size_t device);
void oc_sec_remove_cred(oc_sec_cred_t *cred, size_t device);
oc_sec_cred_t *oc_sec_find_creds_for_subject(oc_uuid_t *subjectuuid,
                                             oc_sec_cred_t *start,
                                             size_t device);
oc_sec_cred_t *oc_sec_find_cred(oc_uuid_t *subjectuuid,
                                oc_sec_credtype_t credtype,
                                oc_sec_credusage_t credusage, size_t device);
oc_sec_cred_t *oc_sec_find_role_cred(const char *role, const char *authority);
oc_sec_creds_t *oc_sec_get_creds(size_t device);
oc_sec_cred_t *oc_sec_get_cred_by_credid(int credid, size_t device);
oc_sec_cred_t *oc_sec_allocate_cred(oc_uuid_t *subjectuuid,
                                    oc_sec_credtype_t credtype,
                                    oc_sec_credusage_t credusage,
                                    size_t device);
void put_cred(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *data);
void post_cred(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data);
void get_cred(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *data);
void delete_cred(oc_request_t *request, oc_interface_mask_t iface_mask,
                 void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_CRED_H */
