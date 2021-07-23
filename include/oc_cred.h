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

#include "oc_ri.h"
#include "oc_uuid.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum oc_sec_credtype_t {
  OC_CREDTYPE_NULL = 0,
  OC_CREDTYPE_PSK = 1,
  OC_CREDTYPE_CERT = 8,
  OC_CREDTYPE_OSCORE = 64,
  OC_CREDTYPE_OSCORE_MCAST_CLIENT = 128,
  OC_CREDTYPE_OSCORE_MCAST_SERVER = 256
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
#ifdef OC_OSCORE
  void *oscore_ctx;
#endif /* OC_OSCORE */
  int credid;
  oc_sec_credtype_t credtype;
  oc_uuid_t subjectuuid;
  bool owner_cred;
} oc_sec_cred_t;

typedef struct oc_sec_creds_t
{
  OC_LIST_STRUCT(creds);
  oc_uuid_t rowneruuid;
} oc_sec_creds_t;

const char *oc_cred_read_credusage(oc_sec_credusage_t credusage);
const char *oc_cred_read_encoding(oc_sec_encoding_t encoding);
oc_sec_credusage_t oc_cred_parse_credusage(oc_string_t *credusage_string);
oc_sec_encoding_t oc_cred_parse_encoding(oc_string_t *encoding_string);
const char *oc_cred_credtype_string(oc_sec_credtype_t credtype);

#ifdef __cplusplus
}
#endif

#endif /* OC_CRED_COMMON_H */
