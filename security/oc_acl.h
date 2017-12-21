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

#ifndef OC_ACL_H
#define OC_ACL_H

#include "oc_ri.h"
#include "oc_uuid.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include <stdbool.h>

typedef enum {
  OC_PERM_NONE = 0,
  OC_PERM_CREATE = (1 << 0),
  OC_PERM_RETRIEVE = (1 << 1),
  OC_PERM_UPDATE = (1 << 2),
  OC_PERM_DELETE = (1 << 3),
  OC_PERM_NOTIFY = (1 << 4)
} oc_ace_permissions_t;

typedef enum {
  OC_ACE_NO_WC = -1,
  OC_ACE_WC_ALL = 0x11,
  OC_ACE_WC_ALL_DISCOVERABLE = 0x01,
  OC_ACE_WC_ALL_NON_DISCOVERABLE = 0x10,
} oc_ace_wildcard_t;

typedef enum {
  OC_SUBJECT_UUID = 0,
  OC_SUBJECT_ROLE,
  OC_SUBJECT_CONN
} oc_ace_subject_type_t;

typedef enum {
  OC_CONN_AUTH_CRYPT = 0,
  OC_CONN_ANON_CLEAR
} oc_ace_connection_type_t;

typedef struct oc_ace_res_s
{
  struct oc_ace_res_s *next;
  oc_string_t href;
  oc_interface_mask_t interfaces;
  oc_string_array_t types;
  oc_ace_wildcard_t wildcard;
} oc_ace_res_t;

typedef union
{
  oc_uuid_t uuid;
  struct
  {
    oc_string_t role;
    oc_string_t authority;
  } role;
  oc_ace_connection_type_t conn;
} oc_ace_subject_t;

typedef struct oc_sec_ace_s
{
  struct oc_sec_ace_s *next;
  OC_LIST_STRUCT(resources);
  oc_ace_subject_type_t subject_type;
  oc_ace_subject_t subject;
  int aceid;
  oc_ace_permissions_t permission;
  // TODO: Add "validity" for ACE. It is currently not a mandatory property
} oc_sec_ace_t;

typedef struct
{
  OC_LIST_STRUCT(subjects);
  oc_uuid_t rowneruuid;
} oc_sec_acl_t;

void oc_sec_acl_init(void);
oc_sec_acl_t *oc_sec_get_acl(int device);
void oc_sec_acl_default(int device);
bool oc_sec_encode_acl(int device);
bool oc_sec_decode_acl(oc_rep_t *rep, bool from_storage, int device);
void oc_sec_acl_init(void);
void post_acl(oc_request_t *request, oc_interface_mask_t interface, void *data);
void get_acl(oc_request_t *request, oc_interface_mask_t interface, void *data);
void delete_acl(oc_request_t *request, oc_interface_mask_t interface,
                void *data);
bool oc_sec_check_acl(oc_method_t method, oc_resource_t *resource,
                      oc_endpoint_t *endpoint);
void oc_sec_set_post_otm_acl(int device);

#endif /* OC_ACL_H */
