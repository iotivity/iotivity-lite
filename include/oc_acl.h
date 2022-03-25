/*
// Copyright (c) 2016-2019 Intel Corporation
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
#ifndef OC_ACL_COMMON_H
#define OC_ACL_COMMON_H

#include "oc_export.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "util/oc_list.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief security access control list
 *
 */
typedef struct oc_sec_acl_s
{
  OC_LIST_STRUCT(subjects); ///< list of subjects
  oc_uuid_t rowneruuid;     ///< rowner uuid
} oc_sec_acl_t;

/**
 * @brief Access control connection type
 *
 */
typedef enum {
  OC_CONN_AUTH_CRYPT = 0, ///< auth-crypt, authenticated and encrypted
  OC_CONN_ANON_CLEAR      ///< anon-clear, not authenticated and not encrypted
} oc_ace_connection_type_t;

/**
 * @brief ACE wild cards
 *
 */
typedef enum {
  OC_ACE_NO_WC = 0,             ///< no wild card
  OC_ACE_WC_ALL = 0x111,        ///< all
  OC_ACE_WC_ALL_SECURED = 0x01, ///< Secured
  OC_ACE_WC_ALL_PUBLIC = 0x10,  ///< public
} oc_ace_wildcard_t;

/**
 * @brief ACE permissions, as bitmap
 *
 */
typedef enum {
  OC_PERM_NONE = 0,          ///< no permissions
  OC_PERM_CREATE = (1 << 0), ///< Create permission is granted
  OC_PERM_RETRIEVE =
    (1 << 1),                ///< Read, observe, discover permission is granted
  OC_PERM_UPDATE = (1 << 2), ///< Write, update permission is granted
  OC_PERM_DELETE = (1 << 3), ///< Delete permission is granted
  OC_PERM_NOTIFY = (1 << 4)  ///< Notify permission is granted
} oc_ace_permissions_t;

/**
 * @brief ACE subject
 *
 */
typedef enum {
  OC_SUBJECT_UUID = 0, ///< DI of the device
  OC_SUBJECT_ROLE,     ///< Security role specified as an Authority and Rolename
  OC_SUBJECT_CONN      ///< connection type, ACE to be matched based on the
                       ///< connection or message type
} oc_ace_subject_type_t;

/**
 * @brief ACE resource information
 *
 */
typedef struct oc_ace_res_t
{
  struct oc_ace_res_t *next;      ///< pointer to next entry
  oc_string_t href;               ///< href
  oc_interface_mask_t interfaces; ///< applicable interfaces (as bit mask)
  oc_string_array_t types;        ///< resource types (rt)
  oc_ace_wildcard_t wildcard;     ///< wildcard info
} oc_ace_res_t;

/**
 * @brief ACE subject information
 *
 */
typedef union oc_ace_subject_t {
  oc_uuid_t uuid; ///< DI
  struct
  {
    oc_string_t role;      ///< role
    oc_string_t authority; ///< authority
  } role;
  oc_ace_connection_type_t conn; ///< ACE type
} oc_ace_subject_t;

/**
 * @brief Security ACE information
 *
 */
typedef struct oc_sec_ace_t
{
  struct oc_sec_ace_t *next;          ///< pointer to next entry
  OC_LIST_STRUCT(resources);          ///< list of resources
  oc_ace_subject_type_t subject_type; ///< subject type
  oc_ace_subject_t subject;           ///< subject
  int aceid;                          ///< ACE identifier
  oc_ace_permissions_t permission;    ///< permissions
} oc_sec_ace_t;

/**
 * @brief Get access control list of a device
 *
 * @param device Index of the device
 * @return oc_sec_creds_t* Access control list
 */
OC_API
oc_sec_acl_t *oc_sec_get_acl(size_t device);

/**
 * @brief Add initial access control list for core resources of a device
 *
 * @param device Index of the device
 */
OC_API
void oc_sec_acl_add_bootstrap_acl(size_t device);

/**
 * @brief Callback invoked with a created / updated access control entry
 *
 * @param rowneruuid Uuid of the resource owner
 * @param ace New or updated access control entry
 * @param user_data User data passed from the caller
 */
typedef void (*oc_sec_on_apply_acl_cb_t)(oc_uuid_t rowneruuid,
                                         oc_sec_ace_t *ace, void *user_data);

/**
 * @brief Parse payload and add/update access control list
 *
 * @param rep Payload to parse
 * @param device Index of the device
 * @param on_apply_ace_cb Callback invoked when a new access control entry is
 * added or updated
 * @param on_apply_ace_data User data passed to the on_apply_ace_cb function
 * @return int -1 On failure
 * @return int 0 Payload was successfully parsed
 */
OC_API
int oc_sec_apply_acl(oc_rep_t *rep, size_t device,
                     oc_sec_on_apply_acl_cb_t on_apply_ace_cb,
                     void *on_apply_ace_data);

#ifdef __cplusplus
}
#endif

#endif /* OC_ACL_COMMON_H */
