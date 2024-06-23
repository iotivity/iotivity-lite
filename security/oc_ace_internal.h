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

#ifndef OC_ACE_INTERNAL_H
#define OC_ACE_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_acl.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_ACE_WC_ALL_STR "*"
#define OC_ACE_WC_ALL_SECURED_STR "+"
#define OC_ACE_WC_ALL_PUBLIC_STR "-"

#define OC_CONN_AUTH_CRYPT_STR "auth-crypt"
#define OC_CONN_ANON_CLEAR_STR "anon-clear"

#define OC_ACE_PROP_SUBJECT "subject"
#define OC_ACE_PROP_SUBJECT_UUID "uuid"
#define OC_ACE_PROP_SUBJECT_ROLE "role"
#define OC_ACE_PROP_SUBJECT_AUTHORITY "authority"
#define OC_ACE_PROP_SUBJECT_CONNTYPE "conntype"
#define OC_ACE_PROP_PERMISSION "permission"
#define OC_ACE_PROP_ACEID "aceid"
#define OC_ACE_PROP_TAG "tag"
#define OC_ACE_PROP_RESOURCES "resources"
#define OC_ACE_PROP_RESOURCE_HREF "href"
#define OC_ACE_PROP_RESOURCE_WILDCARD "wc"

/** Convert wildcard to string representation */
oc_string_view_t oc_ace_wildcard_to_string(oc_ace_wildcard_t wc);

/** Convert string to wildcard */
int oc_ace_wildcard_from_string(oc_string_view_t str);

/** Convert connection type to string */
oc_string_view_t oc_ace_connection_type_to_string(
  oc_ace_connection_type_t conn);

/** Convert string to connection type */
int oc_ace_connection_type_from_string(oc_string_view_t str);

typedef struct
{
  oc_string_view_t role;
  oc_string_view_t authority;
} oc_ace_subject_role_view_t;

typedef union {
  oc_uuid_t uuid;
  oc_ace_subject_role_view_t role;
  oc_ace_connection_type_t conn;
} oc_ace_subject_view_t;

/** Create a new ACE of given subject type */
oc_sec_ace_t *oc_sec_new_ace(oc_ace_subject_type_t type,
                             oc_ace_subject_view_t subject, int aceid,
                             uint16_t permission, oc_string_view_t tag)
  OC_NONNULL();

/** Free an ACE */
void oc_sec_free_ace(oc_sec_ace_t *ace) OC_NONNULL();

/** Check if ACE has mathing tag */
bool oc_ace_has_matching_tag(const oc_sec_ace_t *ace, oc_string_view_t tag)
  OC_NONNULL();

/** Check if ACE has matching subject */
bool oc_ace_has_matching_subject(const oc_sec_ace_t *ace,
                                 oc_ace_subject_type_t type,
                                 oc_ace_subject_view_t subject) OC_NONNULL();

/** Find ACE in a list */
oc_sec_ace_t *oc_sec_ace_find_subject(oc_sec_ace_t *ace,
                                      oc_ace_subject_type_t type,
                                      oc_ace_subject_view_t subject, int aceid,
                                      uint16_t permission, oc_string_view_t tag,
                                      bool match_tag);

typedef struct oc_ace_res_data_t
{
  oc_ace_res_t *res;
  bool created;
} oc_ace_res_data_t;

/** Get an ACE if it exists, otherwise create it */
oc_ace_res_data_t oc_sec_ace_get_or_add_res(oc_sec_ace_t *ace,
                                            oc_string_view_t href,
                                            oc_ace_wildcard_t wildcard,
                                            bool create) OC_NONNULL();

/** Find an ACE match by href or a wildcard */
oc_ace_res_t *oc_sec_ace_find_resource(oc_ace_res_t *start,
                                       const oc_sec_ace_t *ace,
                                       oc_string_view_t href,
                                       uint16_t wildcard);

/** Encode an ACE to encoder  */
void oc_sec_encode_ace(CborEncoder *encoder, const oc_sec_ace_t *sub,
                       bool to_storage) OC_NONNULL();

typedef struct
{
  int aceid;
  uint16_t permission;
  oc_ace_subject_view_t subject;
  oc_ace_subject_type_t subject_type;
  const oc_rep_t *resources;
  const oc_string_t *tag;
} oc_sec_ace_decode_t;

/** Decode representation to struct  */
bool oc_sec_decode_ace(const oc_rep_t *rep, oc_sec_ace_decode_t *acedecode)
  OC_NONNULL(2);

typedef struct
{
  oc_ace_wildcard_t wildcard;
  const oc_string_t *href;
#if 0
#ifdef OC_SERVER
  oc_resource_properties_t wc_r;
#endif /* OC_SERVER */
#endif
} oc_sec_ace_res_decode_t;

typedef void (*oc_sec_on_decode_ace_resource_fn_t)(
  const oc_sec_ace_res_decode_t *aceresdecode, void *user_data) OC_NONNULL(1);

/** Decode resources object array and invoke decode callback on each resource */
bool oc_sec_decode_ace_resources(const oc_rep_t *rep,
                                 oc_sec_on_decode_ace_resource_fn_t on_decode,
                                 void *decode_fn_data) OC_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* OC_ACE_INTERNAL_H */
