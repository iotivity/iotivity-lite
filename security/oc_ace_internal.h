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

/** Convert wildcard to string representation */
oc_string_view_t oc_ace_wildcard_to_string(oc_ace_wildcard_t wc);

/** Create a new ACE of given subject type */
oc_sec_ace_t *oc_sec_new_ace(oc_ace_subject_type_t type,
                             const oc_ace_subject_t *subject, int aceid,
                             uint16_t permission, oc_string_view_t tag)
  OC_NONNULL();

/** Free an ACE */
void oc_sec_free_ace(oc_sec_ace_t *ace) OC_NONNULL();

/** Find ACE in a list */
oc_sec_ace_t *oc_sec_ace_find_subject(oc_sec_ace_t *ace,
                                      oc_ace_subject_type_t type,
                                      const oc_ace_subject_t *subject,
                                      int aceid, uint16_t permission,
                                      oc_string_view_t tag, bool match_tag)
  OC_NONNULL(3);

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
                       bool to_storage);

#ifdef __cplusplus
}
#endif

#endif /* OC_ACE_INTERNAL_H */
