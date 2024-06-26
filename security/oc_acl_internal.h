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

#ifndef OC_ACL_INTERNAL_H
#define OC_ACL_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_acl.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_SEC_ACL_URI "/oic/sec/acl2"
#define OCF_SEC_ACL_RT "oic.r.acl2"
#define OCF_SEC_ACL_STORE_NAME "acl"

#define OC_ACE_WC_ALL_STR "*"
#define OC_ACE_WC_ALL_SECURED_STR "+"
#define OC_ACE_WC_ALL_PUBLIC_STR "-"

void oc_sec_acl_init(void);
void oc_sec_acl_free(void);
void oc_sec_acl_default(size_t device);
bool oc_sec_encode_acl(size_t device, oc_interface_mask_t iface_mask,
                       bool to_storage);
bool oc_sec_decode_acl(const oc_rep_t *rep, bool from_storage, size_t device,
                       oc_sec_on_apply_acl_cb_t on_apply_ace_cb,
                       void *on_apply_ace_data);
bool oc_sec_acl_add_created_resource_ace(const char *href,
                                         const oc_endpoint_t *client,
                                         size_t device, bool collection);
typedef struct
{
  oc_sec_ace_t *ace;
  bool created;
  bool created_resource;
} oc_sec_ace_update_data_t;

bool oc_sec_ace_update_res(oc_ace_subject_type_t type,
                           const oc_ace_subject_t *subject, int aceid,
                           uint16_t permission, const char *tag,
                           const char *href, oc_ace_wildcard_t wildcard,
                           size_t device, oc_sec_ace_update_data_t *data);

oc_sec_ace_t *oc_sec_acl_find_subject(oc_sec_ace_t *start,
                                      oc_ace_subject_type_t type,
                                      const oc_ace_subject_t *subject,
                                      int aceid, uint16_t permission,
                                      const char *tag, bool match_tag,
                                      size_t device);

oc_ace_res_t *oc_sec_ace_find_resource(oc_ace_res_t *start,
                                       const oc_sec_ace_t *ace,
                                       const char *href,
                                       oc_ace_wildcard_t wildcard);

/**
 * @brief Create ACL (/oic/sec/acl2) resource for given device.
 *
 * @param device device index
 */
void oc_sec_acl_create_resource(size_t device);

/** @brief Check if the URI matches the ACL resource URI (with or without the
 * leading slash */
bool oc_sec_is_acl_resource_uri(oc_string_view_t uri);

/** @brief Check if the ACL resource is owned by given UUID */
bool oc_sec_acl_is_owned_by(size_t device, oc_uuid_t uuid);

#ifdef __cplusplus
}
#endif

#endif /* OC_ACL_INTERNAL_H */
