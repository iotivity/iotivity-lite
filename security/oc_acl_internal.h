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

#ifndef OC_ACL_H
#define OC_ACL_H

#include "oc_acl.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void oc_sec_acl_init(void);
void oc_sec_acl_free(void);
oc_sec_acl_t *oc_sec_get_acl(size_t device);
void oc_sec_acl_default(size_t device);
bool oc_sec_encode_acl(size_t device, oc_interface_mask_t iface_mask,
                       bool to_storage);
bool oc_sec_decode_acl(oc_rep_t *rep, bool from_storage, size_t device);
void oc_sec_acl_init(void);
void post_acl(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *data);
void get_acl(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);
void delete_acl(oc_request_t *request, oc_interface_mask_t iface_mask,
                void *data);
bool oc_sec_check_acl(oc_method_t method, oc_resource_t *resource,
                      oc_endpoint_t *endpoint);
void oc_sec_acl_add_bootsrap_acl(size_t device);
bool oc_sec_acl_add_created_resource_ace(const char *href,
                                         oc_endpoint_t *client, size_t device,
                                         bool collection);

#ifdef __cplusplus
}
#endif

#endif /* OC_ACL_H */
