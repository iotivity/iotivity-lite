/*
// Copyright (c) 2018-2019 Intel Corporation
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

#ifndef OC_SP_H
#define OC_SP_H

#include "oc_ri.h"
#include "oc_pki.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  oc_sp_types_t supported_profiles;
  oc_sp_types_t current_profile;
  int credid;
} oc_sec_sp_t;

void oc_sec_sp_init(void);
void oc_sec_sp_free(void);
bool oc_sec_decode_sp(oc_rep_t *rep, size_t device);
void oc_sec_encode_sp(size_t device, oc_interface_mask_t iface_mask,
                      bool to_storage);
oc_sec_sp_t *oc_sec_get_sp(size_t device);
void oc_sec_sp_default(size_t device);
void get_sp(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);
void post_sp(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_SP_H */
