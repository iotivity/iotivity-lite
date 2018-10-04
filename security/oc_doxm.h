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

#ifndef OC_DOXM_H
#define OC_DOXM_H

#include "oc_uuid.h"
#include "oc_security.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  int oxmsel;
  int sct;
  bool owned;
  oc_uuid_t deviceuuid;
  oc_uuid_t devowneruuid;
  oc_uuid_t rowneruuid;
} oc_sec_doxm_t;

void oc_sec_doxm_init(void);
void oc_sec_doxm_free(void);
bool oc_sec_decode_doxm(oc_rep_t *rep, bool from_storage, size_t device);
void oc_sec_encode_doxm(size_t device);
oc_sec_doxm_t *oc_sec_get_doxm(size_t device);
void oc_sec_doxm(size_t device, oc_doxm_method_t oxmsel);
void get_doxm(oc_request_t *request, oc_interface_mask_t interface, void *data);
void post_doxm(oc_request_t *request, oc_interface_mask_t interface,
               void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_DOXM_H */
