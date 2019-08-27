/*
// Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef OC_ACSR_H
#define OC_ACSR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  bool owned;
} oc_sec_acsr_t;

void oc_sec_acsr_init(void);
void oc_sec_acsr_free(void);
bool oc_sec_decode_acsr(oc_rep_t *rep, bool from_storage, size_t device);
bool oc_sec_encode_acsr(size_t device);
oc_sec_acsr_t *oc_sec_get_acsr(size_t device);
void oc_sec_acsr_default(size_t device);
void get_acsr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);
void post_acsr(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_ACSR_H */
