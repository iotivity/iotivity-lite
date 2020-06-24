/*
// Copyright (c) 2020, Beijing OPPO telecommunications corp., ltd.
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

#ifndef OC_SDI_H
#define OC_SDI_H

#include "oc_ri.h"
#include "oc_uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  bool priv;
  oc_uuid_t uuid;
  oc_string_t name;
} oc_sec_sdi_t;

void oc_sec_sdi_init(void);
void oc_sec_sdi_free(void);
void oc_sec_sdi_default(size_t device);
bool oc_sec_decode_sdi(oc_rep_t *rep, bool from_storage, size_t device);
void oc_sec_encode_sdi(size_t device, bool to_storage);
oc_sec_sdi_t *oc_sec_get_sdi(size_t device);
void get_sdi(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);
void post_sdi(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_SDI_H */
