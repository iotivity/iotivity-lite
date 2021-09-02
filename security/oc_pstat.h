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

#ifndef OC_PSTAT_H
#define OC_PSTAT_H

#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  OC_DOS_RESET = 0,
  OC_DOS_RFOTM,
  OC_DOS_RFPRO,
  OC_DOS_RFNOP,
  OC_DOS_SRESET
} oc_dostype_t;

typedef enum {
  OC_DPM_SVV = 64,
  OC_DPM_SSV = 128,
  OC_DPM_NSA = 256
} oc_dpmtype_t;

typedef struct
{
  oc_dostype_t s;
  bool p;
  bool isop;
  oc_dpmtype_t cm;
  oc_dpmtype_t tm;
  int om;
  int sm;
  oc_uuid_t rowneruuid;
} oc_sec_pstat_t;

void oc_sec_pstat_init(void);
void oc_sec_pstat_free(void);
bool oc_sec_is_operational(size_t device);
bool oc_sec_decode_pstat(oc_rep_t *rep, bool from_storage, size_t device);
void oc_sec_encode_pstat(size_t device, oc_interface_mask_t iface_mask,
                         bool to_storage);
oc_sec_pstat_t *oc_sec_get_pstat(size_t device);
void oc_sec_pstat_default(size_t device);
void get_pstat(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data);
void post_pstat(oc_request_t *request, oc_interface_mask_t iface_mask,
                void *data);
bool oc_pstat_reset_device(size_t device, bool self_reset);

void oc_sec_pstat_set_current_mode(size_t device, oc_dpmtype_t cm);

#ifdef __cplusplus
}
#endif

#endif /* OC_PSTAT_H */
