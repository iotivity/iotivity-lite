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

#ifndef OC_PSTAT_H
#define OC_PSTAT_H

#include "oc_ri.h"

typedef enum {
  OC_DOS_RESET = 0,
  OC_DOS_RFOTM,
  OC_DOS_RFPRO,
  OC_DOS_RFNOP,
  OC_DOS_SRESET
} oc_dostype_t;

typedef struct
{
  oc_dostype_t s;
  bool p;
  bool isop;
  int cm;
  int tm;
  int om;
  int sm;
  oc_uuid_t rowneruuid;
} oc_sec_pstat_t;

void oc_sec_pstat_init(void);
bool oc_sec_is_operational(int device);
bool oc_sec_decode_pstat(oc_rep_t *rep, bool from_storage, int device);
void oc_sec_encode_pstat(int device);
oc_sec_pstat_t *oc_sec_get_pstat(int device);
void oc_sec_pstat_default(int device);
void get_pstat(oc_request_t *request, oc_interface_mask_t interface,
               void *data);
void post_pstat(oc_request_t *request, oc_interface_mask_t interface,
                void *data);

#endif /* OC_PSTAT_H */
