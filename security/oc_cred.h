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

#ifndef OC_CRED_H
#define OC_CRED_H

#include "oc_ri.h"
#include "oc_uuid.h"
#include <stdint.h>

typedef struct oc_sec_cred_s
{
  struct oc_sec_cred_s *next;
  int credid;
  int credtype;
  oc_uuid_t subjectuuid;
  struct
  {
    oc_string_t role;
    oc_string_t authority;
  } role;
  uint8_t key[16]; // Supports only 128-bit keys
} oc_sec_cred_t;

typedef struct
{
  OC_LIST_STRUCT(creds);
  oc_uuid_t rowneruuid;
} oc_sec_creds_t;

void oc_sec_cred_default(int device);
void oc_sec_cred_init(void);
void oc_sec_encode_cred(bool persist, int device);
bool oc_sec_decode_cred(oc_rep_t *rep, oc_sec_cred_t **owner, bool from_storage,
                        int device);
bool oc_cred_remove_subject(const char *subjectuuid, int device);
oc_sec_cred_t *oc_sec_find_cred(oc_uuid_t *subjectuuid, int device);
oc_sec_creds_t *oc_sec_get_creds(int device);
oc_sec_cred_t *oc_sec_get_cred(oc_uuid_t *subjectuuid, int device);
void put_cred(oc_request_t *request, oc_interface_mask_t interface, void *data);
void post_cred(oc_request_t *request, oc_interface_mask_t interface,
               void *data);
void get_cred(oc_request_t *request, oc_interface_mask_t interface, void *data);
void delete_cred(oc_request_t *request, oc_interface_mask_t interface,
                 void *data);

#endif /* OC_CRED_H */
