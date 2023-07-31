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

#ifndef OC_DOXM_INTERNAL_H
#define OC_DOXM_INTERNAL_H

#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_uuid.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum oc_sec_doxmtype_t {
  OC_OXMTYPE_JW = 0,
  OC_OXMTYPE_RDP = 1,
  OC_OXMTYPE_MFG_CERT = 2
} oc_sec_oxmtype_t;

typedef struct
{
  int oxmsel;
  int oxms[3];
  int num_oxms;
  int sct;
  bool owned;
  oc_uuid_t deviceuuid;
  oc_uuid_t devowneruuid;
  oc_uuid_t rowneruuid;
} oc_sec_doxm_t;

void oc_sec_doxm_init(void);

/*
 * modifiedbyme <2023/7/25> add func proto : void oc_sec_doxm_new_device()
 */
#ifdef OC_HAS_FEATURE_BRIDGE
/**
 * @brief increase existing memory for all doxms for all Devices
 * by the size of `oc_sec_doxm_t`
 */
void oc_sec_doxm_new_device(void);
#endif /* OC_HAS_FEATURE_BRIDGE */

void oc_sec_doxm_free(void);
bool oc_sec_decode_doxm(const oc_rep_t *rep, bool from_storage, bool doc,
                        size_t device);
void oc_sec_encode_doxm(size_t device, oc_interface_mask_t iface_mask,
                        bool to_storage);
oc_sec_doxm_t *oc_sec_get_doxm(size_t device);
void oc_sec_doxm_default(size_t device);
void oc_sec_doxm_set_default(oc_sec_doxm_t *doxm);
void get_doxm(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *data);
void post_doxm(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_DOXM_INTERNAL_H */
