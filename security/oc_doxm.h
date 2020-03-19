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

#ifndef OC_DOXM_H
#define OC_DOXM_H

#include "oc_uuid.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#include "oc_ri.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
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

void oc_sec_doxm_init(size_t device);
void oc_sec_doxm_free(void);
bool oc_sec_decode_doxm(oc_rep_t *rep, bool from_storage, size_t device);
void oc_sec_encode_doxm(size_t device, bool to_storage);
oc_sec_doxm_t *oc_sec_get_doxm(size_t device);
void oc_sec_doxm_default(size_t device);
void get_doxm(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *data);
void post_doxm(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data);

/**
 * Callback invoked when the "owned" property of the doxm is changed
 *
 * @param doxm the doxm that the owned property just changed
 * @param device index of the logical device the doxm belongs to
 * @param user_data context pointer
 */
typedef void (*oc_sec_doxm_owned_cb_t)(const oc_sec_doxm_t *doxm,
                                       size_t device_index, void *user_data);
/**
 * Add callback that is invoked when the doxm "owned" property is changed
 *
 * @param cb callback funtion that will be invoked
 * @param user_data context pointer passed to the oc_sec_doxm_owned_cb_t
 * callback the pointer must remain valid till callback is removed.
 */
void oc_sec_doxm_add_owned_changed_cb(oc_sec_doxm_owned_cb_t cb,
                                      void *user_data);
void oc_sec_doxm_remove_owned_changed_cb(oc_sec_doxm_owned_cb_t cb,
                                         void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* OC_DOXM_H */
