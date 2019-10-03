/*
// Copyright (c) 2019 Intel Corporation
// Copyright 2018 Samsung Electronics All Rights Reserved
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

#ifndef OC_OBT_OTM_INTERNAL_H
#define OC_OBT_OTM_INTERNAL_H

#include "oc_api.h"
#include "security/oc_obt_internal.h"

#ifdef __cplusplus
extern "C"
{
#endif

void oc_obt_otm_close_dtls(oc_client_response_t *data);

void oc_obt_otm_set_dos_to_rfnop(oc_client_response_t *data);

void oc_obt_otm_post_acl2(oc_client_response_t *data);

void oc_obt_otm_delete_acl2(oc_client_response_t *data);

void oc_obt_otm_set_dos_to_rfpro(oc_client_response_t *data);

void oc_obt_otm_set_doxm_owned(oc_client_response_t *data);

void oc_obt_otm_set_cred_rowneruuid(oc_client_response_t *data);

void oc_obt_otm_set_pstat_rowneruuid(oc_client_response_t *data);

void oc_obt_otm_set_acl_rowneruuid(oc_client_response_t *data);

void oc_obt_otm_set_doxm_rowneruuid(oc_client_response_t *data);

void oc_obt_otm_set_doxm_deviceuuid(oc_client_response_t *data);

void oc_obt_otm_set_doxm_devowneruuid(oc_client_response_t *data);

void oc_obt_otm_set_pstat_om(oc_client_response_t *data);

void oc_obt_otm_set_doxm_oxmsel(oc_client_response_t *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_OBT_OTM_INTERNAL_H */
