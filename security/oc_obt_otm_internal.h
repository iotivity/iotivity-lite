/*
// Copyright (c) 2017-2019 Intel Corporation
// Copyright 2019 Samsung Electronics All Rights Reserved
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

#ifdef __cplusplus
extern "C"
{
#endif

void oc_obt_otm_get_doxm_handler(oc_client_response_t *data);

void oc_obt_otm_post_pstat_om_handler(oc_client_response_t *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_OBT_OTM_INTERNAL_H */
