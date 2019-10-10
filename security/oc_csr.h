/*
// Copyright (c) 2018-2019 Intel Corporation
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

#ifndef OC_CSR_H
#define OC_CSR_H

#include "oc_ri.h"
#include "oc_uuid.h"
#include <stdint.h>

#include "oc_cred_internal.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C"
{
#endif

void get_csr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_CSR_H */
