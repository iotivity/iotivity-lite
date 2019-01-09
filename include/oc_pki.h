/*
// Copyright (c) 2018 Intel Corporation
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

#ifndef OC_PKI_H
#define OC_PKI_H

#include "security/oc_sp.h"

#ifdef __cplusplus
extern "C" {
#endif

int oc_pki_add_mfg_cert(size_t device, const unsigned char *cert,
                        size_t cert_size, const unsigned char *key,
                        size_t key_size);

int oc_pki_add_mfg_intermediate_cert(size_t device, int credid,
                                     const unsigned char *cert,
                                     size_t cert_size);

int oc_pki_add_mfg_trust_anchor(size_t device, const unsigned char *cert,
                                size_t cert_size);

int oc_pki_add_trust_anchor(size_t device, const unsigned char *cert,
                            size_t cert_size);

void oc_pki_set_security_profile(size_t device,
                                 oc_sp_types_t supported_profiles,
                                 oc_sp_types_t current_profile, int mfg_credid);
#ifdef __cplusplus
}
#endif
#endif /* OC_PKI_H */
