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

#ifndef OC_ENDPOINT_H
#define OC_ENDPOINT_H

#include "oc_helpers.h"
#include "port/oc_connectivity.h"

void oc_init_endpoint_list(void);
int oc_add_endpoint_to_list(oc_endpoint_t *endpoint);
oc_endpoint_t *oc_get_endpoint_list(void);
void oc_free_endpoint_list(void);
oc_endpoint_t *oc_new_endpoint(void);
void oc_free_endpoint(oc_endpoint_t *endpoint);
int oc_endpoint_to_string(oc_endpoint_t *endpoint, oc_string_t *endpoint_str);
int oc_string_to_endpoint(oc_string_t *endpoint_str, oc_endpoint_t *endpoint,
                          oc_string_t *uri);
int oc_ipv6_endpoint_is_link_local(oc_endpoint_t *endpoint);
int oc_endpoint_compare(oc_endpoint_t *ep1, oc_endpoint_t *ep2);
int oc_endpoint_compare_address(oc_endpoint_t *ep1, oc_endpoint_t *ep2);

#endif /* OC_ENDPOINT_H */
