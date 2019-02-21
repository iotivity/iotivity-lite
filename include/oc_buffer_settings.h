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
/**
  @file
*/
#ifndef OC_BUFFER_SETTINGS_H
#define OC_BUFFER_SETTINGS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

int oc_set_mtu_size(size_t mtu_size);
long oc_get_mtu_size(void);
void oc_set_max_app_data_size(size_t size);
long oc_get_max_app_data_size(void);
long oc_get_block_size(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_BUFFER_SETTINGS_H */
