/*
// Copyright (c) 2019 Intel Corporation
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

#ifndef OC_MAIN_H
#define OC_MAIN_H

#include "oc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_factory_presets_t
{
  oc_factory_presets_cb_t cb;
  void *data;
} oc_factory_presets_t;

oc_factory_presets_t *oc_get_factory_presets_cb(void);

typedef struct oc_random_pin_t
{
  oc_random_pin_cb_t cb;
  void *data;
} oc_random_pin_t;

#ifdef __cplusplus
}
#endif

#endif /* OC_MAIN_H */
