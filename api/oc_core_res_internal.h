/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OC_CORE_RES_INTERNAL_H
#define OC_CORE_RES_INTERNAL_H

#include "oc_core_res.h"
#include <stdint.h>

oc_device_info_t *oc_core_add_new_device_at_index(
  const char *uri, const char *rt, const char *name, const char *spec_version,
  const char *data_model_version, size_t index,
  oc_core_add_device_cb_t add_device_cb, void *data);

#endif /* OC_CORE_RES_INTERNAL_H */
