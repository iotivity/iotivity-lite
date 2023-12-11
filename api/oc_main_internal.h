/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#ifndef OC_MAIN_INTERNAL_H
#define OC_MAIN_INTERNAL_H

#include "oc_api.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_factory_presets_t
{
  oc_factory_presets_cb_t cb;
  void *data;
} oc_factory_presets_t;

oc_factory_presets_t *oc_get_factory_presets_cb(void);

/** @brief Check if the IoT stack is initialized. */
bool oc_main_initialized(void);

/*
 * modifiedbyme <2023/7/16> add func proto : `oc_resize_drop_command()`
 */
#ifdef OC_HAS_FEATURE_BRIDGE
/**
 * @brief Realloc memory for g_drop_commands, It is necessary when the Bridge
 *        manages Devices dynamically
 *
 * @param[in] device_count number of Devices
 */
void oc_resize_drop_command(size_t device_count);
#endif /* OC_HAS_FEATURE_BRIDGE */

#ifdef __cplusplus
}
#endif

#endif /* OC_MAIN_INTERNAL_H */
